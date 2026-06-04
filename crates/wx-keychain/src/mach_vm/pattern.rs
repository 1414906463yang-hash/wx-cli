use std::collections::HashSet;

pub const MAX_HEX_LEN: usize = 192;
pub const MAX_PATTERN_BYTES: usize = MAX_HEX_LEN + 3;

/// A candidate key found by scanning a memory chunk for an SQL hex literal.
///
/// Supported payload forms (mirrors `refs/wx-decrypt/find_all_keys.py`):
/// - `x'<64 hex>'`   → enc_key only
/// - `x'<96 hex>'`   → enc_key + salt
/// - `x'<98..192 hex, even>'` → enc_key = first 64 hex, salt = last 32 hex
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FoundKey {
    pub enc_key: [u8; 32],
    pub salt: Option<[u8; 16]>,
}

/// Scan `buf` for supported `x'<...>'` hex literal patterns.
pub fn scan_chunk(buf: &[u8]) -> Vec<FoundKey> {
    let mut seen = HashSet::new();
    let mut results = Vec::new();

    if buf.len() < 2 {
        return results;
    }

    let mut i = 0;
    while i + 1 < buf.len() {
        if buf[i] != b'x' || buf[i + 1] != b'\'' {
            i += 1;
            continue;
        }

        let payload_start = i + 2;
        let mut payload_end = payload_start;
        while payload_end < buf.len()
            && payload_end - payload_start < MAX_HEX_LEN
            && buf[payload_end].is_ascii_hexdigit()
        {
            payload_end += 1;
        }

        if payload_end >= buf.len() {
            break;
        }

        if buf[payload_end] != b'\'' {
            i += 1;
            continue;
        }

        let hex_len = payload_end - payload_start;
        if !is_supported_hex_len(hex_len) {
            i += 1;
            continue;
        }

        let hex_slice = &buf[payload_start..payload_end];
        if let Some(found) = decode_found_key(hex_slice) {
            if seen.insert(found.clone()) {
                results.push(found);
            }
        }

        i = payload_end + 1;
    }

    results
}

fn is_supported_hex_len(len: usize) -> bool {
    len == 64 || len == 96 || (len > 96 && len <= MAX_HEX_LEN && len.is_multiple_of(2))
}

fn decode_found_key(hex_slice: &[u8]) -> Option<FoundKey> {
    let enc_vec = hex::decode(&hex_slice[..64]).ok()?;
    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&enc_vec);

    let salt = match hex_slice.len() {
        64 => None,
        96 => decode_salt(&hex_slice[64..96]),
        len if len > 96 && len % 2 == 0 => decode_salt(&hex_slice[len - 32..len]),
        _ => None,
    };

    Some(FoundKey { enc_key, salt })
}

fn decode_salt(hex_slice: &[u8]) -> Option<[u8; 16]> {
    let salt_vec = hex::decode(hex_slice).ok()?;
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&salt_vec);
    Some(salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENC_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SALT_HEX: &str = "fedcba9876543210fedcba9876543210";

    fn expected_enc_key() -> [u8; 32] {
        let v = hex::decode(ENC_HEX).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v);
        arr
    }

    fn expected_salt() -> [u8; 16] {
        let v = hex::decode(SALT_HEX).unwrap();
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&v);
        arr
    }

    #[test]
    fn exact_96_hex_returns_key_and_salt() {
        let buf = format!("x'{}{}'", ENC_HEX, SALT_HEX).into_bytes();
        let keys = scan_chunk(&buf);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].enc_key, expected_enc_key());
        assert_eq!(keys[0].salt, Some(expected_salt()));
    }

    #[test]
    fn exact_64_hex_returns_key_only() {
        let buf = format!("x'{}'", ENC_HEX).into_bytes();
        let keys = scan_chunk(&buf);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].enc_key, expected_enc_key());
        assert_eq!(keys[0].salt, None);
    }

    #[test]
    fn long_hex_uses_first_key_and_last_salt() {
        let middle = "a1".repeat(20);
        let buf = format!("x'{}{}{}'", ENC_HEX, middle, SALT_HEX).into_bytes();
        let keys = scan_chunk(&buf);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].enc_key, expected_enc_key());
        assert_eq!(keys[0].salt, Some(expected_salt()));
    }

    #[test]
    fn invalid_mid_length_hex_is_ignored() {
        let payload = format!("{}{}", ENC_HEX, "ab".repeat(8)); // 80 hex
        let buf = format!("x'{}'", payload).into_bytes();
        let keys = scan_chunk(&buf);
        assert!(keys.is_empty());
    }

    #[test]
    fn mixed_case_hex_decoded_correctly() {
        let mixed_enc: String = ENC_HEX
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        let mixed_salt: String = SALT_HEX
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        let buf = format!("x'{}{}'", mixed_enc, mixed_salt).into_bytes();
        let keys = scan_chunk(&buf);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].enc_key, expected_enc_key());
        assert_eq!(keys[0].salt, Some(expected_salt()));
    }

    #[test]
    fn duplicate_patterns_are_deduplicated() {
        let pattern = format!("x'{}{}'", ENC_HEX, SALT_HEX);
        let buf = format!("{}__{}", pattern, pattern).into_bytes();
        let keys = scan_chunk(&buf);
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn incomplete_pattern_at_end_is_ignored() {
        let buf = format!("x'{}", ENC_HEX).into_bytes();
        let keys = scan_chunk(&buf);
        assert!(keys.is_empty());
    }
}
