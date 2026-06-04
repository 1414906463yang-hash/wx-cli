use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use wx_decrypt::KeyMaterial;

use crate::error::KeychainError;

/// Try to resolve an account's nickname from its contact.db.
///
/// This is best-effort: returns `Ok(None)` if the nickname cannot be resolved
/// (e.g. contact.db doesn't exist, decryption fails, no matching record).
/// Errors are only returned for unexpected I/O failures.
pub fn resolve_nickname(
    data_dir: &Path,
    key_material: &KeyMaterial,
    base_wxid: &str,
) -> Result<Option<String>, KeychainError> {
    let contact_db = data_dir.join("db_storage/contact/contact.db");
    if !contact_db.exists() {
        return Ok(None);
    }

    let params = &wx_decrypt::MACOS_4_1_7_31;
    let tmp_db = unique_temp_db_path();

    // Decrypt contact.db to temp file
    let decrypt_result = match key_material {
        KeyMaterial::RawKey(key) => wx_decrypt::decrypt_db(&contact_db, &tmp_db, key, params),
        KeyMaterial::EncKey { key, salt } => {
            wx_decrypt::decrypt_db_direct(&contact_db, &tmp_db, key, salt, params)
        }
        KeyMaterial::EncKeys(pairs) => {
            match wx_decrypt::read_main_db_salt_for_path(&contact_db) {
                Ok(db_salt) => {
                    match pairs.iter().find(|p| p.salt == db_salt) {
                        Some(pair) => wx_decrypt::decrypt_db_direct(
                            &contact_db,
                            &tmp_db,
                            &pair.key,
                            &pair.salt,
                            params,
                        ),
                        None => return Ok(None), // best-effort: no matching key
                    }
                }
                Err(_) => return Ok(None), // best-effort: can't read salt
            }
        }
    };

    match decrypt_result {
        Ok(()) => {}
        Err(wx_decrypt::DecryptError::AlreadyDecrypted) => {
            if std::fs::copy(&contact_db, &tmp_db).is_err() {
                return Ok(None);
            }
        }
        Err(_) => return Ok(None),
    }

    // Query nickname using sqlite3 CLI
    let result = query_nickname_from_db(&tmp_db, base_wxid);

    // Clean up temp files
    let _ = std::fs::remove_file(&tmp_db);
    let _ = std::fs::remove_file(with_suffix(&tmp_db, "-wal"));
    let _ = std::fs::remove_file(with_suffix(&tmp_db, "-shm"));

    result
}

fn query_nickname_from_db(
    db_path: &Path,
    base_wxid: &str,
) -> Result<Option<String>, KeychainError> {
    let query = format!(
        "SELECT COALESCE(\
            NULLIF(remark, ''),\
            NULLIF(nick_name, ''),\
            NULLIF(alias, '')\
        ) FROM contact WHERE username = '{}' LIMIT 1;",
        base_wxid.replace('\'', "''")
    );

    let output = Command::new("sqlite3")
        .args([db_path.to_str().unwrap_or(""), &query])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if name.is_empty() {
                Ok(None)
            } else {
                Ok(Some(name))
            }
        }
        _ => Ok(None),
    }
}

fn unique_temp_db_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = wx_paths::AppPaths::nickname_temp_db(std::process::id(), nanos);
    if let Some(parent) = path.parent() {
        let _ = wx_paths::AppPaths::ensure_dir(parent);
    }
    path
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{}", path.display(), suffix))
}

// ---- Test coverage notes ----
//
// `resolve_nickname()` EncKeys branch is not directly unit-tested because:
//   1. It requires constructing an encrypted contact.db with a valid `contact` table
//      schema, decrypting it, then querying via sqlite3 CLI — high integration cost.
//   2. The EncKeys branch only calls `read_main_db_salt_for_path()` (tested in
//      wx-decrypt db.rs) and `decrypt_db_direct()` (tested in wx-decrypt db.rs).
//   3. The salt-matching + best-effort `Ok(None)` fallback is a trivial code path.
//
// Indirect coverage:
//   - `read_main_db_salt_for_path()`: 3 tests in wx-decrypt/src/db.rs
//   - `decrypt_db_direct()`: 2 tests in wx-decrypt/src/db.rs
//   - EncKeys salt matching: tested in wx-context/src/cache.rs
//     (`enc_keys_decrypt_db_selects_matching_pair`, `enc_keys_decrypt_db_no_match_returns_error`)
//   - E2E coverage via VM test scenario 4 (key scan + decrypt with EncKeys)
