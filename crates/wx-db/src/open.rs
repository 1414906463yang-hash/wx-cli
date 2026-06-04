use std::collections::HashMap;
use std::fmt;
use std::os::raw::c_void;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use rusqlite::Connection;

use crate::error::DbError;
use crate::pool::ShardPool;
use crate::shard_metadata::{now_nanos, ShardMeta, ShardMetadataFile};

/// Metadata for a single message shard database file.
#[derive(Debug)]
pub(crate) struct MessageShard {
    pub path: PathBuf,
    pub start_unix: i64,
    pub end_unix: i64,
}

/// Handle to an opened (decrypted) WeChat database directory.
///
/// Holds connections to contact/session databases and metadata about
/// message shard files. Created via [`WechatDb::open`].
pub struct WechatDb {
    pub(crate) contact_conn: Connection,
    pub(crate) contact_path: PathBuf,
    pub(crate) session_conn: Connection,
    pub(crate) session_path: PathBuf,
    pub(crate) shards: Vec<MessageShard>,
    /// Path to `message/message_fts.db` if it exists.
    pub message_fts_path: Option<PathBuf>,
    /// Path to `message/contact_fts.db` if it exists.
    pub contact_fts_path: Option<PathBuf>,
    /// Optional pre-opened connection pool for serve mode.
    pub(crate) pool: Option<ShardPool>,
    /// Raw key for encrypted direct open. Stored for reopen operations.
    pub(crate) raw_key: Option<[u8; 32]>,
    /// Lazily initialized cache of label_id -> label_name from contact_label table.
    /// Cleared on `reopen_contacts()` so label changes are visible.
    pub(crate) label_cache: RwLock<Option<HashMap<String, String>>>,
}

impl fmt::Debug for WechatDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WechatDb")
            .field("shards", &self.shards)
            .finish_non_exhaustive()
    }
}

/// Open a read-only connection, optionally applying sqlite3_key for encrypted DBs.
pub fn open_readonly_connection(
    path: &Path,
    raw_key: Option<&[u8; 32]>,
) -> Result<Connection, DbError> {
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    if let Some(key) = raw_key {
        unsafe {
            let rc = rusqlite::ffi::sqlite3_key(conn.handle(), key.as_ptr() as *const c_void, 32);
            if rc != 0 {
                return Err(DbError::EncryptionKey(format!(
                    "sqlite3_key failed: rc={rc}"
                )));
            }
        }
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(|_| DbError::EncryptionKey("incorrect key or not an encrypted database".into()))?;
        conn.execute_batch("PRAGMA query_only = ON")?;
    }
    Ok(conn)
}

pub(crate) fn open_connection(
    path: &Path,
    raw_key: Option<&[u8; 32]>,
) -> Result<Connection, DbError> {
    open_readonly_connection(path, raw_key)
}

impl WechatDb {
    /// Open a decrypted WeChat database directory.
    ///
    /// Returns `DbError::NotFound` if the path, contact.db, or session.db
    /// does not exist. Message shards are optional here; message queries will
    /// return `DbError::NoShards` if no numbered shard is available.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DbError> {
        Self::open_internal(path.as_ref(), None)
    }

    /// Open a decrypted WeChat database directory with a pre-opened
    /// connection pool for all message shards and FTS.
    ///
    /// `fts_init` is called on the FTS connection to register custom
    /// tokenizers (e.g. `register_mm_fts_tokenizer`).
    pub fn open_with_pool(
        path: impl AsRef<Path>,
        fts_init: impl Fn(&Connection) -> Result<(), String> + Send + Sync + 'static,
    ) -> Result<Self, DbError> {
        Self::open_with_pool_internal(path, None, fts_init)
    }

    /// Open an encrypted WeChat database directory directly using `sqlite3_key()`.
    pub fn open_encrypted(path: impl AsRef<Path>, raw_key: [u8; 32]) -> Result<Self, DbError> {
        Self::open_internal(path.as_ref(), Some(raw_key))
    }

    /// Open an encrypted WeChat database directory with a pre-opened
    /// connection pool for all message shards and FTS.
    pub fn open_encrypted_with_pool(
        path: impl AsRef<Path>,
        raw_key: [u8; 32],
        fts_init: impl Fn(&Connection) -> Result<(), String> + Send + Sync + 'static,
    ) -> Result<Self, DbError> {
        Self::open_with_pool_internal(path, Some(raw_key), fts_init)
    }

    fn open_internal(path: &Path, raw_key: Option<[u8; 32]>) -> Result<Self, DbError> {
        if !path.exists() {
            return Err(DbError::NotFound(path.display().to_string()));
        }

        let key_ref = raw_key.as_ref();

        // Open contact.db
        let contact_path = path.join("contact").join("contact.db");
        if !contact_path.exists() {
            return Err(DbError::NotFound(contact_path.display().to_string()));
        }
        let contact_conn = open_readonly_connection(&contact_path, key_ref)?;

        // Open session.db
        let session_path = path.join("session").join("session.db");
        if !session_path.exists() {
            return Err(DbError::NotFound(session_path.display().to_string()));
        }
        let session_conn = open_readonly_connection(&session_path, key_ref)?;

        // Scan message shards
        let msg_dir = path.join("message");
        let mut shards = Vec::new();

        if msg_dir.is_dir() {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(&msg_dir)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| is_numbered_message_shard(p))
                .collect();
            entries.sort();

            for shard_path in entries {
                let start_unix = read_shard_timestamp(&shard_path, key_ref);
                shards.push(MessageShard {
                    path: shard_path,
                    start_unix,
                    end_unix: 0, // assigned below
                });
            }
        }

        // Sort shards by start_unix ASC
        shards.sort_by_key(|s| s.start_unix);

        // Assign end_unix: each shard ends at next shard's start - 1; last = i64::MAX
        let n = shards.len();
        for i in 0..n {
            if i + 1 < n {
                shards[i].end_unix = shards[i + 1].start_unix - 1;
            } else {
                shards[i].end_unix = i64::MAX;
            }
        }

        Ok(WechatDb {
            contact_conn,
            contact_path,
            session_conn,
            session_path,
            shards,
            message_fts_path: {
                let p = msg_dir.join("message_fts.db");
                if p.exists() {
                    Some(p)
                } else {
                    None
                }
            },
            contact_fts_path: {
                let p = msg_dir.join("contact_fts.db");
                if p.exists() {
                    Some(p)
                } else {
                    None
                }
            },
            pool: None,
            raw_key,
            label_cache: RwLock::new(None),
        })
    }

    fn open_with_pool_internal(
        path: impl AsRef<Path>,
        raw_key: Option<[u8; 32]>,
        fts_init: impl Fn(&Connection) -> Result<(), String> + Send + Sync + 'static,
    ) -> Result<Self, DbError> {
        let mut db = Self::open_internal(path.as_ref(), raw_key)?;
        let fts_init_arc: Arc<crate::pool::FtsInitFn> = Arc::new(fts_init);
        let pool = ShardPool::open(
            &db.shards,
            db.message_fts_path.as_deref(),
            Some(fts_init_arc),
            raw_key,
        )?;
        db.pool = Some(pool);
        Ok(db)
    }

    /// Re-open the session.db connection to pick up external changes.
    pub fn reopen_sessions(&mut self) -> Result<(), DbError> {
        self.session_conn = open_connection(&self.session_path, self.raw_key.as_ref())?;
        Ok(())
    }

    /// Re-open the contact.db connection to pick up external changes.
    /// Also invalidates the label cache so it is reloaded on next query.
    pub fn reopen_contacts(&mut self) -> Result<(), DbError> {
        self.contact_conn = open_connection(&self.contact_path, self.raw_key.as_ref())?;
        *self.label_cache.write().unwrap() = None;
        Ok(())
    }

    /// Reopen a specific pooled shard connection.
    /// Returns `Ok(true)` if the path was in the pool (and reopened),
    /// `Ok(false)` if the path was not in the pool (unknown shard — possible topology change).
    /// No-op if pool is not initialized (returns `Ok(false)`).
    pub fn reopen_pooled_shard(&mut self, path: &Path) -> Result<bool, DbError> {
        if let Some(pool) = &mut self.pool {
            if pool.get(path).is_some() {
                pool.reopen_shard(path)?;
                return Ok(true);
            }
            return Ok(false);
        }
        Ok(false)
    }

    /// Reopen all pooled connections (shards + FTS).
    /// No-op if pool is not initialized.
    pub fn reopen_all_pooled(&mut self) -> Result<(), DbError> {
        if let Some(pool) = &mut self.pool {
            pool.reopen_all()?;
        }
        Ok(())
    }

    /// Reopen only the FTS connection in the pool.
    /// No-op if pool is not initialized.
    pub fn reopen_fts(&mut self) -> Result<(), DbError> {
        if let Some(pool) = &mut self.pool {
            pool.reopen_fts()?;
        }
        Ok(())
    }

    /// Borrow the connection pool, if initialized.
    pub fn pool(&self) -> Option<&ShardPool> {
        self.pool.as_ref()
    }

    /// Return shards whose time range overlaps `[start, end]`.
    pub(crate) fn shards_for_range(&self, start: i64, end: i64) -> Vec<&MessageShard> {
        self.shards
            .iter()
            .filter(|s| s.start_unix <= end && s.end_unix >= start)
            .collect()
    }

    /// Return all message shards (for full-shard scan in anchor queries).
    pub(crate) fn all_shards(&self) -> &[MessageShard] {
        &self.shards
    }

    /// Build a `ShardMetadataFile` from the current shard metadata.
    /// Callers can persist this to a sidecar file for future routing.
    pub fn shard_metadata(&self) -> ShardMetadataFile {
        let shards = self
            .shards
            .iter()
            .filter_map(|s| {
                let shard_id = extract_shard_id(&s.path)?;
                Some(ShardMeta {
                    shard_id,
                    start_unix: s.start_unix,
                    end_unix: s.end_unix,
                })
            })
            .collect();
        ShardMetadataFile {
            shards,
            written_at_ns: now_nanos(),
        }
    }

    /// Open a SQLite connection to a specific shard, optionally encrypted.
    pub(crate) fn open_shard_with_key(
        shard: &MessageShard,
        raw_key: Option<&[u8; 32]>,
    ) -> Result<Connection, DbError> {
        open_readonly_connection(&shard.path, raw_key)
    }
}

/// Extract the numeric shard ID from a path like `message_N.db`.
fn extract_shard_id(path: &Path) -> Option<u32> {
    let stem = path.file_stem()?.to_str()?;
    let suffix = stem.strip_prefix("message_")?;
    suffix.parse().ok()
}

fn is_numbered_message_shard(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
        return false;
    };
    if ext != "db" {
        return false;
    }

    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return false;
    };

    let Some(suffix) = stem.strip_prefix("message_") else {
        return false;
    };

    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

/// Try to read the timestamp from a message shard's Timestamp table.
/// Returns 0 if the table does not exist or is empty.
fn read_shard_timestamp(path: &Path, raw_key: Option<&[u8; 32]>) -> i64 {
    let conn = match open_connection(path, raw_key) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    conn.query_row("SELECT timestamp FROM Timestamp LIMIT 1", [], |row| {
        row.get(0)
    })
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::raw::c_void;
    use tempfile::TempDir;

    /// Create an encrypted SQLite DB at `path` using SQLCipher's `sqlite3_key()`.
    fn create_encrypted_db(path: &Path, raw_key: &[u8; 32], setup_sql: &str) {
        let conn = Connection::open(path).unwrap();
        unsafe {
            let rc =
                rusqlite::ffi::sqlite3_key(conn.handle(), raw_key.as_ptr() as *const c_void, 32);
            assert_eq!(rc, 0, "sqlite3_key failed during test DB creation");
        }
        conn.execute_batch(setup_sql).unwrap();
    }

    /// Build a minimal encrypted db_storage directory for `open_encrypted` tests.
    fn build_encrypted_db_storage(root: &Path, raw_key: &[u8; 32]) {
        std::fs::create_dir_all(root.join("contact")).unwrap();
        std::fs::create_dir_all(root.join("session")).unwrap();
        std::fs::create_dir_all(root.join("message")).unwrap();

        create_encrypted_db(
            &root.join("contact").join("contact.db"),
            raw_key,
            "CREATE TABLE contact (username TEXT PRIMARY KEY, alias TEXT, remark TEXT, nick_name TEXT, description TEXT, extra_buffer BLOB);",
        );
        create_encrypted_db(
            &root.join("session").join("session.db"),
            raw_key,
            "CREATE TABLE SessionTable (username TEXT, sort_timestamp INTEGER, summary TEXT);",
        );
        create_encrypted_db(
            &root.join("message").join("message_0.db"),
            raw_key,
            "CREATE TABLE Timestamp (timestamp INTEGER); INSERT INTO Timestamp VALUES (1700000000);",
        );
    }

    #[test]
    fn open_encrypted_succeeds_with_correct_key() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db_storage");
        let raw_key = [0xAB_u8; 32];
        build_encrypted_db_storage(&root, &raw_key);

        let db = WechatDb::open_encrypted(&root, raw_key).unwrap();
        assert_eq!(db.shards.len(), 1);
        assert_eq!(db.shards[0].start_unix, 1700000000);
    }

    #[test]
    fn open_encrypted_fails_with_wrong_key() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db_storage");
        let raw_key = [0xAB_u8; 32];
        build_encrypted_db_storage(&root, &raw_key);

        let wrong_key = [0xCD_u8; 32];
        let result = WechatDb::open_encrypted(&root, wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn open_encrypted_reopen_sessions_works() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db_storage");
        let raw_key = [0xAB_u8; 32];
        build_encrypted_db_storage(&root, &raw_key);

        let mut db = WechatDb::open_encrypted(&root, raw_key).unwrap();
        // Reopen should succeed (re-applies sqlite3_key)
        db.reopen_sessions().unwrap();
        db.reopen_contacts().unwrap();
    }

    #[test]
    fn open_connection_plaintext_works() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.db");
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE t (id INTEGER)")
            .unwrap();

        let conn = open_connection(&path, None).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn open_connection_encrypted_works() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("enc.db");
        let raw_key = [0xAB_u8; 32];
        create_encrypted_db(
            &path,
            &raw_key,
            "CREATE TABLE t (id INTEGER); INSERT INTO t VALUES (42);",
        );

        let conn = open_connection(&path, Some(&raw_key)).unwrap();
        let val: i64 = conn
            .query_row("SELECT id FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(val, 42);
    }
}
