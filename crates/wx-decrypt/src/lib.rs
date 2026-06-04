pub mod db;
pub mod dispatch;
pub mod error;
pub mod kdf;
pub mod key_material;
pub mod page;
pub mod params;
pub mod wal;

pub use db::{
    decrypt_db, decrypt_db_direct, read_db_salt, read_main_db_salt_for_path, validate_enc_key,
    validate_key,
};
pub use dispatch::{dispatch_decrypt_db, dispatch_decrypt_wal};
pub use error::DecryptError;
pub use key_material::{EncKeyPair, KeyMaterial};
pub use params::{CryptoParams, MACOS_4_1_7_31};
pub use wal::{decrypt_wal, decrypt_wal_direct};
