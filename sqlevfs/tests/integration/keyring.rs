use bincode::config;
use sqlevfs::{
    crypto::keys::KeyScope,
    keyring::{Keyring, PersistedKeyring},
};

use crate::common::{make_provider, test_db_path};

#[test_log::test]
fn test_keyring_scope_resolution() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let keyfile = test_db_path(&temp, "keyring.key");
    std::fs::write(&keyfile, [0x99u8; 32]).expect("write keyfile");

    let provider = make_provider(&keyfile);
    let keyring = Keyring::new(provider);

    let db_dek = keyring
        .dek_for(&KeyScope::Database)
        .expect("database DEK should be generated");

    let db_dek_again = keyring
        .dek_for(&KeyScope::Database)
        .expect("database DEK should be cached");
    assert_eq!(db_dek_again.as_bytes(), db_dek.as_bytes());

    let table_dek = keyring
        .dek_for(&KeyScope::Table("users".into()))
        .expect("table DEK");
    assert_ne!(table_dek.as_bytes(), db_dek.as_bytes());

    let column_dek = keyring
        .dek_for(&KeyScope::Column {
            table: "users".into(),
            column: "ssn".into(),
        })
        .expect("column DEK");
    assert_ne!(column_dek.as_bytes(), db_dek.as_bytes());
}

#[test_log::test]
fn test_keyring_sidecar_persistence_and_rewrap() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let keyfile = test_db_path(&temp, "persist.key");
    std::fs::write(&keyfile, [0x55u8; 32]).expect("write keyfile");

    let provider = make_provider(&keyfile);
    let keyring = Keyring::new(provider);

    let db_path = test_db_path(&temp, "persist.db");
    std::fs::write(&db_path, b"fake").expect("write placeholder db");

    keyring.set_sidecar_path(&db_path);
    let _ = keyring
        .dek_for(&KeyScope::Database)
        .expect("database DEK generation");

    let sidecar = db_path.with_extension("evfs-keyring");
    assert!(sidecar.exists());

    let sidecar_bytes = std::fs::read(&sidecar).expect("read sidecar");
    assert!(!sidecar_bytes.is_empty());

    let persisted: PersistedKeyring =
        bincode::decode_from_slice(&sidecar_bytes, config::standard())
            .expect("decode sidecar")
            .0;
    assert!(!persisted.keys.is_empty());

    keyring.rewrap_all().expect("rewrap_all should succeed");
}
