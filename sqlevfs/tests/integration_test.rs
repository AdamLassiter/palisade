use std::{fs, path::PathBuf};

use bincode::config;
use sqlevfs::{keyring::PersistedKeyring, *};
use tempfile::TempDir;

// Helper to create a test database path
fn test_db_path(dir: &TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

#[test_log::test]
fn test_builder_device_key_with_keyfile() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let keyfile = temp_dir.path().join("test.key");
    fs::write(&keyfile, vec![0xAA; 32])?;

    let mode = Mode::DeviceKey {
        keyfile: Some(keyfile),
        passphrase: None,
    };

    let builder = EvfsBuilder::new(mode);
    assert_eq!(builder.name, "evfs");
    assert_eq!(builder.page_size, 4096);
    assert_eq!(builder.reserve_size, 48);

    Ok(())
}

#[test_log::test]
fn test_builder_device_key_with_passphrase() {
    let mode = Mode::DeviceKey {
        keyfile: None,
        passphrase: Some("test_password".to_string()),
    };

    let builder = EvfsBuilder::new(mode);
    assert_eq!(builder.page_size, 4096);
}

#[test_log::test]
#[should_panic(expected = "DeviceKey mode requires keyfile or passphrase")]
fn test_builder_device_key_no_source_panics() {
    let mode = Mode::DeviceKey {
        keyfile: None,
        passphrase: None,
    };

    let _builder = EvfsBuilder::new(mode);
}

#[test_log::test]
fn test_builder_tenant_key() {
    let mode = Mode::TenantKey {
        key_id: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
            .to_string(),
        endpoint: Some("https://kms.us-east-1.amazonaws.com".to_string()),
    };

    let builder = EvfsBuilder::new(mode);
    assert_eq!(builder.page_size, 4096);
}

#[test_log::test]
fn test_builder_chaining() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let keyfile = temp_dir.path().join("test.key");
    fs::write(&keyfile, vec![0xBB; 32])?;

    let mode = Mode::DeviceKey {
        keyfile: Some(keyfile),
        passphrase: None,
    };

    let builder = EvfsBuilder::new(mode)
        .page_size(8192)
        .reserve_size(64)
        .vfs_name("custom_evfs");

    assert_eq!(builder.name, "custom_evfs");
    assert_eq!(builder.page_size, 8192);
    assert_eq!(builder.reserve_size, 64);

    Ok(())
}

#[test_log::test]
fn test_end_to_end_database_operations() -> anyhow::Result<()> {
    use rusqlite::{Connection, OpenFlags};

    let temp_dir = TempDir::new()?;
    let keyfile = temp_dir.path().join("db.key");
    fs::write(&keyfile, vec![0xCC; 32])?;

    let db_path = test_db_path(&temp_dir, "test.db");

    // Register VFS
    let mode = Mode::DeviceKey {
        keyfile: Some(keyfile.clone()),
        passphrase: None,
    };

    let _keyring = EvfsBuilder::new(mode).vfs_name("evfs_test").register()?;

    // Open database with custom VFS
    let conn = Connection::open_with_flags_and_vfs(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        "evfs_test",
    )?;

    conn.execute_batch(
        r#"
        PRAGMA page_size = 4096;
        PRAGMA journal_mode = MEMORY;
        VACUUM;
        "#,
    )?;

    let policy = policy::StoragePolicy {
        journal_mode: policy::JournalModePolicy::DeleteOnlyIfRamdisk {
            fallback: policy::JournalModeFallback::Memory,
        },
        temp_store: policy::TempStorePolicy::FileOnlyIfRamdisk {
            fallback: policy::TempStoreFallback::Memory,
        },
        enforce: policy::Enforce::Warn,
    };
    let report = sqlevfs::policy::apply_storage_policy(&conn, &db_path, &policy)?;
    log::error!("Storage policy report: {:?}", report);

    // Create table
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)", [])?;

    // Insert data
    conn.execute("INSERT INTO users (name) VALUES (?1)", ["Alice"])?;
    conn.execute("INSERT INTO users (name) VALUES (?1)", ["Bob"])?;

    // Query data
    {
        let mut stmt = conn.prepare("SELECT id, name FROM users ORDER BY id")?;
        let users: Vec<(i32, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(users.len(), 2);
        assert_eq!(users[0].1, "Alice");
        assert_eq!(users[1].1, "Bob");
    }

    conn.close().map_err(|(_, e)| e)?;

    // Verify file is encrypted (doesn't have plaintext SQLite header beyond first 100 bytes)
    let encrypted_data = fs::read(&db_path)?;
    assert!(encrypted_data.len() > 4096);

    // First page should have SQLite header in first 100 bytes
    assert_eq!(&encrypted_data[0..16], b"SQLite format 3\0");

    // But data after first page should be encrypted
    // (Check for absence of plaintext patterns)
    let second_page = &encrypted_data[4096..8192];
    assert_ne!(&second_page[0..16], b"SQLite format 3\0");

    Ok(())
}

#[test_log::test]
fn test_reopening_encrypted_database() -> anyhow::Result<()> {
    use rusqlite::{Connection, OpenFlags};

    let temp_dir = TempDir::new()?;
    let keyfile = temp_dir.path().join("reopen.key");
    fs::write(&keyfile, vec![0xDD; 32])?;

    let db_path = test_db_path(&temp_dir, "reopen.db");
    let reserve_size = 48;

    // First session - create and write
    {
        let mode = Mode::DeviceKey {
            keyfile: Some(keyfile.clone()),
            passphrase: None,
        };

        EvfsBuilder::new(mode)
            .vfs_name("evfs_reopen1")
            .reserve_size(reserve_size)
            .register()?;

        let conn = Connection::open_with_flags_and_vfs(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            "evfs_reopen1",
        )?;

        // Set page size and reserve BEFORE creating tables
        conn.execute_batch(
            r#"
            PRAGMA page_size = 4096;
            PRAGMA journal_mode = DELETE;
            VACUUM;
            "#,
        )?;

        let page_size: i64 = conn.pragma_query_value(None, "page_size", |r| r.get(0))?;
        assert_eq!(page_size, 4096);

        conn.execute("CREATE TABLE data (value TEXT)", [])?;
        conn.execute("INSERT INTO data VALUES (?1)", ["test_value"])?;
        conn.close().map_err(|(_, e)| e)?;
    }

    let bytes = std::fs::read(&db_path)?;
    assert_eq!(&bytes[0..16], b"SQLite format 3\0");
    assert_eq!(bytes[20] as usize, reserve_size);

    // Second session - reopen and read
    {
        let mode = Mode::DeviceKey {
            keyfile: Some(keyfile),
            passphrase: None,
        };

        EvfsBuilder::new(mode)
            .vfs_name("evfs_reopen2")
            .reserve_size(reserve_size)
            .register()?;

        let conn = Connection::open_with_flags_and_vfs(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE,
            "evfs_reopen2",
        )?;

        let value: String = conn.query_row("SELECT value FROM data", [], |row| row.get(0))?;

        assert_eq!(value, "test_value");
        conn.close().map_err(|(_, e)| e)?;
    }

    Ok(())
}

#[test_log::test]
fn test_large_data_encryption() -> anyhow::Result<()> {
    use rusqlite::{Connection, OpenFlags};

    let temp_dir = TempDir::new()?;
    let keyfile = temp_dir.path().join("large.key");
    fs::write(&keyfile, vec![0x22; 32])?;

    let db_path = test_db_path(&temp_dir, "large.db");
    let reserve_size = 48;

    let mode = Mode::DeviceKey {
        keyfile: Some(keyfile),
        passphrase: None,
    };

    EvfsBuilder::new(mode)
        .vfs_name("evfs_large")
        .reserve_size(reserve_size)
        .register()?;

    let conn = Connection::open_with_flags_and_vfs(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        "evfs_large",
    )?;

    // Set page size BEFORE creating tables
    conn.execute_batch(
        r#"
        PRAGMA page_size = 4096;
        PRAGMA journal_mode = DELETE;
        PRAGMA locking_mode = EXCLUSIVE;
        PRAGMA temp_store = FILE;
        PRAGMA synchronous = OFF;
        VACUUM;
        "#,
    )?;

    let page_size: i64 = conn.pragma_query_value(None, "page_size", |r| r.get(0))?;

    assert_eq!(page_size, 4096);

    // Create table with large blobs
    conn.execute("CREATE TABLE blobs (id INTEGER, data BLOB)", [])?;

    // Insert large data (1MB)
    log::info!("Started writing large data encryption");
    let large_data = vec![0x42u8; 1024 * 1024];
    conn.execute(
        "INSERT INTO blobs (id, data) VALUES (?1, ?2)",
        rusqlite::params![1, &large_data],
    )?;
    log::info!("Finished writing large data encryption");

    let bytes = std::fs::read(&db_path)?;
    let page_size = 4096usize;
    let reserve = 48usize;

    let actual_reserve = bytes[20] as usize;
    assert_eq!(actual_reserve, reserve);

    let page2 = &bytes[page_size..page_size * 2];
    let payload_len = page_size - reserve;

    // tag is [payload_len..payload_len+16], marker is next 6 bytes
    let marker = &page2[payload_len + 16..payload_len + 22];
    assert_eq!(marker, b"EVFSv1");

    log::info!("Started reading large data encryption");
    // Read back
    let retrieved: Vec<u8> =
        conn.query_row("SELECT data FROM blobs WHERE id = ?1", [1], |row| {
            row.get(0)
        })?;
    log::info!("Finished reading large data encryption");

    assert_eq!(retrieved.len(), large_data.len());
    assert!(retrieved == large_data); // Avoid assert_eq that prints huge data on failure

    conn.close().map_err(|(_, e)| e)?;

    Ok(())
}

#[test_log::test]
fn test_wrong_key_fails_to_decrypt() -> anyhow::Result<()> {
    use rusqlite::{Connection, OpenFlags};

    let temp_dir = TempDir::new()?;
    let keyfile1 = temp_dir.path().join("key1.key");
    let keyfile2 = temp_dir.path().join("key2.key");
    fs::write(&keyfile1, vec![0xEE; 32])?;
    fs::write(&keyfile2, vec![0xFF; 32])?; // Different key

    let db_path = test_db_path(&temp_dir, "wrong_key.db");

    // Create with key1
    {
        let mode = Mode::DeviceKey {
            keyfile: Some(keyfile1),
            passphrase: None,
        };

        EvfsBuilder::new(mode).vfs_name("evfs_key1").register()?;

        let conn = Connection::open_with_flags_and_vfs(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            "evfs_key1",
        )?;

        conn.execute("CREATE TABLE secret (data TEXT)", [])?;
        conn.execute("INSERT INTO secret VALUES ('sensitive')", [])?;
        conn.close().map_err(|(_, e)| e)?;
    }

    // Try to open with key2 - should fail
    {
        let mode = Mode::DeviceKey {
            keyfile: Some(keyfile2),
            passphrase: None,
        };

        EvfsBuilder::new(mode).vfs_name("evfs_key2").register()?;

        let result = Connection::open_with_flags_and_vfs(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE,
            "evfs_key2",
        );

        // Connection might open but queries should fail
        if let Ok(conn) = result {
            let query_result: Result<String, _> =
                conn.query_row("SELECT data FROM secret", [], |row| row.get(0));
            // Should fail due to decryption error
            assert!(query_result.is_err());
        }
    }

    Ok(())
}

#[test_log::test]
fn test_keyring_persistence_via_sidecar() -> anyhow::Result<()> {
    use rusqlite::{Connection, OpenFlags};

    let temp_dir = TempDir::new()?;
    let keyfile = temp_dir.path().join("persist.key");
    fs::write(&keyfile, vec![0x11; 32])?;

    let db_path = test_db_path(&temp_dir, "persist.db");
    let sidecar_path = db_path.with_extension("evfs-keyring");

    // Create database
    {
        let mode = Mode::DeviceKey {
            keyfile: Some(keyfile.clone()),
            passphrase: None,
        };

        let _keyring = EvfsBuilder::new(mode).vfs_name("evfs_persist").register()?;

        let conn = Connection::open_with_flags_and_vfs(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            "evfs_persist",
        )?;

        conn.execute("CREATE TABLE test (id INTEGER)", [])?;
        conn.close().map_err(|(_, e)| e)?;
    }

    // Verify sidecar exists
    assert!(sidecar_path.exists(), "Sidecar file should be created");
    // Verify sidecar has content
    let sidecar_bytes = std::fs::read(&sidecar_path)?;
    assert!(!sidecar_bytes.is_empty());
    // Verify sidecar can be decoded into PersistedKeyring
    let kr: PersistedKeyring = bincode::decode_from_slice(&sidecar_bytes, config::standard())?.0;
    // Should have at least one key entry
    assert!(!kr.keys.is_empty(), "Keyring should have entries");

    Ok(())
}

#[test_log::test]
#[ignore]
fn test_concurrent_access() -> anyhow::Result<()> {
    use std::thread;

    use rusqlite::{Connection, OpenFlags};

    let temp_dir = TempDir::new()?;
    let keyfile = temp_dir.path().join("concurrent.key");
    fs::write(&keyfile, vec![0x33; 32])?;

    let db_path = test_db_path(&temp_dir, "concurrent.db");

    let mode = Mode::DeviceKey {
        keyfile: Some(keyfile),
        passphrase: None,
    };

    EvfsBuilder::new(mode)
        .vfs_name("evfs_concurrent")
        .register()?;

    // Setup database
    {
        let conn = Connection::open_with_flags_and_vfs(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            "evfs_concurrent",
        )?;

        conn.execute("CREATE TABLE counter (value INTEGER)", [])?;
        conn.execute("INSERT INTO counter VALUES (0)", [])?;
        conn.close().map_err(|(_, e)| e)?;
    }

    // Concurrent reads
    let db_path_clone = db_path.clone();
    let handles: Vec<_> = (0..5)
        .map(|_| {
            let path = db_path_clone.clone();
            thread::spawn(move || {
                let conn = Connection::open_with_flags_and_vfs(
                    &path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY,
                    "evfs_concurrent",
                )
                .unwrap();

                let value: i32 = conn
                    .query_row("SELECT value FROM counter", [], |row| row.get(0))
                    .unwrap();

                assert_eq!(value, 0);
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    Ok(())
}

#[test_log::test]
fn test_sqlite3_evfs_init_with_keyfile_env() {
    unsafe {
        std::env::set_var("EVFS_KEYFILE", "/tmp/test.key");
        std::env::remove_var("EVFS_PASSPHRASE");
        std::env::remove_var("EVFS_KMS_KEY_ID");

        // Note: This will fail if file doesn't exist, but tests the path
        let _result = sqlite3_evfs_init(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        std::env::remove_var("EVFS_KEYFILE");
    }
}

#[test_log::test]
fn test_sqlite3_evfs_init_with_passphrase_env() {
    unsafe {
        std::env::remove_var("EVFS_KEYFILE");
        std::env::set_var("EVFS_PASSPHRASE", "test_password");
        std::env::remove_var("EVFS_KMS_KEY_ID");

        let result = sqlite3_evfs_init(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        // Should succeed with passphrase
        assert_eq!(result, 0); // SQLITE_OK

        std::env::remove_var("EVFS_PASSPHRASE");
    }
}

#[test_log::test]
fn test_sqlite3_evfs_init_no_env() {
    unsafe {
        std::env::remove_var("EVFS_KEYFILE");
        std::env::remove_var("EVFS_PASSPHRASE");
        std::env::remove_var("EVFS_KMS_KEY_ID");

        let result = sqlite3_evfs_init(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        assert_eq!(result, 1); // SQLITE_ERROR
    }
}
