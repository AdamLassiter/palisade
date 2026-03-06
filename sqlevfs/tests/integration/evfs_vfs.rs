use std::fs;

use bincode::config;
use rusqlite::{Connection, OpenFlags};
use sqlevfs::{EvfsBuilder, Mode, keyring::PersistedKeyring, policy};
use tempfile::TempDir;

use crate::common::{sqlite_api_is_available, test_db_path};

#[test_log::test]
fn test_end_to_end_database_operations() -> anyhow::Result<()> {
    if !sqlite_api_is_available() {
        eprintln!("skipping: sqlite extension API pointers are not initialized in this build");
        return Ok(());
    }
    let temp_dir = TempDir::new()?;
    let keyfile = temp_dir.path().join("db.key");
    fs::write(&keyfile, vec![0xCC; 32])?;

    let db_path = test_db_path(&temp_dir, "test.db");

    let mode = Mode::DeviceKey {
        keyfile: Some(keyfile.clone()),
        passphrase: None,
    };

    let _keyring = EvfsBuilder::new(mode).vfs_name("evfs_test").register()?;

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

    let storage_policy = policy::StoragePolicy {
        journal_mode: policy::JournalModePolicy::DeleteOnlyIfRamdisk {
            fallback: policy::JournalModeFallback::Memory,
        },
        temp_store: policy::TempStorePolicy::FileOnlyIfRamdisk {
            fallback: policy::TempStoreFallback::Memory,
        },
        enforce: policy::Enforce::Warn,
    };
    let _ = policy::apply_storage_policy(&conn, &db_path, &storage_policy)?;

    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)", [])?;
    conn.execute("INSERT INTO users (name) VALUES (?1)", ["Alice"])?;
    conn.execute("INSERT INTO users (name) VALUES (?1)", ["Bob"])?;

    let users: Vec<(i32, String)> = {
        let mut stmt = conn.prepare("SELECT id, name FROM users ORDER BY id")?;
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?
    };

    assert_eq!(users.len(), 2);
    assert_eq!(users[0].1, "Alice");
    assert_eq!(users[1].1, "Bob");

    conn.close().map_err(|(_, e)| e)?;

    let encrypted_data = fs::read(&db_path)?;
    assert!(encrypted_data.len() > 4096);
    assert_eq!(&encrypted_data[0..16], b"SQLite format 3\0");

    let second_page = &encrypted_data[4096..8192];
    assert_ne!(&second_page[0..16], b"SQLite format 3\0");

    Ok(())
}

#[test_log::test]
fn test_reopening_encrypted_database() -> anyhow::Result<()> {
    if !sqlite_api_is_available() {
        eprintln!("skipping: sqlite extension API pointers are not initialized in this build");
        return Ok(());
    }
    let temp_dir = TempDir::new()?;
    let keyfile = temp_dir.path().join("reopen.key");
    fs::write(&keyfile, vec![0xDD; 32])?;

    let db_path = test_db_path(&temp_dir, "reopen.db");
    let reserve_size = 48;

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
    if !sqlite_api_is_available() {
        eprintln!("skipping: sqlite extension API pointers are not initialized in this build");
        return Ok(());
    }
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

    conn.execute("CREATE TABLE blobs (id INTEGER, data BLOB)", [])?;

    let large_data = vec![0x42u8; 1024 * 1024];
    conn.execute(
        "INSERT INTO blobs (id, data) VALUES (?1, ?2)",
        rusqlite::params![1, &large_data],
    )?;

    let bytes = std::fs::read(&db_path)?;
    let page_size = 4096usize;
    let reserve = 48usize;

    let actual_reserve = bytes[20] as usize;
    assert_eq!(actual_reserve, reserve);

    let page2 = &bytes[page_size..page_size * 2];
    let payload_len = page_size - reserve;
    let marker = &page2[payload_len + 16..payload_len + 22];
    assert_eq!(marker, b"EVFSv1");

    let retrieved: Vec<u8> =
        conn.query_row("SELECT data FROM blobs WHERE id = ?1", [1], |row| {
            row.get(0)
        })?;

    assert_eq!(retrieved.len(), large_data.len());
    assert_eq!(retrieved, large_data);

    conn.close().map_err(|(_, e)| e)?;

    Ok(())
}

#[test_log::test]
fn test_wrong_key_fails_to_decrypt() -> anyhow::Result<()> {
    if !sqlite_api_is_available() {
        eprintln!("skipping: sqlite extension API pointers are not initialized in this build");
        return Ok(());
    }
    let temp_dir = TempDir::new()?;
    let keyfile1 = temp_dir.path().join("key1.key");
    let keyfile2 = temp_dir.path().join("key2.key");
    fs::write(&keyfile1, vec![0xEE; 32])?;
    fs::write(&keyfile2, vec![0xFF; 32])?;

    let db_path = test_db_path(&temp_dir, "wrong_key.db");

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

        if let Ok(conn) = result {
            let query_result: Result<String, _> =
                conn.query_row("SELECT data FROM secret", [], |row| row.get(0));
            assert!(query_result.is_err());
        }
    }

    Ok(())
}

#[test_log::test]
fn test_keyring_persistence_via_sidecar() -> anyhow::Result<()> {
    if !sqlite_api_is_available() {
        eprintln!("skipping: sqlite extension API pointers are not initialized in this build");
        return Ok(());
    }
    let temp_dir = TempDir::new()?;
    let keyfile = temp_dir.path().join("persist.key");
    fs::write(&keyfile, vec![0x11; 32])?;

    let db_path = test_db_path(&temp_dir, "persist.db");
    let sidecar_path = db_path.with_extension("evfs-keyring");

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

    assert!(sidecar_path.exists(), "Sidecar file should be created");
    let sidecar_bytes = std::fs::read(&sidecar_path)?;
    assert!(!sidecar_bytes.is_empty());

    let kr: PersistedKeyring = bincode::decode_from_slice(&sidecar_bytes, config::standard())?.0;
    assert!(!kr.keys.is_empty(), "Keyring should have entries");

    Ok(())
}

#[test_log::test]
#[ignore]
fn test_concurrent_access() -> anyhow::Result<()> {
    if !sqlite_api_is_available() {
        eprintln!("skipping: sqlite extension API pointers are not initialized in this build");
        return Ok(());
    }
    use std::thread;

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
fn test_wal_journal_mode_enabled_with_evfs() -> anyhow::Result<()> {
    if !sqlite_api_is_available() {
        eprintln!("skipping: sqlite extension API pointers are not initialized in this build");
        return Ok(());
    }
    let temp_dir = TempDir::new()?;
    let keyfile = temp_dir.path().join("wal-mode.key");
    fs::write(&keyfile, vec![0x77; 32])?;

    let db_path = temp_dir.path().join("wal-mode.db");
    let vfs_name = "evfs_wal_mode_test";

    let mode = Mode::DeviceKey {
        keyfile: Some(keyfile),
        passphrase: None,
    };

    EvfsBuilder::new(mode).vfs_name(vfs_name).register()?;

    let conn = Connection::open_with_flags_and_vfs(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        vfs_name,
    )?;

    let mut stmt = conn.prepare("PRAGMA journal_mode = WAL")?;
    let wal_after: String = stmt.query_row([], |r| r.get(0))?;
    drop(stmt);
    assert_eq!(wal_after.to_lowercase(), "wal");

    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)", [])?;
    conn.execute("INSERT INTO t (v) VALUES ('ok')", [])?;
    let v: String = conn.query_row("SELECT v FROM t WHERE id = 1", [], |r| r.get(0))?;
    assert_eq!(v, "ok");

    conn.close().map_err(|(_, e)| e)?;
    Ok(())
}
