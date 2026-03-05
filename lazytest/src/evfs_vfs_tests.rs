use rusqlite::{Connection, OpenFlags, Result, params};

use crate::helpers::{TestDir, TestRunner};

pub(crate) fn run_evfs_vfs_tests(t: &mut TestRunner, mode: &str) -> Result<()> {
    t.section("EVFS VFS Registration");

    let tmp = TestDir::new("evfs-vfs-");
    let keyfile = tmp.write_keyfile("master.key", [0xAA; 32]);
    let db_path = tmp.path("test.db");

    unsafe {
        std::env::set_var("EVFS_KEYFILE", &keyfile);
    }

    {
        let loader = Connection::open(":memory:")?;
        unsafe {
            loader.load_extension_enable()?;
            match loader.load_extension(format!("../sqlevfs/target/{mode}/libsqlevfs"), None::<&str>)
            {
                Ok(()) => t.ok("loaded sqlevfs extension"),
                Err(e) => {
                    t.fail("load sqlevfs extension", &e);
                    return Ok(());
                }
            }
            loader.load_extension_disable()?;
        }
    }

    t.section("EVFS Encrypted Database - Write");

    let conn = match Connection::open_with_flags_and_vfs(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        "evfs",
    ) {
        Ok(c) => {
            t.ok("opened DB with vfs=evfs");
            c
        }
        Err(e) => {
            t.fail("open DB with vfs=evfs", &e);
            return Ok(());
        }
    };
    t.ok("opened DB with vfs=evfs");

    conn.execute_batch("PRAGMA reserve_bytes = 48;")?;
    t.ok("PRAGMA reserve_bytes = 48");

    conn.execute_batch(
        "CREATE TABLE widgets (
            id    INTEGER PRIMARY KEY,
            name  TEXT NOT NULL,
            price REAL NOT NULL
        );",
    )?;
    t.ok("CREATE TABLE widgets");

    conn.execute(
        "INSERT INTO widgets (id, name, price) VALUES (?1, ?2, ?3)",
        params![1, "Sprocket", 9.99],
    )?;
    conn.execute(
        "INSERT INTO widgets (id, name, price) VALUES (?1, ?2, ?3)",
        params![2, "Gizmo", 14.50],
    )?;
    conn.execute(
        "INSERT INTO widgets (id, name, price) VALUES (?1, ?2, ?3)",
        params![3, "Doohickey", 3.25],
    )?;
    t.ok("INSERT 3 rows");

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM widgets", [], |r| r.get(0))?;
    t.assert_eq("row count after insert", &count, &3i64);

    let total: f64 = conn.query_row("SELECT SUM(price) FROM widgets", [], |r| r.get(0))?;
    let expected_total = 27.74f64;
    if (total - expected_total).abs() < 0.001 {
        t.ok(&format!("SUM(price) = {total}"));
    } else {
        t.fail(
            "SUM(price)",
            &format!("expected {expected_total}, got {total}"),
        );
    }

    drop(conn);

    t.section("EVFS Encrypted Database - Reopen & Read");

    let conn =
        Connection::open_with_flags_and_vfs(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY, "evfs")?;
    t.ok("reopened DB with vfs=evfs (read-only)");

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM widgets", [], |r| r.get(0))?;
    t.assert_eq("row count after reopen", &count, &3i64);

    let name: String = conn.query_row("SELECT name FROM widgets WHERE id = 2", [], |r| r.get(0))?;
    t.assert_eq("read row id=2", &name, &"Gizmo".to_string());

    drop(conn);

    t.section("EVFS Ciphertext Verification");

    let raw = std::fs::read(&db_path).expect("read raw DB file");
    let has_sqlite_header = raw.len() >= 16 && &raw[0..16] == b"SQLite format 3\0";
    if has_sqlite_header {
        t.ok("raw DB file has SQLite header (expected)");
    } else {
        t.fail("raw DB file has SQLite header", &"header not found");
    }

    let raw_str = String::from_utf8_lossy(&raw);
    let contains_plaintext =
        raw_str.contains("Sprocket") || raw_str.contains("Gizmo") || raw_str.contains("Doohickey");

    if !contains_plaintext {
        t.ok("raw DB file does not contain plaintext row data");
    } else {
        t.fail("ciphertext check", &"plaintext row data found in raw file");
    }

    t.section("EVFS Multi-Table Operations");

    let conn =
        Connection::open_with_flags_and_vfs(&db_path, OpenFlags::SQLITE_OPEN_READ_WRITE, "evfs")?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS orders (
            id        INTEGER PRIMARY KEY,
            widget_id INTEGER REFERENCES widgets(id),
            qty       INTEGER NOT NULL
        );",
    )?;
    t.ok("CREATE TABLE orders");

    conn.execute(
        "INSERT INTO orders (id, widget_id, qty) VALUES (?1, ?2, ?3)",
        params![1, 1, 100],
    )?;
    conn.execute(
        "INSERT INTO orders (id, widget_id, qty) VALUES (?1, ?2, ?3)",
        params![2, 3, 250],
    )?;
    t.ok("INSERT into orders");

    let joined: Vec<(String, i64)> = {
        let mut stmt = conn.prepare(
            "SELECT w.name, o.qty
             FROM orders o
             JOIN widgets w ON w.id = o.widget_id
             ORDER BY o.id",
        )?;

        stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<Result<Vec<_>>>()?
    };

    t.assert_eq("JOIN row 0", &joined[0], &("Sprocket".to_string(), 100i64));
    t.assert_eq("JOIN row 1", &joined[1], &("Doohickey".to_string(), 250i64));

    t.section("EVFS Transactions");

    conn.execute_batch("BEGIN;")?;
    conn.execute(
        "INSERT INTO widgets (id, name, price) VALUES (?1, ?2, ?3)",
        params![4, "Thingamajig", 7.77],
    )?;
    conn.execute_batch("ROLLBACK;")?;

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM widgets", [], |r| r.get(0))?;
    t.assert_eq("count after ROLLBACK", &count, &3i64);

    conn.execute_batch("BEGIN;")?;
    conn.execute(
        "INSERT INTO widgets (id, name, price) VALUES (?1, ?2, ?3)",
        params![4, "Thingamajig", 7.77],
    )?;
    conn.execute_batch("COMMIT;")?;

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM widgets", [], |r| r.get(0))?;
    t.assert_eq("count after COMMIT", &count, &4i64);

    drop(conn);

    Ok(())
}
