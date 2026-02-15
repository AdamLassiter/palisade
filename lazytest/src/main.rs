use std::{
    env,
    io::Cursor,
    path::{Path, PathBuf},
    sync::Arc,
};

use rusqlite::{Connection, OpenFlags, Result, params};
// ── Imports from the evfs crate for backup API testing ──────────────
use sqlevfs::backup;
use sqlevfs::{
    crypto::keys::KeyScope,
    keyring::Keyring,
    kms::{KmsProvider, local::DeviceKeyProvider},
};

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

struct TestDir {
    dir: tempfile::TempDir,
}

impl TestDir {
    fn new(prefix: &str) -> Self {
        Self {
            dir: tempfile::Builder::new()
                .prefix(prefix)
                .tempdir()
                .expect("failed to create temp dir"),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Write a 32-byte keyfile and return its path.
    fn write_keyfile(&self, name: &str, key: [u8; 32]) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, key).expect("failed to write keyfile");
        p
    }
}

/// Counts passed / failed and prints a summary.
struct TestRunner {
    passed: u32,
    failed: u32,
    section: String,
}

impl TestRunner {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            section: String::new(),
        }
    }

    fn section(&mut self, name: &str) {
        self.section = name.to_string();
        println!("\n--- {name} ---");
    }

    fn ok(&mut self, msg: &str) {
        self.passed += 1;
        println!("  ✓ {msg}");
    }

    fn fail(&mut self, msg: &str, err: &dyn std::fmt::Display) {
        self.failed += 1;
        eprintln!("  ✗ {msg}: {err}");
    }

    fn assert_eq<T: PartialEq + std::fmt::Debug>(&mut self, label: &str, got: &T, expected: &T) {
        if got == expected {
            self.ok(label);
        } else {
            self.failed += 1;
            eprintln!("  ✗ {label}: expected {expected:?}, got {got:?}");
        }
    }

    fn summary(&self) {
        println!("\n========================================");
        println!(
            "  {} passed, {} failed, {} total",
            self.passed,
            self.failed,
            self.passed + self.failed,
        );
        if self.failed > 0 {
            println!("  SOME TESTS FAILED");
        } else {
            println!("  ALL TESTS PASSED");
        }
        println!("========================================");
    }
}

// ────────────────────────────────────────────────────────────────────
// Original sqlshim / sqlsec tests
// ────────────────────────────────────────────────────────────────────

fn run_sqlshim_tests(t: &mut TestRunner, mode: &str) -> Result<()> {
    t.section("sqlshim + sqlsec Extension Loading");

    let conn = Connection::open(":memory:")?;

    unsafe {
        conn.load_extension_enable()?;
        match conn.load_extension(format!("../sqlsec/target/{mode}/libsqlsec"), None::<&str>) {
            Ok(()) => t.ok("loaded sqlsec extension"),
            Err(e) => {
                t.fail("load sqlsec extension", &e);
                // Can't continue without the extension.
                return Ok(());
            }
        }
        conn.load_extension_disable()?;
    }

    // ── DEFINE LABEL ────────────────────────────────────────────
    t.section("DEFINE LABEL");
    for stmt in [
        "DEFINE LABEL 'true';",
        "DEFINE LABEL 'role=admin';",
        "DEFINE LABEL 'role=admin&team=finance';",
        "DEFINE LABEL '(role=admin|role=auditor)';",
    ] {
        match conn.execute_batch(stmt) {
            Ok(()) => t.ok(stmt),
            Err(e) => t.fail(stmt, &e),
        }
    }

    // ── DEFINE LEVEL ────────────────────────────────────────────
    t.section("DEFINE LEVEL");
    for (name, val) in [
        ("public", 0),
        ("confidential", 1),
        ("secret", 2),
        ("top_secret", 3),
    ] {
        let stmt = format!("DEFINE LEVEL clearance '{name}' = {val};");
        match conn.execute_batch(&stmt) {
            Ok(()) => t.ok(&stmt),
            Err(e) => t.fail(&stmt, &e),
        }
    }

    // ── CREATE POLICY ───────────────────────────────────────────
    t.section("CREATE POLICY");
    let policies = [
        (
            "SELECT",
            r#"CREATE POLICY invoices_read ON invoices
               FOR SELECT USING (has_role('finance'));"#,
        ),
        (
            "UPDATE",
            r#"CREATE POLICY invoices_write ON invoices
               FOR UPDATE
               USING (has_role('admin')
                      AND has_project_membership(project_id));"#,
        ),
        (
            "ALL",
            r#"CREATE POLICY users_all ON users
               USING (role='admin');"#,
        ),
    ];
    for (label, sql) in policies {
        match conn.execute_batch(sql) {
            Ok(()) => t.ok(&format!("CREATE POLICY ({label})")),
            Err(e) => t.fail(&format!("CREATE POLICY ({label})"), &e),
        }
    }

    // ── DROP POLICY ─────────────────────────────────────────────
    t.section("DROP POLICY");
    match conn.execute_batch("DROP POLICY invoices_write ON invoices;") {
        Ok(()) => t.ok("DROP POLICY"),
        Err(e) => t.fail("DROP POLICY", &e),
    }

    // ── SET / CLEAR / PUSH / POP CONTEXT ────────────────────────
    t.section("Context Management");
    for stmt in [
        "SET CONTEXT role = 'admin';",
        "SET CONTEXT team = 'finance';",
        "SET CONTEXT clearance = 'secret';",
        "CLEAR CONTEXT;",
        "SET CONTEXT role = 'user';",
        "PUSH CONTEXT;",
        "SET CONTEXT role = 'admin';",
        "POP CONTEXT;",
    ] {
        match conn.execute_batch(stmt) {
            Ok(()) => t.ok(stmt),
            Err(e) => t.fail(stmt, &e),
        }
    }

    // ── REFRESH SECURE VIEWS ────────────────────────────────────
    t.section("REFRESH SECURE VIEWS");
    match conn.execute_batch("REFRESH SECURE VIEWS;") {
        Ok(()) => t.ok("REFRESH SECURE VIEWS"),
        Err(e) => t.fail("REFRESH SECURE VIEWS", &e),
    }

    // ── REGISTER SECURE TABLE ───────────────────────────────────
    t.section("REGISTER SECURE TABLE");
    match conn.execute_batch(
        r#"
        CREATE TABLE __sec_employees (
            id INTEGER PRIMARY KEY,
            name TEXT,
            title TEXT,
            salary INTEGER,
            department TEXT,
            row_label_id INTEGER
        );
        REGISTER SECURE TABLE employees
        ON __sec_employees
        WITH ROW LABEL row_label_id;
        "#,
    ) {
        Ok(()) => t.ok("REGISTER SECURE TABLE (basic)"),
        Err(e) => t.fail("REGISTER SECURE TABLE (basic)", &e),
    }

    match conn.execute_batch(
        r#"
        CREATE TABLE __sec_documents (
            id INTEGER PRIMARY KEY,
            content TEXT,
            row_label_id INTEGER
        );
        REGISTER SECURE TABLE documents
        ON __sec_documents
        WITH ROW LABEL row_label_id
        TABLE LABEL 'role=admin'
        INSERT LABEL 'role=editor';
        "#,
    ) {
        Ok(()) => t.ok("REGISTER SECURE TABLE (with labels)"),
        Err(e) => t.fail("REGISTER SECURE TABLE (with labels)", &e),
    }

    // ── CREATE SECURE VIEW ──────────────────────────────────────
    t.section("CREATE SECURE VIEW");
    match conn.execute_batch(
        r#"
        CREATE SECURE VIEW employee_view AS
        SELECT id, name, salary
        FROM employees
        WHERE department = 'finance';
        "#,
    ) {
        Ok(()) => t.ok("CREATE SECURE VIEW"),
        Err(e) => t.fail("CREATE SECURE VIEW", &e),
    }

    // ── SET COLUMN SECURITY ─────────────────────────────────────
    t.section("SET COLUMN SECURITY");
    for stmt in [
        "SET COLUMN SECURITY employees.salary READ 'role=manager';",
        "SET COLUMN SECURITY employees.title UPDATE 'role=hr';",
        "SET COLUMN SECURITY employees.ssn READ 'role=admin' UPDATE 'role=auditor';",
    ] {
        match conn.execute_batch(stmt) {
            Ok(()) => t.ok(stmt),
            Err(e) => t.fail(stmt, &e),
        }
    }

    // ── Stub Features ───────────────────────────────────────────
    t.section("Stub Features (audit / explain policy)");
    for stmt in [
        "ENABLE AUDIT ON users;",
        "ENABLE AUDIT ON invoices FOR INSERT, UPDATE, DELETE;",
        "EXPLAIN POLICY ON employees FOR USER = 'alice';",
    ] {
        match conn.execute_batch(stmt) {
            Ok(()) => t.ok(stmt),
            Err(e) => t.fail(stmt, &e),
        }
    }

    // ── Normal SQL passthrough ──────────────────────────────────
    t.section("Normal SQL Passthrough");
    conn.execute_batch("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT);")?;
    conn.execute_batch("INSERT INTO test_table (id, name) VALUES (1, 'test');")?;
    let name: String = conn.query_row("SELECT name FROM test_table WHERE id = 1", [], |row| {
        row.get(0)
    })?;
    t.assert_eq("SELECT passthrough", &name, &"test".to_string());

    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// EVFS VFS tests (extension loading + encrypted I/O)
// ────────────────────────────────────────────────────────────────────

fn run_evfs_vfs_tests(t: &mut TestRunner, mode: &str) -> Result<()> {
    t.section("EVFS VFS Registration");

    let tmp = TestDir::new("evfs-vfs-");
    let keyfile = tmp.write_keyfile("master.key", [0xAA; 32]);
    let db_path = tmp.path("test.db");

    // Set the env var so sqlite3_evfs_init picks it up.
    unsafe {
        std::env::set_var("EVFS_KEYFILE", &keyfile);
    }

    // Open an in-memory connection just to load the extension and
    // register the VFS globally.
    {
        let loader = Connection::open(":memory:")?;
        unsafe {
            loader.load_extension_enable()?;
            match loader.load_extension(
                format!("../sqlevfs/target/{mode}/libsqlevfs"),
                Some("sqlite3_evfs_init"),
            ) {
                Ok(()) => t.ok("loaded sqlevfs extension"),
                Err(e) => {
                    t.fail("load sqlevfs extension", &e);
                    return Ok(());
                }
            }
            loader.load_extension_disable()?;
        }
    }

    // ── Open a file-based DB through the encrypted VFS ──────────
    t.section("EVFS Encrypted Database - Write");
    println!("DB path: {}", db_path.display());

    let conn = Connection::open_with_flags_and_vfs(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        "evfs",
    )?;
    t.ok("opened DB with vfs=evfs");
    println!("DB file created: {}", db_path.exists());

    // Set the reserve bytes so SQLite leaves room for the auth tag.
    // This must match what evfs expects (48 by default in EvfsBuilder,
    // but the init function uses the default builder which sets 48).
    // PRAGMA must be set before any tables are created.
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
    // 9.99 + 14.50 + 3.25 = 27.74
    let expected_total = 27.74f64;
    if (total - expected_total).abs() < 0.001 {
        t.ok(&format!("SUM(price) = {total}"));
    } else {
        t.fail(
            "SUM(price)",
            &format!("expected {expected_total}, got {total}"),
        );
    }

    // Close the connection.
    drop(conn);

    // ── Reopen and verify persistence ───────────────────────────
    t.section("EVFS Encrypted Database - Reopen & Read");

    let conn =
        Connection::open_with_flags_and_vfs(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY, "evfs")?;
    t.ok("reopened DB with vfs=evfs (read-only)");

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM widgets", [], |r| r.get(0))?;
    t.assert_eq("row count after reopen", &count, &3i64);

    let name: String = conn.query_row("SELECT name FROM widgets WHERE id = 2", [], |r| r.get(0))?;
    t.assert_eq("read row id=2", &name, &"Gizmo".to_string());

    drop(conn);

    // ── Verify the raw file is not plaintext ────────────────────
    t.section("EVFS Ciphertext Verification");

    let raw = std::fs::read(&db_path).expect("read raw DB file");
    let has_sqlite_header = raw.len() >= 16 && &raw[0..16] == b"SQLite format 3\0";
    if has_sqlite_header {
        t.ok("raw DB file has SQLite header (expected)");
    } else {
        t.fail("raw DB file has SQLite header", &"header not found");
    }

    // Page 1 may still have the SQLite header in cleartext (first
    // 100 bytes) depending on implementation, but the payload after
    // that should be encrypted.  Check that "Sprocket" does not
    // appear anywhere in the raw bytes.
    let raw_str = String::from_utf8_lossy(&raw);
    let contains_plaintext =
        raw_str.contains("Sprocket") || raw_str.contains("Gizmo") || raw_str.contains("Doohickey");

    if !contains_plaintext {
        t.ok("raw DB file does not contain plaintext row data");
    } else {
        t.fail("ciphertext check", &"plaintext row data found in raw file");
    }

    // ── Multi-table test ────────────────────────────────────────
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

    // ── Transaction test ────────────────────────────────────────
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

// ────────────────────────────────────────────────────────────────────
// EVFS Backup / Restore tests (via Rust API)
// ────────────────────────────────────────────────────────────────────

fn make_provider(keyfile: &Path) -> Arc<dyn KmsProvider> {
    Arc::new(DeviceKeyProvider::from_keyfile(keyfile.to_path_buf()))
}

fn run_evfs_backup_tests(t: &mut TestRunner) {
    t.section("EVFS Backup - Setup");

    let tmp = TestDir::new("evfs-backup-");
    let src_key = tmp.write_keyfile("src.key", [0x11; 32]);
    let bkp_key = tmp.write_keyfile("bkp.key", [0x22; 32]);
    let tgt_key = tmp.write_keyfile("tgt.key", [0x33; 32]);
    let db_path = tmp.path("source.db");

    let page_size: u32 = 4096;
    let reserve: usize = 48;
    let page_count: usize = 4;

    // Build a fake encrypted database on disk using the crypto
    // primitives directly (avoids depending on the VFS being
    // registered for this test group).
    let src_provider = make_provider(&src_key);
    let src_keyring = Arc::new(Keyring::new(src_provider.clone()));
    let src_dek = match src_keyring.dek_for(&KeyScope::Database) {
        Ok(d) => {
            t.ok("generated source DEK");
            d
        }
        Err(e) => {
            t.fail("generate source DEK", &e);
            return;
        }
    };

    let mut db_bytes = vec![0u8; page_count * page_size as usize];
    for i in 0..page_count {
        let off = i * page_size as usize;
        let pattern = (i as u8).wrapping_add(0x41); // 'A','B','C','D'
        db_bytes[off..off + page_size as usize - reserve].fill(pattern);
        if let Err(e) = sqlevfs::crypto::page::encrypt_page(
            &mut db_bytes[off..off + page_size as usize],
            i as u32 + 1,
            &src_dek,
            reserve,
        ) {
            t.fail(&format!("encrypt page {}", i + 1), &e);
            return;
        }
    }
    std::fs::write(&db_path, &db_bytes).expect("write source DB");
    t.ok(&format!("created encrypted source DB ({page_count} pages)"));

    // ── Create backup ───────────────────────────────────────────
    t.section("EVFS Backup - Create");

    let bkp_provider = make_provider(&bkp_key);
    let mut backup_buf: Vec<u8> = Vec::new();

    match backup::create_backup(
        &db_path,
        &mut backup_buf,
        &src_keyring,
        bkp_provider.as_ref(),
        page_size,
        reserve,
    ) {
        Ok(()) => t.ok(&format!("backup created ({} bytes)", backup_buf.len())),
        Err(e) => {
            t.fail("create backup", &e);
            return;
        }
    }

    // The backup should be larger than just the raw pages because
    // of the header.
    let min_expected = 8 + 4 + page_count * page_size as usize; // magic + hdr_len + pages
    if backup_buf.len() >= min_expected {
        t.ok("backup size plausible");
    } else {
        t.fail(
            "backup size",
            &format!("expected >= {min_expected}, got {}", backup_buf.len()),
        );
    }

    // Magic bytes check.
    if &backup_buf[..8] == b"EVFSBKUP" {
        t.ok("backup magic correct");
    } else {
        t.fail("backup magic", &"wrong magic bytes");
    }

    // ── Verify backup ───────────────────────────────────────────
    t.section("EVFS Backup - Verify");

    match backup::verify_backup(&mut Cursor::new(&backup_buf), bkp_provider.as_ref()) {
        Ok(result) => {
            t.assert_eq(
                "verified page_count",
                &result.page_count,
                &(page_count as u32),
            );
            t.assert_eq("pages_ok", &result.pages_ok, &(page_count as u32));
            t.assert_eq("pages_bad", &result.pages_bad, &0u32);
            if result.is_ok() {
                t.ok("backup verification passed");
            } else {
                t.fail("backup verification", &"some pages bad");
            }
        }
        Err(e) => t.fail("verify backup", &e),
    }

    // ── Verify with wrong key fails ─────────────────────────────
    t.section("EVFS Backup - Wrong Key Rejection");

    let wrong_provider = make_provider(&tgt_key); // different key
    match backup::verify_backup(&mut Cursor::new(&backup_buf), wrong_provider.as_ref()) {
        Ok(result) if result.is_ok() => {
            t.fail(
                "wrong-key verify",
                &"should have failed but all pages passed",
            );
        }
        Ok(result) => {
            t.ok(&format!(
                "wrong key correctly fails ({} bad pages)",
                result.pages_bad,
            ));
        }
        Err(_) => {
            // Unwrap itself failed - also acceptable.
            t.ok("wrong key correctly rejected at DEK unwrap");
        }
    }

    // ── Restore backup ──────────────────────────────────────────
    t.section("EVFS Backup - Restore");

    let tgt_provider = make_provider(&tgt_key);
    let tgt_keyring = Arc::new(Keyring::new(tgt_provider.clone()));
    let restored_path = tmp.path("restored.db");

    match backup::restore_backup(
        &mut Cursor::new(&backup_buf),
        &restored_path,
        bkp_provider.as_ref(),
        &tgt_keyring,
    ) {
        Ok(()) => t.ok("backup restored"),
        Err(e) => {
            t.fail("restore backup", &e);
            return;
        }
    }

    // Verify restored DB has the right size.
    let restored_bytes = std::fs::read(&restored_path).expect("read restored DB");
    t.assert_eq(
        "restored DB size",
        &restored_bytes.len(),
        &(page_count * page_size as usize),
    );

    // Decrypt each page with the target DEK and check contents.
    let tgt_dek = tgt_keyring
        .dek_for(&KeyScope::Database)
        .expect("get target DEK");
    let mut all_pages_ok = true;
    for i in 0..page_count {
        let off = i * page_size as usize;
        let mut page = restored_bytes[off..off + page_size as usize].to_vec();
        match sqlevfs::crypto::page::decrypt_page(&mut page, i as u32 + 1, &tgt_dek, reserve) {
            Ok(()) => {
                let expected = (i as u8).wrapping_add(0x41);
                let payload = &page[..page_size as usize - reserve];
                if payload.iter().all(|&b| b == expected) {
                    t.ok(&format!("restored page {} content correct", i + 1));
                } else {
                    t.fail(
                        &format!("restored page {} content", i + 1),
                        &"data mismatch",
                    );
                    all_pages_ok = false;
                }
            }
            Err(e) => {
                t.fail(&format!("decrypt restored page {}", i + 1), &e);
                all_pages_ok = false;
            }
        }
    }
    if all_pages_ok {
        t.ok("all restored pages verified");
    }

    // ── KEK rotation ────────────────────────────────────────────
    t.section("EVFS Backup - KEK Rotation");

    let backup_file = tmp.path("rotatable.evfs-backup");
    std::fs::write(&backup_file, &backup_buf).expect("write backup file");

    let new_kek = tmp.write_keyfile("new-bkp.key", [0x44; 32]);
    let new_provider = make_provider(&new_kek);

    match backup::rotate_backup_kek(&backup_file, bkp_provider.as_ref(), new_provider.as_ref()) {
        Ok(()) => t.ok("KEK rotation succeeded"),
        Err(e) => {
            t.fail("KEK rotation", &e);
            return;
        }
    }

    // Verify with the NEW key should work.
    let rotated_data = std::fs::read(&backup_file).expect("read rotated backup");
    match backup::verify_backup(&mut Cursor::new(&rotated_data), new_provider.as_ref()) {
        Ok(result) if result.is_ok() => {
            t.ok("verify after rotation (new key) passed");
        }
        Ok(result) => {
            t.fail(
                "verify after rotation (new key)",
                &format!("{} bad pages", result.pages_bad),
            );
        }
        Err(e) => t.fail("verify after rotation (new key)", &e),
    }

    // Verify with the OLD key should fail.
    match backup::verify_backup(&mut Cursor::new(&rotated_data), bkp_provider.as_ref()) {
        Ok(result) if result.is_ok() => {
            t.fail("verify after rotation (old key)", &"should have failed");
        }
        _ => t.ok("old key correctly rejected after rotation"),
    }

    // ── Restore from rotated backup ─────────────────────────────
    t.section("EVFS Backup - Restore After Rotation");

    let tgt2_key = tmp.write_keyfile("tgt2.key", [0x55; 32]);
    let tgt2_provider = make_provider(&tgt2_key);
    let tgt2_keyring = Arc::new(Keyring::new(tgt2_provider));
    let restored2_path = tmp.path("restored2.db");

    match backup::restore_backup(
        &mut Cursor::new(&rotated_data),
        &restored2_path,
        new_provider.as_ref(),
        &tgt2_keyring,
    ) {
        Ok(()) => t.ok("restore from rotated backup succeeded"),
        Err(e) => {
            t.fail("restore from rotated backup", &e);
            return;
        }
    }

    // Quick sanity: first page content.
    let restored2_bytes = std::fs::read(&restored2_path).expect("read restored2 DB");
    let tgt2_dek = tgt2_keyring
        .dek_for(&KeyScope::Database)
        .expect("get tgt2 DEK");
    let mut page1 = restored2_bytes[..page_size as usize].to_vec();
    match sqlevfs::crypto::page::decrypt_page(&mut page1, 1, &tgt2_dek, reserve) {
        Ok(()) => {
            let expected = 0x41u8; // 'A'
            if page1[..page_size as usize - reserve]
                .iter()
                .all(|&b| b == expected)
            {
                t.ok("restored2 page 1 content correct");
            } else {
                t.fail("restored2 page 1 content", &"data mismatch");
            }
        }
        Err(e) => t.fail("decrypt restored2 page 1", &e),
    }
}

// ────────────────────────────────────────────────────────────────────
// EVFS Crypto unit tests (run in-process, no VFS needed)
// ────────────────────────────────────────────────────────────────────

fn run_evfs_crypto_tests(t: &mut TestRunner) {
    t.section("EVFS Crypto - Page Round-Trip");

    let dek = sqlevfs::crypto::keys::Dek::generate();
    let reserve = 48;
    let page_size = 4096;

    let mut page = vec![0xBEu8; page_size];
    let original = page.clone();

    match sqlevfs::crypto::page::encrypt_page(&mut page, 1, &dek, reserve) {
        Ok(()) => t.ok("encrypt_page succeeded"),
        Err(e) => {
            t.fail("encrypt_page", &e);
            return;
        }
    }

    // Ciphertext should differ from plaintext.
    if page[..page_size - reserve] != original[..page_size - reserve] {
        t.ok("ciphertext differs from plaintext");
    } else {
        t.fail("ciphertext check", &"ciphertext == plaintext");
    }

    match sqlevfs::crypto::page::decrypt_page(&mut page, 1, &dek, reserve) {
        Ok(()) => t.ok("decrypt_page succeeded"),
        Err(e) => {
            t.fail("decrypt_page", &e);
            return;
        }
    }

    if page[..page_size - reserve] == original[..page_size - reserve] {
        t.ok("round-trip payload matches");
    } else {
        t.fail("round-trip", &"payload mismatch after decrypt");
    }

    // ── Wrong key ───────────────────────────────────────────────
    t.section("EVFS Crypto - Wrong Key Rejection");

    let dek2 = sqlevfs::crypto::keys::Dek::generate();
    let mut page = vec![0xCDu8; page_size];
    sqlevfs::crypto::page::encrypt_page(&mut page, 1, &dek, reserve).unwrap();

    match sqlevfs::crypto::page::decrypt_page(&mut page, 1, &dek2, reserve) {
        Err(_) => t.ok("wrong key correctly rejected"),
        Ok(()) => t.fail("wrong key", &"decryption should have failed"),
    }

    // ── Wrong page number ───────────────────────────────────────
    t.section("EVFS Crypto - Wrong Page Number Rejection");

    let mut page = vec![0xEFu8; page_size];
    sqlevfs::crypto::page::encrypt_page(&mut page, 5, &dek, reserve).unwrap();

    match sqlevfs::crypto::page::decrypt_page(&mut page, 6, &dek, reserve) {
        Err(_) => t.ok("wrong page_no correctly rejected"),
        Ok(()) => t.fail("wrong page_no", &"decryption should have failed"),
    }

    // ── Envelope wrap / unwrap ──────────────────────────────────
    t.section("EVFS Crypto - Envelope Encryption");

    let tmp = TestDir::new("evfs-envelope-");
    let kf = tmp.write_keyfile("envelope.key", [0x77; 32]);
    let provider = make_provider(&kf);

    let dek = sqlevfs::crypto::keys::Dek::generate();
    let wrapped = match sqlevfs::crypto::envelope::wrap_dek(&dek, provider.as_ref()) {
        Ok(w) => {
            t.ok("wrap_dek succeeded");
            w
        }
        Err(e) => {
            t.fail("wrap_dek", &e);
            return;
        }
    };

    match sqlevfs::crypto::envelope::unwrap_dek(&wrapped, provider.as_ref()) {
        Ok(unwrapped) => {
            if unwrapped.as_bytes() == dek.as_bytes() {
                t.ok("unwrap_dek round-trip matches");
            } else {
                t.fail("unwrap_dek", &"key bytes differ");
            }
        }
        Err(e) => t.fail("unwrap_dek", &e),
    }

    // Unwrap with wrong provider should fail.
    let kf2 = tmp.write_keyfile("wrong.key", [0x88; 32]);
    let wrong_provider = make_provider(&kf2);
    match sqlevfs::crypto::envelope::unwrap_dek(&wrapped, wrong_provider.as_ref()) {
        Err(_) => t.ok("unwrap with wrong KEK correctly rejected"),
        Ok(_) => t.fail("unwrap wrong KEK", &"should have failed"),
    }
}

// ────────────────────────────────────────────────────────────────────
// Keyring tests
// ────────────────────────────────────────────────────────────────────

fn run_evfs_keyring_tests(t: &mut TestRunner) {
    t.section("EVFS Keyring - Scope Resolution");

    let tmp = TestDir::new("evfs-keyring-");
    let kf = tmp.write_keyfile("keyring.key", [0x99; 32]);
    let provider = make_provider(&kf);
    let keyring = Keyring::new(provider);

    // Database scope.
    let dek1 = match keyring.dek_for(&KeyScope::Database) {
        Ok(d) => {
            t.ok("dek_for(Database) first call");
            d
        }
        Err(e) => {
            t.fail("dek_for(Database)", &e);
            return;
        }
    };

    // Same scope should return the same DEK (cached).
    match keyring.dek_for(&KeyScope::Database) {
        Ok(dek1b) => {
            if dek1b.as_bytes() == dek1.as_bytes() {
                t.ok("dek_for(Database) returns cached key");
            } else {
                t.fail("dek cache", &"second call returned different key");
            }
        }
        Err(e) => t.fail("dek_for(Database) second call", &e),
    }

    // Table scope should return a different DEK.
    match keyring.dek_for(&KeyScope::Table("users".into())) {
        Ok(dek_users) => {
            if dek_users.as_bytes() != dek1.as_bytes() {
                t.ok("Table('users') DEK differs from Database DEK");
            } else {
                t.fail("table scope", &"table DEK same as database DEK");
            }
        }
        Err(e) => t.fail("dek_for(Table('users'))", &e),
    }

    // Column scope.
    match keyring.dek_for(&KeyScope::Column {
        table: "users".into(),
        column: "ssn".into(),
    }) {
        Ok(dek_col) => {
            if dek_col.as_bytes() != dek1.as_bytes() {
                t.ok("Column('users.ssn') DEK differs from Database DEK");
            } else {
                t.fail("column scope", &"column DEK same as database DEK");
            }
        }
        Err(e) => t.fail("dek_for(Column)", &e),
    }

    // ── Sidecar persistence ─────────────────────────────────────
    t.section("EVFS Keyring - Sidecar Persistence");

    let fake_db = tmp.path("persist-test.db");
    std::fs::write(&fake_db, b"fake").unwrap();
    keyring.set_sidecar_path(&fake_db);

    // Generate a DEK (triggers sidecar write).
    let _ = keyring.dek_for(&KeyScope::Database).unwrap();

    let sidecar = fake_db.with_extension("evfs-keyring");
    if sidecar.exists() {
        t.ok("sidecar file created");
        let contents = std::fs::read_to_string(&sidecar).unwrap();
        if contents.contains("database") {
            t.ok("sidecar contains 'database' scope entry");
        } else {
            t.fail("sidecar contents", &"missing 'database' key");
        }
    } else {
        t.fail("sidecar", &"file not created");
    }

    // ── Rewrap ──────────────────────────────────────────────────
    t.section("EVFS Keyring - Rewrap All");

    match keyring.rewrap_all() {
        Ok(()) => t.ok("rewrap_all succeeded"),
        Err(e) => t.fail("rewrap_all", &e),
    }
}

// ────────────────────────────────────────────────────────────────────
// Main
// ────────────────────────────────────────────────────────────────────

fn main() {
    println!("=== LazySQL + EVFS Test Suite ===");

    // ── Parse mode argument ─────────────────────────────────────
    let mode = match env::args().nth(1).as_deref() {
        Some("--debug") => "debug",
        Some("--release") | None => "release",
        Some(other) => {
            eprintln!("Usage: lazytest [--release|--debug]");
            eprintln!("Unknown option: {}", other);
            std::process::exit(1);
        }
    };

    println!("Running in {} mode...\n", mode);

    let mut t = TestRunner::new();

    // ── sqlshim/sqlsec tests ────────────────────────────────────
    let sqlsec_path = PathBuf::from(format!("../sqlsec/target/{mode}/libsqlsec.so"));

    if sqlsec_path.exists() {
        match run_sqlshim_tests(&mut t, mode) {
            Ok(()) => {}
            Err(e) => t.fail("sqlshim test suite", &e),
        }
    } else {
        println!(
            "\n⚠ Skipping sqlshim/sqlsec tests ({})",
            sqlsec_path.display()
        );
    }

    // ── EVFS crypto unit tests ──────────────────────────────────
    run_evfs_crypto_tests(&mut t);

    // ── EVFS keyring tests ──────────────────────────────────────
    run_evfs_keyring_tests(&mut t);

    // ── EVFS backup tests ───────────────────────────────────────
    run_evfs_backup_tests(&mut t);

    // ── EVFS VFS integration tests ──────────────────────────────
    let evfs_path_str = format!("../sqlevfs/target/{}/libsqlevfs.so", mode);
    let evfs_path = Path::new(&evfs_path_str);

    if evfs_path.exists() {
        match run_evfs_vfs_tests(&mut t, mode) {
            Ok(()) => {}
            Err(e) => t.fail("evfs VFS test suite", &e),
        }
    } else {
        println!("\n⚠ Skipping EVFS VFS tests ({})", evfs_path.display());
    }

    // ── Summary ────────────────────────────────────────────────
    t.summary();

    if t.failed > 0 {
        std::process::exit(1);
    }
}
