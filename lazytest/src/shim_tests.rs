use rusqlite::{Connection, Result};

use crate::helpers::TestRunner;

pub(crate) fn run_sqlshim_tests(t: &mut TestRunner, mode: &str) -> Result<()> {
    t.section("sqlshim + sqlsec Extension Loading");

    let conn = Connection::open(":memory:")?;

    unsafe {
        conn.load_extension_enable()?;
        match conn.load_extension(format!("../sqlsec/target/{mode}/libsqlsec"), None::<&str>) {
            Ok(()) => t.ok("loaded sqlsec extension"),
            Err(e) => {
                t.fail("load sqlsec extension", &e);
                return Ok(());
            }
        }
        conn.load_extension_disable()?;
    }

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

    t.section("DROP POLICY");
    match conn.execute_batch("DROP POLICY invoices_write ON invoices;") {
        Ok(()) => t.ok("DROP POLICY"),
        Err(e) => t.fail("DROP POLICY", &e),
    }

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

    t.section("REFRESH SECURE VIEWS");
    match conn.execute_batch("REFRESH SECURE VIEWS;") {
        Ok(()) => t.ok("REFRESH SECURE VIEWS"),
        Err(e) => t.fail("REFRESH SECURE VIEWS", &e),
    }

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

    t.section("Normal SQL Passthrough");
    conn.execute_batch("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT);")?;
    conn.execute_batch("INSERT INTO test_table (id, name) VALUES (1, 'test');")?;
    let name: String = conn.query_row("SELECT name FROM test_table WHERE id = 1", [], |row| {
        row.get(0)
    })?;
    t.assert_eq("SELECT passthrough", &name, &"test".to_string());

    Ok(())
}
