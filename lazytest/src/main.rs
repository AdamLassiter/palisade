use rusqlite::{Connection, Result};

fn main() -> Result<()> {
    println!("=== LazySQL Shim Test Suite ===\n");

    let conn = Connection::open(":memory:")?;

    // Load the sqlsec extension (assumes it's built and available)
    unsafe {
        conn.load_extension_enable()?;
        conn.load_extension("../sqlsec/target/release/libsqlsec", None::<&str>)?;
        conn.load_extension_disable()?;
    }

    println!("--- Testing DEFINE LABEL ---");
    conn.execute_batch("DEFINE LABEL 'true';")?;
    conn.execute_batch("DEFINE LABEL 'role=admin';")?;
    conn.execute_batch("DEFINE LABEL 'role=admin&team=finance';")?;
    conn.execute_batch("DEFINE LABEL '(role=admin|role=auditor)';")?;
    println!("✓ DEFINE LABEL statements processed\n");

    println!("--- Testing DEFINE LEVEL ---");
    conn.execute_batch("DEFINE LEVEL clearance 'public' = 0;")?;
    conn.execute_batch("DEFINE LEVEL clearance 'confidential' = 1;")?;
    conn.execute_batch("DEFINE LEVEL clearance 'secret' = 2;")?;
    conn.execute_batch("DEFINE LEVEL clearance 'top_secret' = 3;")?;
    println!("✓ DEFINE LEVEL statements processed\n");

    println!("--- Testing CREATE POLICY ---");
    conn.execute_batch(
        r#"
        CREATE POLICY invoices_read
        ON invoices
        FOR SELECT
        USING (has_role('finance'));
        "#,
    )?;
    println!("✓ CREATE POLICY (SELECT) processed");

    conn.execute_batch(
        r#"
        CREATE POLICY invoices_write
        ON invoices
        FOR UPDATE
        USING (has_role('admin') AND has_project_membership(project_id));
        "#,
    )?;
    println!("✓ CREATE POLICY (UPDATE) processed");

    conn.execute_batch(
        r#"
        CREATE POLICY users_all
        ON users
        USING (role='admin');
        "#,
    )?;
    println!("✓ CREATE POLICY (ALL) processed\n");

    println!("--- Testing DROP POLICY ---");
    conn.execute_batch("DROP POLICY invoices_write ON invoices;")?;
    println!("✓ DROP POLICY processed\n");

    println!("--- Testing SET CONTEXT ---");
    conn.execute_batch("SET CONTEXT role = 'admin';")?;
    conn.execute_batch("SET CONTEXT team = 'finance';")?;
    conn.execute_batch("SET CONTEXT clearance = 'secret';")?;
    println!("✓ SET CONTEXT statements processed\n");

    println!("--- Testing CLEAR CONTEXT ---");
    conn.execute_batch("CLEAR CONTEXT;")?;
    println!("✓ CLEAR CONTEXT processed\n");

    println!("--- Testing PUSH/POP CONTEXT ---");
    conn.execute_batch("SET CONTEXT role = 'user';")?;
    conn.execute_batch("PUSH CONTEXT;")?;
    conn.execute_batch("SET CONTEXT role = 'admin';")?;
    conn.execute_batch("POP CONTEXT;")?;
    println!("✓ PUSH/POP CONTEXT processed\n");

    println!("--- Testing REFRESH SECURE VIEWS ---");
    conn.execute_batch("REFRESH SECURE VIEWS;")?;
    println!("✓ REFRESH SECURE VIEWS processed\n");

    println!("--- Testing REGISTER SECURE TABLE ---");
    conn.execute_batch(
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
    )?;
    println!("✓ REGISTER SECURE TABLE (basic) processed");

    conn.execute_batch(
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
    )?;
    println!("✓ REGISTER SECURE TABLE (with labels) processed\n");

    println!("--- Testing CREATE SECURE VIEW ---");
    conn.execute_batch(
        r#"
        CREATE SECURE VIEW employee_view AS
        SELECT id, name, salary
        FROM employees
        WHERE department = 'finance';
        "#,
    )?;
    println!("✓ CREATE SECURE VIEW (basic) processed\n");

    println!("--- Testing SET COLUMN SECURITY ---");
    conn.execute_batch("SET COLUMN SECURITY employees.salary READ 'role=manager';")?;
    println!("✓ SET COLUMN SECURITY (read) processed");

    conn.execute_batch("SET COLUMN SECURITY employees.title UPDATE 'role=hr';")?;
    println!("✓ SET COLUMN SECURITY (update) processed");

    conn.execute_batch(
        "SET COLUMN SECURITY employees.ssn READ 'role=admin' UPDATE 'role=auditor';",
    )?;
    println!("✓ SET COLUMN SECURITY (read+update) processed\n");

    println!("--- Testing Stub Features (should show warnings) ---");

    println!("\nAudit features:");
    conn.execute_batch("ENABLE AUDIT ON users;")?;
    conn.execute_batch("ENABLE AUDIT ON invoices FOR INSERT, UPDATE, DELETE;")?;
    conn.execute_batch("EXPLAIN POLICY ON employees FOR USER = 'alice';")?;

    println!("\n--- Testing Passthrough (normal SQL) ---");
    conn.execute_batch("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT);")?;
    conn.execute_batch("INSERT INTO test_table (id, name) VALUES (1, 'test');")?;

    let name: String = conn.query_row("SELECT name FROM test_table WHERE id = 1", [], |row| {
        row.get(0)
    })?;
    assert_eq!(name, "test");
    println!("✓ Normal SQL passthrough works\n");

    println!("=== All tests completed ===");

    Ok(())
}
