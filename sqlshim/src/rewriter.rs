use crate::statement::*;

fn escape_sql_string(s: &str) -> String {
    s.replace('\'', "''")
}

pub fn rewrite(stmt: CustomStatement) -> String {
    match stmt {
        // sqlsec: Fully Implemented
        CustomStatement::CreatePolicy(p) => rewrite_create_policy(p),
        CustomStatement::DropPolicy(p) => rewrite_drop_policy(p),
        CustomStatement::SetContext(s) => rewrite_set_context(s),
        CustomStatement::ClearContext => "SELECT sec_clear_context();".to_string(),
        CustomStatement::PushContext => "SELECT sec_push_context();".to_string(),
        CustomStatement::PopContext => "SELECT sec_pop_context();".to_string(),
        CustomStatement::RefreshSecureViews => "SELECT sec_refresh_views();".to_string(),
        CustomStatement::RegisterSecureTable(r) => rewrite_register_secure_table(r),
        CustomStatement::DefineLabel(d) => rewrite_define_label(d),
        CustomStatement::DefineLevelStmt(d) => rewrite_define_level(d),
        CustomStatement::SetColumnSecurity(s) => rewrite_set_column_security(s),
        CustomStatement::CreateSecureView(v) => rewrite_create_secure_view(v),

        // Stubs
        CustomStatement::EnableAudit(a) => stub_enable_audit(a),
        CustomStatement::ExplainPolicy(e) => stub_explain_policy(e),
    }
}

fn rewrite_create_policy(p: CreatePolicyStmt) -> String {
    let escaped_expr = escape_sql_string(&p.using_expr);
    let escaped_name = escape_sql_string(&p.name);
    let escaped_table = escape_sql_string(&p.table);

    let op_str = match p.operation {
        Some(PolicyOperation::Select) => "SELECT",
        Some(PolicyOperation::Insert) => "INSERT",
        Some(PolicyOperation::Update) => "UPDATE",
        Some(PolicyOperation::Delete) => "DELETE",
        Some(PolicyOperation::All) | None => "ALL",
    };

    format!(
        r#"
        CREATE TABLE IF NOT EXISTS __sqlshim_policies (
            name TEXT NOT NULL,
            table_name TEXT NOT NULL,
            operation TEXT NOT NULL,
            label_id INTEGER,
            expr TEXT NOT NULL,
            PRIMARY KEY (name, table_name)
        );
        INSERT OR REPLACE INTO __sqlshim_policies (name, table_name, operation, label_id, expr)
        VALUES ('{escaped_name}', '{escaped_table}', '{op_str}', NULL, '{escaped_expr}');
        "#
    )
}

fn rewrite_drop_policy(p: DropPolicyStmt) -> String {
    let escaped_name = escape_sql_string(&p.name);
    let escaped_table = escape_sql_string(&p.table);
    format!(
        r#"
        DELETE FROM __sqlshim_policies
        WHERE name = '{escaped_name}'
        AND table_name = '{escaped_table}';
        "#
    )
}

fn rewrite_set_context(s: SetContextStmt) -> String {
    let escaped_key = escape_sql_string(&s.key);
    let escaped_value = escape_sql_string(&s.value);
    format!(
        r#"
        SELECT sec_set_attr('{escaped_key}', '{escaped_value}');
        SELECT sec_refresh_views();
        "#
    )
}

fn rewrite_register_secure_table(r: RegisterSecureTableStmt) -> String {
    let escaped_logical = escape_sql_string(&r.logical_name);
    let escaped_physical = escape_sql_string(&r.physical_name);
    let escaped_row_col = escape_sql_string(&r.row_label_column);

    let table_label = r
        .table_label
        .map(|l| format!("sec_define_label('{}')", escape_sql_string(&l)))
        .unwrap_or_else(|| "NULL".to_string());

    let insert_label = r
        .insert_label
        .map(|l| format!("sec_define_label('{}')", escape_sql_string(&l)))
        .unwrap_or_else(|| "NULL".to_string());

    format!(
        "SELECT sec_register_table('{escaped_logical}', '{escaped_physical}', '{escaped_row_col}', {table_label}, {insert_label});"
    )
}

fn rewrite_define_label(d: DefineLabelStmt) -> String {
    let escaped = escape_sql_string(&d.expr);
    format!("SELECT sec_define_label('{escaped}');")
}

fn rewrite_define_level(d: DefineLevelStmt) -> String {
    let escaped_attr = escape_sql_string(&d.attribute);
    let escaped_name = escape_sql_string(&d.name);
    format!(
        "SELECT sec_define_level('{escaped_attr}', '{escaped_name}', {});",
        d.value
    )
}

fn rewrite_set_column_security(s: SetColumnSecurityStmt) -> String {
    let escaped_table = escape_sql_string(&s.table);
    let escaped_column = escape_sql_string(&s.column);

    let mut stmts = Vec::new();

    if let Some(read_label) = s.read_label {
        let escaped = escape_sql_string(&read_label);
        stmts.push(format!(
            r#"
            UPDATE sec_columns
            SET read_label_id = sec_define_label('{escaped}')
            WHERE logical_table = '{escaped_table}'
              AND column_name = '{escaped_column}';
            "#
        ));
    }

    if let Some(update_label) = s.update_label {
        let escaped = escape_sql_string(&update_label);
        stmts.push(format!(
            r#"
            UPDATE sec_columns
            SET update_label_id = sec_define_label('{escaped}')
            WHERE logical_table = '{escaped_table}'
              AND column_name = '{escaped_column}';
            "#
        ));
    }

    if stmts.is_empty() {
        "SELECT 1;".to_string()
    } else {
        stmts.join("\n")
    }
}

fn rewrite_create_secure_view(v: CreateSecureViewStmt) -> String {
    let escaped_name = escape_sql_string(&v.name);
    format!(
        r#"
        CREATE VIEW {} AS
        SELECT *
        FROM ({})
        WHERE sec_assert_fresh();
        "#,
        escaped_name, v.query
    )
}

// Stubs with debug output
fn stub_enable_audit(a: EnableAuditStmt) -> String {
    eprintln!("STUB: ENABLE AUDIT ON {}", a.table);
    format!("SELECT 'STUB: ENABLE AUDIT ON {}' AS stub;", a.table)
}

fn stub_explain_policy(e: ExplainPolicyStmt) -> String {
    eprintln!("STUB: EXPLAIN POLICY ON {} FOR USER='{}'", e.table, e.user);
    "SELECT 'STUB: EXPLAIN POLICY' AS stub;".to_string()
}
