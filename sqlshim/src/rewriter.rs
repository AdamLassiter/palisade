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
        CustomStatement::RefreshSecurityViews => {
            "SELECT sec_refresh_views();".to_string()
        }
        CustomStatement::RegisterSecureTable(r) => rewrite_register_secure_table(r),
        CustomStatement::DefineLabel(d) => rewrite_define_label(d),
        CustomStatement::DefineLevelStmt(d) => rewrite_define_level(d),
        CustomStatement::SetColumnSecurity(s) => rewrite_set_column_security(s),
        CustomStatement::CreateSecureView(v) => rewrite_create_secure_view(v),

        // Stubs
        CustomStatement::CreateTenantTable(t) => stub_create_tenant_table(t),
        CustomStatement::SetTenant(t) => stub_set_tenant(t),
        CustomStatement::ExportTenant(e) => stub_export_tenant(e),
        CustomStatement::ImportTenant(i) => stub_import_tenant(i),
        CustomStatement::CreateTemporalTable(t) => stub_create_temporal_table(t),
        CustomStatement::AsOfQuery(q) => stub_as_of_query(q),
        CustomStatement::HistoryQuery(q) => stub_history_query(q),
        CustomStatement::RestoreTable(r) => stub_restore_table(r),
        CustomStatement::CreateChangefeed(c) => stub_create_changefeed(c),
        CustomStatement::DropChangefeed(d) => stub_drop_changefeed(d),
        CustomStatement::EncryptColumn(e) => stub_encrypt_column(e),
        CustomStatement::RotateEncryptionKey(r) => stub_rotate_key(r),
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
        r#"CREATE TABLE IF NOT EXISTS __sqlshim_policies (
            name TEXT NOT NULL,
            table_name TEXT NOT NULL,
            operation TEXT NOT NULL,
            label_id INTEGER,
            expr TEXT NOT NULL,
            PRIMARY KEY (name, table_name)
        );
        INSERT OR REPLACE INTO __sqlshim_policies (name, table_name, operation, label_id, expr)
        VALUES ('{escaped_name}', '{escaped_table}', '{op_str}', NULL, '{escaped_expr}');"#
    )
}

fn rewrite_drop_policy(p: DropPolicyStmt) -> String {
    let escaped_name = escape_sql_string(&p.name);
    let escaped_table = escape_sql_string(&p.table);
    format!(
        "DELETE FROM __sqlshim_policies WHERE name = '{escaped_name}' AND table_name = '{escaped_table}';"
    )
}

fn rewrite_set_context(s: SetContextStmt) -> String {
    let escaped_key = escape_sql_string(&s.key);
    let escaped_value = escape_sql_string(&s.value);
    format!("SELECT sec_set_attr('{escaped_key}', '{escaped_value}'); SELECT sec_refresh_views();")
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
            "UPDATE sec_columns SET read_label_id = sec_define_label('{escaped}') WHERE logical_table = '{escaped_table}' AND column_name = '{escaped_column}';"
        ));
    }

    if let Some(update_label) = s.update_label {
        let escaped = escape_sql_string(&update_label);
        stmts.push(format!(
            "UPDATE sec_columns SET update_label_id = sec_define_label('{escaped}') WHERE logical_table = '{escaped_table}' AND column_name = '{escaped_column}';"
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
        "CREATE VIEW {} AS SELECT * FROM ({}) WHERE sec_assert_fresh();",
        escaped_name, v.query
    )
}

// Stubs with debug output
fn stub_create_tenant_table(t: CreateTenantTableStmt) -> String {
    eprintln!("STUB: CREATE TENANT TABLE {}", t.name);
    format!("SELECT 'STUB: CREATE TENANT TABLE {}' AS stub;", t.name)
}

fn stub_set_tenant(t: SetTenantStmt) -> String {
    eprintln!("STUB: SET TENANT = '{}'", t.tenant_id);
    format!("SELECT 'STUB: SET TENANT {}' AS stub;", t.tenant_id)
}

fn stub_export_tenant(e: ExportTenantStmt) -> String {
    eprintln!("STUB: EXPORT TENANT '{}'", e.tenant_id);
    "SELECT 'STUB: EXPORT TENANT' AS stub;".to_string()
}

fn stub_import_tenant(i: ImportTenantStmt) -> String {
    eprintln!("STUB: IMPORT TENANT '{}'", i.tenant_id);
    "SELECT 'STUB: IMPORT TENANT' AS stub;".to_string()
}

fn stub_create_temporal_table(t: CreateTemporalTableStmt) -> String {
    eprintln!("STUB: CREATE TEMPORAL TABLE {}", t.name);
    format!("SELECT 'STUB: CREATE TEMPORAL TABLE {}' AS stub;", t.name)
}

fn stub_as_of_query(_q: AsOfQueryStmt) -> String {
    eprintln!("STUB: AS OF query");
    "SELECT 'STUB: AS OF query' AS stub;".to_string()
}

fn stub_history_query(q: HistoryQueryStmt) -> String {
    eprintln!("STUB: HISTORY query on {}", q.table);
    "SELECT 'STUB: HISTORY query' AS stub;".to_string()
}

fn stub_restore_table(r: RestoreTableStmt) -> String {
    eprintln!("STUB: RESTORE {} TO '{}'", r.table, r.timestamp);
    "SELECT 'STUB: RESTORE TABLE' AS stub;".to_string()
}

fn stub_create_changefeed(c: CreateChangefeedStmt) -> String {
    eprintln!("STUB: CREATE CHANGEFEED {} ON {}", c.name, c.table);
    format!("SELECT 'STUB: CREATE CHANGEFEED {}' AS stub;", c.name)
}

fn stub_drop_changefeed(d: DropChangefeedStmt) -> String {
    eprintln!("STUB: DROP CHANGEFEED {}", d.name);
    format!("SELECT 'STUB: DROP CHANGEFEED {}' AS stub;", d.name)
}

fn stub_encrypt_column(e: EncryptColumnStmt) -> String {
    eprintln!("STUB: ENCRYPT COLUMN {}.{}", e.table, e.column);
    "SELECT 'STUB: ENCRYPT COLUMN (requires VFS)' AS stub;".to_string()
}

fn stub_rotate_key(r: RotateKeyStmt) -> String {
    eprintln!("STUB: ROTATE ENCRYPTION KEY {:?}", r.table);
    "SELECT 'STUB: ROTATE KEY (requires VFS)' AS stub;".to_string()
}

fn stub_enable_audit(a: EnableAuditStmt) -> String {
    eprintln!("STUB: ENABLE AUDIT ON {}", a.table);
    format!("SELECT 'STUB: ENABLE AUDIT ON {}' AS stub;", a.table)
}

fn stub_explain_policy(e: ExplainPolicyStmt) -> String {
    eprintln!("STUB: EXPLAIN POLICY ON {} FOR USER='{}'", e.table, e.user);
    "SELECT 'STUB: EXPLAIN POLICY' AS stub;".to_string()
}
