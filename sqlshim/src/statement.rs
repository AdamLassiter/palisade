/// Represents all custom SQL extensions supported by the shim.
#[derive(Debug, Clone)]
pub enum CustomStatement {
    // ========================================================================
    // sqlsec: Row-Level & Column-Level Security (IMPLEMENTED)
    // ========================================================================
    /// CREATE POLICY name ON table [FOR operation] USING (expr)
    CreatePolicy(CreatePolicyStmt),

    /// DROP POLICY name ON table
    DropPolicy(DropPolicyStmt),

    /// SET CONTEXT key = 'value'
    SetContext(SetContextStmt),

    /// CLEAR CONTEXT
    ClearContext,

    /// PUSH CONTEXT
    PushContext,

    /// POP CONTEXT
    PopContext,

    /// REFRESH SECURITY VIEWS
    RefreshSecurityViews,

    /// CREATE SECURE VIEW name AS SELECT ... (with automatic policy injection)
    CreateSecureView(CreateSecureViewStmt),

    /// REGISTER SECURE TABLE logical ON physical WITH ROW LABEL column
    ///     [TABLE LABEL label_expr] [INSERT LABEL label_expr]
    RegisterSecureTable(RegisterSecureTableStmt),

    /// DEFINE LABEL 'expr'
    DefineLabel(DefineLabelStmt),

    /// DEFINE LEVEL attr 'name' = value
    DefineLevelStmt(DefineLevelStmt),

    /// SET COLUMN SECURITY table.column READ 'label_expr' [UPDATE 'label_expr']
    SetColumnSecurity(SetColumnSecurityStmt),

    // ========================================================================
    // Multi-Tenancy (STUB)
    // ========================================================================
    /// CREATE TENANT TABLE name (...)
    /// Expected: sec_tenant_register_table(name), auto-add tenant_id column
    CreateTenantTable(CreateTenantTableStmt),

    /// SET TENANT = 'value'
    /// Expected: sec_set_tenant(value), auto-filter all tenant tables
    SetTenant(SetTenantStmt),

    /// EXPORT TENANT 'name' [TO 'path']
    /// Expected: Generate INSERT statements for all tenant data
    ExportTenant(ExportTenantStmt),

    /// IMPORT TENANT 'name' [FROM 'path']
    /// Expected: Import tenant data with conflict resolution
    ImportTenant(ImportTenantStmt),

    // ========================================================================
    // Temporal Tables (STUB)
    // ========================================================================
    /// CREATE TEMPORAL TABLE name (...)
    /// Expected: Create table + history table + versioning triggers
    CreateTemporalTable(CreateTemporalTableStmt),

    /// SELECT ... FROM table AS OF 'timestamp'
    /// Expected: Rewrite to query history with valid_from/valid_to filter
    AsOfQuery(AsOfQueryStmt),

    /// SELECT ... FROM table HISTORY [WHERE ...]
    /// Expected: Query the history table directly
    HistoryQuery(HistoryQueryStmt),

    /// RESTORE table TO 'timestamp' [WHERE ...]
    /// Expected: Copy rows from history back to main table
    RestoreTable(RestoreTableStmt),

    // ========================================================================
    // Change Data Capture (STUB)
    // ========================================================================
    /// CREATE CHANGEFEED name ON table [WHERE ...]
    /// Expected: Create outbox table + triggers for CDC
    CreateChangefeed(CreateChangefeedStmt),

    /// DROP CHANGEFEED name
    /// Expected: Remove CDC infrastructure
    DropChangefeed(DropChangefeedStmt),

    // ========================================================================
    // Encryption (STUB - requires VFS layer)
    // ========================================================================
    /// ENCRYPT COLUMN table.column WITH KEY('keyname')
    /// Expected: Mark column for encryption, rewrite queries
    EncryptColumn(EncryptColumnStmt),

    /// ROTATE ENCRYPTION KEY [FOR table]
    /// Expected: Re-encrypt all data with new key
    RotateEncryptionKey(RotateKeyStmt),

    // ========================================================================
    // Auditing (STUB)
    // ========================================================================
    /// ENABLE AUDIT ON table [FOR operations]
    /// Expected: Create audit triggers
    EnableAudit(EnableAuditStmt),

    /// EXPLAIN POLICY ON table FOR USER = 'name'
    /// Expected: Show which rows/columns would be visible
    ExplainPolicy(ExplainPolicyStmt),
}

#[derive(Debug, Clone)]
pub struct CreatePolicyStmt {
    pub name: String,
    pub table: String,
    pub operation: Option<PolicyOperation>,
    pub using_expr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyOperation {
    Select,
    Insert,
    Update,
    Delete,
    All,
}

#[derive(Debug, Clone)]
pub struct DropPolicyStmt {
    pub name: String,
    pub table: String,
}

#[derive(Debug, Clone)]
pub struct SetContextStmt {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct CreateSecureViewStmt {
    pub name: String,
    pub query: String,
}

#[derive(Debug, Clone)]
pub struct RegisterSecureTableStmt {
    pub logical_name: String,
    pub physical_name: String,
    pub row_label_column: String,
    pub table_label: Option<String>,
    pub insert_label: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DefineLabelStmt {
    pub expr: String,
}

#[derive(Debug, Clone)]
pub struct DefineLevelStmt {
    pub attribute: String,
    pub name: String,
    pub value: i64,
}

#[derive(Debug, Clone)]
pub struct SetColumnSecurityStmt {
    pub table: String,
    pub column: String,
    pub read_label: Option<String>,
    pub update_label: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CreateTenantTableStmt {
    pub name: String,
    pub columns: String,
}

#[derive(Debug, Clone)]
pub struct SetTenantStmt {
    pub tenant_id: String,
}

#[derive(Debug, Clone)]
pub struct ExportTenantStmt {
    pub tenant_id: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ImportTenantStmt {
    pub tenant_id: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CreateTemporalTableStmt {
    pub name: String,
    pub columns: String,
}

#[derive(Debug, Clone)]
pub struct AsOfQueryStmt {
    pub original_sql: String,
    pub table: String,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct HistoryQueryStmt {
    pub table: String,
    pub where_clause: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RestoreTableStmt {
    pub table: String,
    pub timestamp: String,
    pub where_clause: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CreateChangefeedStmt {
    pub name: String,
    pub table: String,
    pub filter: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DropChangefeedStmt {
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct EncryptColumnStmt {
    pub table: String,
    pub column: String,
    pub key_name: String,
}

#[derive(Debug, Clone)]
pub struct RotateKeyStmt {
    pub table: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EnableAuditStmt {
    pub table: String,
    pub operations: Vec<PolicyOperation>,
}

#[derive(Debug, Clone)]
pub struct ExplainPolicyStmt {
    pub table: String,
    pub user: String,
}
