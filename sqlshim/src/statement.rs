/// Represents all custom SQL extensions supported by the shim.
#[derive(Debug, Clone)]
pub enum CustomStatement {
    // =========================================
    // sqlsec: Row-Level & Column-Level Security
    // =========================================
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
    RefreshSecureViews,

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

    // ===============
    // Auditing (STUB)
    // ===============
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
pub struct EnableAuditStmt {
    pub table: String,
    pub operations: Vec<PolicyOperation>,
}

#[derive(Debug, Clone)]
pub struct ExplainPolicyStmt {
    pub table: String,
    pub user: String,
}
