use sqlparser::{
    keywords::Keyword,
    parser::{Parser, ParserError},
};

use crate::{
    parser::ParserExt,
    plugin::CustomPlugin,
    rewriter::escape_sql_string,
    statement::{CustomStatement, EnableAuditStmt, PolicyOperation},
};

pub struct EnableAuditPlugin;

impl CustomPlugin for EnableAuditPlugin {
    fn prefix(&self) -> &'static [&'static str] {
        &["ENABLE", "AUDIT"]
    }

    fn parse(&self, parser: &mut Parser<'_>) -> Result<CustomStatement, ParserError> {
        parser.expect_keyword(Keyword::ON)?;
        let table = parser.parse_identifier()?.value;

        let operations = if parser.parse_keyword(Keyword::FOR) {
            parser.parse_operation_list()?
        } else {
            vec![PolicyOperation::All]
        };

        Ok(CustomStatement::EnableAudit(EnableAuditStmt {
            table,
            operations,
        }))
    }

    fn rewrite(&self, stmt: CustomStatement) -> String {
        match stmt {
            CustomStatement::EnableAudit(stmt) => {
                let escaped_table = escape_sql_string(&stmt.table);
                let (audit_insert, audit_update, audit_delete) = audit_flags(&stmt.operations);

                format!(
                    r#"
                    SELECT sec_audit_enable('{escaped_table}');
                    SELECT sec_audit_configure('{escaped_table}', 'audit_insert', {audit_insert});
                    SELECT sec_audit_configure('{escaped_table}', 'audit_update', {audit_update});
                    SELECT sec_audit_configure('{escaped_table}', 'audit_delete', {audit_delete});
                    "#
                )
            }
            _ => unreachable!(),
        }
    }
}

fn audit_flags(operations: &[PolicyOperation]) -> (i64, i64, i64) {
    if operations
        .iter()
        .any(|op| matches!(op, PolicyOperation::All))
    {
        return (1, 1, 1);
    }

    let audit_insert = operations
        .iter()
        .any(|op| matches!(op, PolicyOperation::Insert)) as i64;
    let audit_update = operations
        .iter()
        .any(|op| matches!(op, PolicyOperation::Update)) as i64;
    let audit_delete = operations
        .iter()
        .any(|op| matches!(op, PolicyOperation::Delete)) as i64;

    (audit_insert, audit_update, audit_delete)
}
