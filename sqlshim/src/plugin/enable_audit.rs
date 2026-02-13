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
                let ops_str = stmt
                    .operations
                    .iter()
                    .map(|op| match op {
                        PolicyOperation::Select => "SELECT",
                        PolicyOperation::Insert => "INSERT",
                        PolicyOperation::Update => "UPDATE",
                        PolicyOperation::Delete => "DELETE",
                        PolicyOperation::All => "ALL",
                    })
                    .collect::<Vec<_>>()
                    .join(", ");

                format!(
                    r#"
                    SELECT 'ENABLE AUDIT ON {escaped_table} FOR {ops_str}' AS stub;
                    "#
                )
            }
            _ => unreachable!(),
        }
    }
}
