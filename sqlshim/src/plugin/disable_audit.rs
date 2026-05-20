use sqlparser::{
    keywords::Keyword,
    parser::{Parser, ParserError},
};

use crate::{
    plugin::CustomPlugin,
    rewriter::escape_sql_string,
    statement::{CustomStatement, DisableAuditStmt},
};

pub struct DisableAuditPlugin;

impl CustomPlugin for DisableAuditPlugin {
    fn prefix(&self) -> &'static [&'static str] {
        &["DISABLE", "AUDIT"]
    }

    fn parse(&self, parser: &mut Parser<'_>) -> Result<CustomStatement, ParserError> {
        parser.expect_keyword(Keyword::ON)?;
        let table = parser.parse_identifier()?.value;
        Ok(CustomStatement::DisableAudit(DisableAuditStmt { table }))
    }

    fn rewrite(&self, stmt: CustomStatement) -> String {
        match stmt {
            CustomStatement::DisableAudit(stmt) => {
                let escaped_table = escape_sql_string(&stmt.table);
                format!("SELECT sec_audit_disable('{escaped_table}');")
            }
            _ => unreachable!(),
        }
    }
}
