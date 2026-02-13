use sqlparser::{
    keywords::Keyword,
    parser::{Parser, ParserError},
};

use crate::{
    plugin::CustomPlugin,
    rewriter::escape_sql_string,
    statement::{CustomStatement, DropPolicyStmt},
};

pub struct DropPolicyPlugin;

impl CustomPlugin for DropPolicyPlugin {
    fn prefix(&self) -> &'static [&'static str] {
        &["DROP", "POLICY"]
    }

    fn parse(&self, parser: &mut Parser<'_>) -> Result<CustomStatement, ParserError> {
        let name = parser.parse_identifier()?.value;

        parser.expect_keyword(Keyword::ON)?;
        let table = parser.parse_identifier()?.value;

        Ok(CustomStatement::DropPolicy(DropPolicyStmt { name, table }))
    }

    fn rewrite(&self, stmt: CustomStatement) -> String {
        match stmt {
            CustomStatement::DropPolicy(stmt) => {
                let escaped_name = escape_sql_string(&stmt.name);
                let escaped_table = escape_sql_string(&stmt.table);
                format!(
                    r#"
                    DELETE FROM __sqlshim_policies
                    WHERE name = '{escaped_name}'
                    AND table_name = '{escaped_table}';
                    "#
                )
            }
            _ => unreachable!(),
        }
    }
}
