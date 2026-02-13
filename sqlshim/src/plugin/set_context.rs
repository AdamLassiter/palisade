use sqlparser::{parser::{Parser, ParserError}, tokenizer::Token};

use crate::{plugin::CustomPlugin, rewriter::escape_sql_string, statement::CustomStatement};

pub struct SetContextPlugin;

impl CustomPlugin for SetContextPlugin {
    fn prefix(&self) -> &'static [&'static str] {
        &["SET", "CONTEXT"]
    }

    fn parse(&self, parser: &mut Parser<'_>) -> Result<CustomStatement, ParserError> {
        let key = parser.parse_identifier()?.value;
        parser.expect_token(&Token::Eq)?;
        let value = parser.parse_literal_string()?;

        Ok(CustomStatement::SetContext(crate::statement::SetContextStmt { key, value }))
    }

    fn rewrite(&self, stmt: CustomStatement) -> String {
        match stmt {
            CustomStatement::SetContext(stmt) => {
                let escaped_key = escape_sql_string(&stmt.key);
                let escaped_value = escape_sql_string(&stmt.value);
                format!(
                    r#"
                    SELECT sec_set_attr('{escaped_key}', '{escaped_value}');
                    SELECT sec_refresh_views();
                    "#
                )
            }
            _ => unreachable!(),
        }
    }
}
