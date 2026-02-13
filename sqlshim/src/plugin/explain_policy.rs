use sqlparser::{
    keywords::Keyword,
    parser::{Parser, ParserError},
    tokenizer::Token,
};

use crate::{
    plugin::CustomPlugin,
    rewriter::escape_sql_string,
    statement::{CustomStatement, ExplainPolicyStmt},
};

pub struct ExplainPolicyPlugin;

impl CustomPlugin for ExplainPolicyPlugin {
    fn prefix(&self) -> &'static [&'static str] {
        &["EXPLAIN", "POLICY"]
    }

    fn parse(&self, parser: &mut Parser<'_>) -> Result<CustomStatement, ParserError> {
        parser.expect_keyword(Keyword::ON)?;
        let table = parser.parse_identifier()?.value;

        parser.expect_keyword(Keyword::FOR)?;
        parser.expect_keyword(Keyword::USER)?;
        parser.expect_token(&Token::Eq)?;
        let user = parser.parse_literal_string()?;

        Ok(CustomStatement::ExplainPolicy(ExplainPolicyStmt {
            table,
            user,
        }))
    }

    fn rewrite(&self, stmt: CustomStatement) -> String {
        match stmt {
            CustomStatement::ExplainPolicy(stmt) => {
                let escaped_table = escape_sql_string(&stmt.table);
                let escaped_user = stmt.user;

                format!(
                    r#"
                     SELECT 'EXPLAIN POLICY ON {escaped_table} FOR USER="{escaped_user}"' AS stub;
                     "#
                )
            }
            _ => unreachable!(),
        }
    }
}
