use sqlparser::{
    keywords::Keyword,
    parser::{Parser, ParserError},
};

use crate::{
    plugin::CustomPlugin,
    rewriter::escape_sql_string,
    statement::{CreateSecureViewStmt, CustomStatement},
};

pub struct CreateSecureViewPlugin;

impl CustomPlugin for CreateSecureViewPlugin {
    fn prefix(&self) -> &'static [&'static str] {
        &["CREATE", "SECURE", "VIEW"]
    }

    fn parse(&self, parser: &mut Parser<'_>) -> Result<CustomStatement, ParserError> {
        let name = parser.parse_identifier()?.value;

        parser.expect_keyword(Keyword::AS)?;
        let query = parser.parse_query()?.to_string();

        Ok(CustomStatement::CreateSecureView(CreateSecureViewStmt {
            name,
            query,
        }))
    }

    fn rewrite(&self, stmt: CustomStatement) -> String {
        match stmt {
            CustomStatement::CreateSecureView(stmt) => {
                let escaped_name = escape_sql_string(&stmt.name);
                format!(
                    r#"
                    CREATE VIEW {} AS
                    SELECT *
                    FROM ({})
                    WHERE sec_assert_fresh();
                    "#,
                    escaped_name, stmt.query
                )
            }
            _ => unreachable!(),
        }
    }
}
