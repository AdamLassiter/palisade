use sqlparser::{
    keywords::Keyword,
    parser::{Parser, ParserError},
    tokenizer::Token,
};

use crate::{
    parser::ParserExt,
    plugin::CustomPlugin,
    rewriter::escape_sql_string,
    statement::{CreatePolicyStmt, CustomStatement, PolicyOperation},
};

pub struct CreatePolicyPlugin;

impl CustomPlugin for CreatePolicyPlugin {
    fn prefix(&self) -> &'static [&'static str] {
        &["CREATE", "POLICY"]
    }

    fn parse(&self, parser: &mut Parser<'_>) -> Result<CustomStatement, ParserError> {
        let name = parser.parse_identifier()?.value;

        parser.expect_keyword(Keyword::ON)?;
        let table = parser.parse_identifier()?.value;

        let operation = if parser.parse_keyword(Keyword::FOR) {
            Some(parser.parse_policy_operation()?)
        } else {
            None
        };

        parser.expect_word("USING")?;
        parser.expect_token(&Token::LParen)?;
        let using_expr = parser.parse_until_token(&Token::RParen)?;
        parser.expect_token(&Token::RParen)?;

        Ok(CustomStatement::CreatePolicy(CreatePolicyStmt {
            name,
            table,
            operation,
            using_expr,
        }))
    }

    fn rewrite(&self, stmt: CustomStatement) -> String {
        match stmt {
            CustomStatement::CreatePolicy(stmt) => {
                let escaped_expr = escape_sql_string(&stmt.using_expr);
                let escaped_name = escape_sql_string(&stmt.name);
                let escaped_table = escape_sql_string(&stmt.table);

                let op_str = match stmt.operation {
                    Some(PolicyOperation::Select) => "SELECT",
                    Some(PolicyOperation::Insert) => "INSERT",
                    Some(PolicyOperation::Update) => "UPDATE",
                    Some(PolicyOperation::Delete) => "DELETE",
                    Some(PolicyOperation::All) | None => "ALL",
                };

                format!(
                    r#"
                    CREATE TABLE IF NOT EXISTS __sqlshim_policies (
                        name TEXT NOT NULL,
                        table_name TEXT NOT NULL,
                        operation TEXT NOT NULL,
                        label_id INTEGER,
                        expr TEXT NOT NULL,
                        PRIMARY KEY (name, table_name)
                    );
                    INSERT OR REPLACE INTO __sqlshim_policies (name, table_name, operation, label_id, expr)
                    VALUES ('{escaped_name}', '{escaped_table}', '{op_str}', NULL, '{escaped_expr}');
                    "#
                )
            }
            _ => unreachable!(),
        }
    }
}
