use sqlparser::{
    parser::{Parser, ParserError},
    tokenizer::Token,
};

use crate::{
    parser::ParserExt,
    plugin::CustomPlugin,
    rewriter::escape_sql_string,
    statement::{CustomStatement, DefineLevelStmt},
};

pub struct DefineLevelPlugin;

impl CustomPlugin for DefineLevelPlugin {
    fn prefix(&self) -> &'static [&'static str] {
        &["DEFINE", "LEVEL"]
    }

    fn parse(&self, parser: &mut Parser<'_>) -> Result<CustomStatement, ParserError> {
        let attribute = parser.parse_identifier()?.value;
        let name = parser.parse_literal_string()?;
        parser.expect_token(&Token::Eq)?;
        let value = parser.parse_literal_int()?;

        Ok(CustomStatement::DefineLevelStmt(DefineLevelStmt {
            attribute,
            name,
            value,
        }))
    }

    fn rewrite(&self, stmt: CustomStatement) -> String {
        match stmt {
            CustomStatement::DefineLevelStmt(stmt) => {
                let escaped_attr = escape_sql_string(&stmt.attribute);
                let escaped_name = escape_sql_string(&stmt.name);
                format!(
                    "SELECT sec_define_level('{escaped_attr}', '{escaped_name}', {});",
                    stmt.value
                )
            }
            _ => unreachable!(),
        }
    }
}
