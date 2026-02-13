use sqlparser::parser::{Parser, ParserError};

use crate::{
    plugin::CustomPlugin,
    rewriter::escape_sql_string,
    statement::{CustomStatement, DefineLabelStmt},
};

pub struct DefineLabelPlugin;

impl CustomPlugin for DefineLabelPlugin {
    fn prefix(&self) -> &'static [&'static str] {
        &["DEFINE", "LABEL"]
    }

    fn parse(&self, parser: &mut Parser<'_>) -> Result<CustomStatement, ParserError> {
        let expr = parser.parse_literal_string()?;

        Ok(CustomStatement::DefineLabel(DefineLabelStmt { expr }))
    }

    fn rewrite(&self, stmt: CustomStatement) -> String {
        match stmt {
            CustomStatement::DefineLabel(stmt) => {
                let escaped = escape_sql_string(&stmt.expr);
                format!("SELECT sec_define_label('{escaped}');")
            }
            _ => unreachable!(),
        }
    }
}
