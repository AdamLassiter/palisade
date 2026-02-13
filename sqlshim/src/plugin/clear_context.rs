use sqlparser::parser::{Parser, ParserError};

use crate::{plugin::CustomPlugin, statement::CustomStatement};

pub struct ClearContextPlugin;

impl CustomPlugin for ClearContextPlugin {
    fn prefix(&self) -> &'static [&'static str] {
        &["CLEAR", "CONTEXT"]
    }

    fn parse(&self, _parser: &mut Parser<'_>) -> Result<CustomStatement, ParserError> {
        Ok(CustomStatement::ClearContext)
    }

    fn rewrite(&self, stmt: CustomStatement) -> String {
        match stmt {
            CustomStatement::ClearContext => "SELECT sec_clear_context();".to_string(),
            _ => unreachable!(),
        }
    }
}
