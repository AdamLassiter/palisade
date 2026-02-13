use sqlparser::parser::{Parser, ParserError};

use crate::{plugin::CustomPlugin, statement::CustomStatement};

pub struct PopContextPlugin;

impl CustomPlugin for PopContextPlugin {
    fn prefix(&self) -> &'static [&'static str] {
        &["POP", "CONTEXT"]
    }

    fn parse(&self, _parser: &mut Parser<'_>) -> Result<CustomStatement, ParserError> {
        Ok(CustomStatement::PopContext)
    }

    fn rewrite(&self, stmt: CustomStatement) -> String {
        match stmt {
            CustomStatement::PopContext => "SELECT sec_pop_context();".to_string(),
            _ => unreachable!(),
        }
    }
}
