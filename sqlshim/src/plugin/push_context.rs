use sqlparser::parser::{Parser, ParserError};

use crate::{plugin::CustomPlugin, statement::CustomStatement};

pub struct PushContextPlugin;

impl CustomPlugin for PushContextPlugin {
    fn prefix(&self) -> &'static [&'static str] {
        &["PUSH", "CONTEXT"]
    }

    fn parse(&self, _parser: &mut Parser<'_>) -> Result<CustomStatement, ParserError> {
        Ok(CustomStatement::PushContext)
    }

    fn rewrite(&self, stmt: CustomStatement) -> String {
        match stmt {
            CustomStatement::PushContext => "SELECT sec_push_context();".to_string(),
            _ => unreachable!(),
        }
    }
}
