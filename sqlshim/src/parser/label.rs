use sqlparser::parser::ParserError;

use super::CustomParser;
use crate::statement::*;

impl CustomParser {
    pub(crate) fn parse_define_label(&mut self) -> Result<CustomStatement, ParserError> {
        let expr = self.parse_literal_string()?;
        Ok(CustomStatement::DefineLabel(DefineLabelStmt { expr }))
    }
}
