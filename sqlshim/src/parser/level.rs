use sqlparser::{parser::ParserError, tokenizer::Token};

use super::CustomParser;
use crate::statement::*;

impl CustomParser {
    pub(crate) fn parse_define_level(&mut self) -> Result<CustomStatement, ParserError> {
        let attribute = self.parse_identifier()?.value;
        let name = self.parse_literal_string()?;
        self.parser.expect_token(&Token::Eq)?;
        let value = self.parse_literal_int()?;

        Ok(CustomStatement::DefineLevelStmt(DefineLevelStmt {
            attribute,
            name,
            value,
        }))
    }
}
