use sqlparser::{parser::ParserError, tokenizer::Token};

use super::CustomParser;
use crate::statement::*;

impl CustomParser {
    pub(crate) fn parse_set_context(&mut self) -> Result<CustomStatement, ParserError> {
        let key = self.parse_identifier()?.value;
        self.parser.expect_token(&Token::Eq)?;
        let value = self.parse_literal_string()?;

        Ok(CustomStatement::SetContext(SetContextStmt { key, value }))
    }

    pub(crate) fn parse_clear_context(&mut self) -> Result<CustomStatement, ParserError> {
        self.expect_word("CONTEXT")?;
        Ok(CustomStatement::ClearContext)
    }

    pub(crate) fn parse_push_context(&mut self) -> Result<CustomStatement, ParserError> {
        self.expect_word("CONTEXT")?;
        Ok(CustomStatement::PushContext)
    }

    pub(crate) fn parse_pop_context(&mut self) -> Result<CustomStatement, ParserError> {
        self.expect_word("CONTEXT")?;
        Ok(CustomStatement::PopContext)
    }
}
