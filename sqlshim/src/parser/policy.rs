use sqlparser::{dialect::keywords::Keyword, parser::ParserError, tokenizer::Token};

use super::CustomParser;
use crate::statement::*;

impl CustomParser {
    pub(crate) fn parse_create_policy(&mut self) -> Result<CustomStatement, ParserError> {
        let name = self.parse_identifier()?.value;
        self.parser.expect_keyword(Keyword::ON)?;
        let table = self.parse_identifier()?.value;

        let operation = if self.parser.parse_keyword(Keyword::FOR) {
            Some(self.parse_policy_operation()?)
        } else {
            None
        };

        self.expect_word("USING")?;
        self.parser.expect_token(&Token::LParen)?;
        let using_expr = self.parse_until_token(&Token::RParen)?;
        self.parser.expect_token(&Token::RParen)?;

        Ok(CustomStatement::CreatePolicy(CreatePolicyStmt {
            name,
            table,
            operation,
            using_expr,
        }))
    }

    pub(crate) fn parse_drop_policy(&mut self) -> Result<CustomStatement, ParserError> {
        let name = self.parse_identifier()?.value;
        self.parser.expect_keyword(Keyword::ON)?;
        let table = self.parse_identifier()?.value;

        Ok(CustomStatement::DropPolicy(DropPolicyStmt { name, table }))
    }

    pub(crate) fn parse_explain_policy(&mut self) -> Result<CustomStatement, ParserError> {
        self.parser.expect_keyword(Keyword::ON)?;
        let table = self.parse_identifier()?.value;
        self.parser.expect_keyword(Keyword::FOR)?;
        self.parser.expect_keyword(Keyword::USER)?;
        self.parser.expect_token(&Token::Eq)?;
        let user = self.parse_literal_string()?;

        Ok(CustomStatement::ExplainPolicy(ExplainPolicyStmt {
            table,
            user,
        }))
    }
}
