use sqlparser::{dialect::keywords::Keyword, parser::ParserError, tokenizer::Token};

use super::CustomParser;
use crate::statement::*;

impl CustomParser {
    pub(crate) fn parse_create_secure_view(&mut self) -> Result<CustomStatement, ParserError> {
        let name = self.parse_identifier()?.value;
        self.parser.expect_keyword(Keyword::AS)?;
        let query = self.parser.parse_query()?.to_string();

        Ok(CustomStatement::CreateSecureView(CreateSecureViewStmt { name, query }))
    }

    pub(crate) fn parse_register_secure_table(&mut self) -> Result<CustomStatement, ParserError> {
        let logical_name = self.parse_identifier()?.value;
        self.parser.expect_keyword(Keyword::ON)?;
        let physical_name = self.parse_identifier()?.value;
        self.parser.expect_keyword(Keyword::WITH)?;
        self.expect_word("ROW")?;
        self.expect_word("LABEL")?;
        let row_label_column = self.parse_identifier()?.value;

        let mut table_label = None;
        let mut insert_label = None;

        while !self.is_statement_end() {
            if self.parse_keyword_seq(&["TABLE", "LABEL"]) {
                table_label = Some(self.parse_literal_string()?);
            } else if self.parse_keyword_seq(&["INSERT", "LABEL"]) {
                insert_label = Some(self.parse_literal_string()?);
            } else {
                break;
            }
        }

        Ok(CustomStatement::RegisterSecureTable(
            RegisterSecureTableStmt {
                logical_name,
                physical_name,
                row_label_column,
                table_label,
                insert_label,
            },
        ))
    }

    pub(crate) fn parse_set_column_security(&mut self) -> Result<CustomStatement, ParserError> {
        let table = self.parse_identifier()?.value;
        self.parser.expect_token(&Token::Period)?;
        let column = self.parse_identifier()?.value;

        let mut read_label = None;
        let mut update_label = None;

        while !self.is_statement_end() {
            if self.parse_keyword_seq(&["READ"]) {
                read_label = Some(self.parse_literal_string()?);
            } else if self.parse_keyword_seq(&["UPDATE"]) {
                update_label = Some(self.parse_literal_string()?);
            } else {
                break;
            }
        }

        Ok(CustomStatement::SetColumnSecurity(SetColumnSecurityStmt {
            table,
            column,
            read_label,
            update_label,
        }))
    }
}
