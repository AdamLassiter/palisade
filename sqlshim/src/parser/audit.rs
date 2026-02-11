use sqlparser::{dialect::keywords::Keyword, parser::ParserError};

use super::CustomParser;
use crate::statement::*;

impl CustomParser {
    pub(crate) fn parse_enable_audit(&mut self) -> Result<CustomStatement, ParserError> {
        self.parser.expect_keyword(Keyword::ON)?;
        let table = self.parse_identifier()?.value;
        let operations = if self.parser.parse_keyword(Keyword::FOR) {
            self.parse_operation_list()?
        } else {
            vec![PolicyOperation::All]
        };

        Ok(CustomStatement::EnableAudit(EnableAuditStmt {
            table,
            operations,
        }))
    }
}
