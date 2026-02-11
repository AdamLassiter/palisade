mod audit;
mod context;
mod label;
mod level;
mod policy;
mod security;

use sqlparser::{
    ast::{Ident, Statement},
    dialect::{Dialect, GenericDialect, keywords::Keyword},
    parser::{Parser, ParserError},
    tokenizer::Token,
};

use crate::statement::*;

static SECURE_DIALECT: SecureDialect = SecureDialect(GenericDialect {});

/// Custom dialect that recognizes our extensions
#[derive(Debug, Default)]
pub struct SecureDialect(GenericDialect);

impl Dialect for SecureDialect {
    fn is_identifier_start(&self, ch: char) -> bool {
        self.0.is_identifier_start(ch)
    }

    fn is_identifier_part(&self, ch: char) -> bool {
        self.0.is_identifier_part(ch)
    }
}

/// Wraps sqlparser's Parser for custom statement parsing
pub struct CustomParser {
    parser: Parser<'static>,
}

impl CustomParser {
    pub fn new(sql: &str) -> Result<Self, ParserError> {
        let parser = Parser::new(&SECURE_DIALECT).try_with_sql(sql)?;
        Ok(Self { parser })
    }

    /// Parse a single statement, returning custom or standard SQL
    pub fn parse_statement(&mut self) -> Result<ParsedStatement, ParserError> {
        // Peek to determine statement type
        if let Some(custom) = self.maybe_parse_custom()? {
            return Ok(ParsedStatement::Custom(custom));
        }

        // Fall back to standard SQL parsing
        let stmt = self.parser.parse_statement()?;
        Ok(ParsedStatement::Standard(Box::new(stmt)))
    }

    fn maybe_parse_custom(&mut self) -> Result<Option<CustomStatement>, ParserError> {
        let token = self.parser.peek_token();

        match &token.token {
            Token::Word(w) => match w.value.to_uppercase().as_str() {
                "CLEAR" => self.parse_clear(),
                "CREATE" => self.parse_create(),
                "DEFINE" => self.parse_define(),
                "DROP" => self.parse_drop(),
                "ENABLE" => self.parse_enable(),
                "EXPLAIN" => self.parse_explain(),
                "POP" => self.parse_pop(),
                "PUSH" => self.parse_push(),
                "REFRESH" => self.parse_refresh(),
                "REGISTER" => self.parse_register(),
                "SET" => self.parse_set(),
                _ => Ok(None),
            },
            _ => Ok(None),
        }
    }

    fn parse_define(&mut self) -> Result<Option<CustomStatement>, ParserError> {
        self.parser.expect_keyword(Keyword::DEFINE)?;

        if self.parse_keyword_seq(&["LABEL"]) {
            return self.parse_define_label().map(Some);
        }

        if self.parse_keyword_seq(&["LEVEL"]) {
            return self.parse_define_level().map(Some);
        }

        Err(ParserError::ParserError(
            "Expected LABEL or LEVEL after DEFINE".into(),
        ))
    }

    fn parse_set(&mut self) -> Result<Option<CustomStatement>, ParserError> {
        // Peek ahead without consuming
        let tokens = self.parser.peek_tokens_ref::<3>();

        if matches!(&tokens[1].token, Token::Word(w) if w.value.to_uppercase() == "CONTEXT") {
            self.parser.expect_keyword(Keyword::SET)?;
            self.expect_word("CONTEXT")?;
            return self.parse_set_context().map(Some);
        }

        if matches!(&tokens[1].token, Token::Word(w) if w.value.to_uppercase() == "COLUMN") {
            self.parser.expect_keyword(Keyword::SET)?;
            self.expect_word("COLUMN")?;
            self.expect_word("SECURITY")?;
            return self.parse_set_column_security().map(Some);
        }

        Ok(None) // Let standard parser handle regular SET
    }

    fn parse_clear(&mut self) -> Result<Option<CustomStatement>, ParserError> {
        self.expect_word("CLEAR")?;

        self.parse_clear_context().map(Some)
    }

    fn parse_push(&mut self) -> Result<Option<CustomStatement>, ParserError> {
        self.expect_word("PUSH")?;

        self.parse_push_context().map(Some)
    }

    fn parse_pop(&mut self) -> Result<Option<CustomStatement>, ParserError> {
        self.expect_word("POP")?;

        self.parse_pop_context().map(Some)
    }

    fn parse_refresh(&mut self) -> Result<Option<CustomStatement>, ParserError> {
        self.expect_word("REFRESH")?;
        self.expect_word("SECURE")?;
        self.expect_word("VIEWS")?;

        Ok(Some(CustomStatement::RefreshSecureViews))
    }

    fn parse_register(&mut self) -> Result<Option<CustomStatement>, ParserError> {
        self.expect_word("REGISTER")?;
        self.expect_word("SECURE")?;
        self.parser.expect_keyword(Keyword::TABLE)?;

        self.parse_register_secure_table().map(Some)
    }

    fn parse_create(&mut self) -> Result<Option<CustomStatement>, ParserError> {
        let tokens = self.parser.peek_tokens_ref::<3>();

        if matches!(&tokens[1].token, Token::Word(w) if w.value.to_uppercase() == "POLICY") {
            self.parser.expect_keyword(Keyword::CREATE)?;
            self.expect_word("POLICY")?;
            return self.parse_create_policy().map(Some);
        }

        if matches!(&tokens[1].token, Token::Word(w) if w.value.to_uppercase() == "SECURE")
            && matches!(&tokens[2].token, Token::Word(w) if w.value.to_uppercase() == "VIEW")
        {
            self.parser.expect_keyword(Keyword::CREATE)?;
            self.expect_word("SECURE")?;
            self.expect_word("VIEW")?;
            return self.parse_create_secure_view().map(Some);
        }

        Ok(None) // Let standard parser handle regular CREATE
    }

    fn parse_drop(&mut self) -> Result<Option<CustomStatement>, ParserError> {
        let tokens = self.parser.peek_tokens_ref::<2>();

        if matches!(&tokens[1].token, Token::Word(w) if w.value.to_uppercase() == "POLICY") {
            self.parser.expect_keyword(Keyword::DROP)?;
            self.expect_word("POLICY")?;
            return self.parse_drop_policy().map(Some);
        }

        Ok(None)
    }

    fn parse_enable(&mut self) -> Result<Option<CustomStatement>, ParserError> {
        self.expect_word("ENABLE")?;
        self.expect_word("AUDIT")?;

        self.parse_enable_audit().map(Some)
    }

    fn parse_explain(&mut self) -> Result<Option<CustomStatement>, ParserError> {
        self.parser.expect_keyword(Keyword::EXPLAIN)?;
        self.expect_word("POLICY")?;

        self.parse_explain_policy().map(Some)
    }

    // --- Helper methods for parsing identifiers, literals, and keywords ---
    // These are used by the individual statement parsers in their respective modules

    fn parse_identifier(&mut self) -> Result<Ident, ParserError> {
        self.parser.parse_identifier()
    }

    fn parse_literal_string(&mut self) -> Result<String, ParserError> {
        self.parser.parse_literal_string()
    }

    fn parse_literal_int(&mut self) -> Result<i64, ParserError> {
        let token = self.parser.next_token();
        match token.token {
            Token::Number(s, _) => s
                .parse()
                .map_err(|e| ParserError::ParserError(format!("Invalid integer: {e}"))),
            _ => Err(ParserError::ParserError(format!(
                "Expected integer, got {token}"
            ))),
        }
    }

    fn expect_word(&mut self, word: &str) -> Result<(), ParserError> {
        let token = self.parser.next_token();
        match &token.token {
            Token::Word(w) if w.value.to_uppercase() == word.to_uppercase() => Ok(()),
            _ => Err(ParserError::ParserError(format!(
                "Expected {word}, got {token}"
            ))),
        }
    }

    fn parse_keyword_seq(&mut self, keywords: &[&str]) -> bool {
        for kw in keywords {
            let token = self.parser.peek_token();
            match &token.token {
                Token::Word(w) if w.value.to_uppercase() == kw.to_uppercase() => {
                    self.parser.next_token();
                }
                _ => return false,
            }
        }
        true
    }

    fn parse_policy_operation(&mut self) -> Result<PolicyOperation, ParserError> {
        let token = self.parser.next_token();
        match &token.token {
            Token::Word(w) => match w.value.to_uppercase().as_str() {
                "SELECT" => Ok(PolicyOperation::Select),
                "INSERT" => Ok(PolicyOperation::Insert),
                "UPDATE" => Ok(PolicyOperation::Update),
                "DELETE" => Ok(PolicyOperation::Delete),
                "ALL" => Ok(PolicyOperation::All),
                _ => Err(ParserError::ParserError(format!(
                    "Unknown operation: {}",
                    w.value
                ))),
            },
            _ => Err(ParserError::ParserError("Expected operation".into())),
        }
    }

    fn parse_operation_list(&mut self) -> Result<Vec<PolicyOperation>, ParserError> {
        let mut ops = vec![self.parse_policy_operation()?];
        while self.parser.consume_token(&Token::Comma) {
            ops.push(self.parse_policy_operation()?);
        }
        Ok(ops)
    }

    fn parse_until_token(&mut self, end: &Token) -> Result<String, ParserError> {
        let mut parts = Vec::new();
        let mut depth = 0;

        loop {
            let token = self.parser.peek_token();
            if &token.token == end && depth == 0 {
                break;
            }
            match &token.token {
                Token::LParen => depth += 1,
                Token::RParen => depth -= 1,
                Token::EOF => {
                    return Err(ParserError::ParserError(format!("Expected {end}")));
                }
                _ => {}
            }
            parts.push(self.parser.next_token().to_string());
        }

        Ok(parts.join(" "))
    }

    fn parse_until_statement_end(&mut self) -> Result<String, ParserError> {
        let mut parts = Vec::new();
        loop {
            let token = self.parser.peek_token();
            match &token.token {
                Token::SemiColon | Token::EOF => break,
                _ => parts.push(self.parser.next_token().to_string()),
            }
        }
        Ok(parts.join(" ").trim().to_string())
    }

    fn is_statement_end(&mut self) -> bool {
        matches!(
            self.parser.peek_token().token,
            Token::SemiColon | Token::EOF
        )
    }
}

/// Result of parsing: either a custom statement or standard SQL
#[derive(Debug)]
pub enum ParsedStatement {
    Custom(CustomStatement),
    Standard(Box<Statement>),
}

/// Convenience function matching original API
pub fn parse(sql: &str) -> Option<CustomStatement> {
    let mut parser = CustomParser::new(sql).ok()?;
    match parser.parse_statement().ok()? {
        ParsedStatement::Custom(c) => Some(c),
        ParsedStatement::Standard(_) => None,
    }
}

/// Parse and return both custom and standard statements
pub fn parse_full(sql: &str) -> Result<ParsedStatement, ParserError> {
    let mut parser = CustomParser::new(sql)?;
    parser.parse_statement()
}
