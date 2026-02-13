use sqlparser::{
    ast::Ident,
    dialect::{Dialect, GenericDialect},
    parser::{Parser, ParserError},
    tokenizer::{Token, TokenWithSpan},
};

use crate::{
    plugin::{PLUGIN_REGISTRY, PluginRegistry},
    statement::*,
};

static CUSTOM_DIALECT: CustomDialect = CustomDialect(GenericDialect {});

/// Custom dialect that recognizes our extensions
#[derive(Debug, Default)]
pub struct CustomDialect(GenericDialect);

impl Dialect for CustomDialect {
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
    registry: &'static PluginRegistry,
}

/// Format a token with its span for error messages
fn format_token_with_span(token: &TokenWithSpan) -> String {
    format!(
        "'{}' at line {}, column {}",
        token.token, token.span.start.line, token.span.start.column
    )
}

/// Create a parser error with span context
fn error_at_span(message: &str, token: &TokenWithSpan) -> ParserError {
    ParserError::ParserError(format!(
        "{} (at line {}, column {})",
        message, token.span.start.line, token.span.start.column
    ))
}

fn consume_prefix(parser: &mut Parser<'_>, words: &[&str]) -> Result<(), ParserError> {
    for word in words {
        let token = parser.next_token();
        match &token.token {
            Token::Word(w) if w.value.to_uppercase() == word.to_uppercase() => Ok(()),
            _ => Err(error_at_span(
                &format!("Expected '{}', got '{}'", word, token.token),
                &token,
            )),
        }?;
    }
    Ok(())
}

impl CustomParser {
    pub fn new(sql: &str, registry: &'static PluginRegistry) -> Result<Self, ParserError> {
        let parser = Parser::new(&CUSTOM_DIALECT).try_with_sql(sql)?;
        Ok(Self { parser, registry })
    }

    /// Parse a single statement, returning custom or standard SQL
    pub fn parse(&mut self) -> Result<Option<CustomStatement>, ParserError> {
        let Self { parser, registry } = self;
        if let Some(plugin) = registry.find_match(parser) {
            consume_prefix(parser, plugin.prefix())?;
            let stmt = plugin.parse(parser)?;
            return Ok(Some(stmt));
        }

        // Fall back to standard SQL parsing
        Ok(None)
    }

    /// Parse and rewrite a single statement
    pub fn parse_rewrite(&mut self) -> Result<String, ParserError> {
        let Self { parser, registry } = self;
        if let Some(plugin) = registry.find_match(parser) {
            consume_prefix(parser, plugin.prefix())?;
            let stmt = plugin.parse(parser)?;
            let rewritten = plugin.rewrite(stmt);
            return Ok(rewritten);
        }

        // Fall back to standard SQL parsing
        let stmt = self.parser.parse_statement()?;
        Ok(stmt.to_string())
    }
}

// --- Helper methods for parsing identifiers, literals, and keywords ---
// These are used by the individual statement parsers in their respective modules
pub trait ParserExt {
    fn parse_identifier(&mut self) -> Result<Ident, ParserError>;
    fn parse_literal_string(&mut self) -> Result<String, ParserError>;
    fn parse_literal_int(&mut self) -> Result<i64, ParserError>;
    fn expect_word(&mut self, word: &str) -> Result<(), ParserError>;
    fn parse_keyword_seq(&mut self, keywords: &[&str]) -> bool;
    fn parse_policy_operation(&mut self) -> Result<PolicyOperation, ParserError>;
    fn parse_operation_list(&mut self) -> Result<Vec<PolicyOperation>, ParserError>;
    fn parse_until_token(&mut self, end: &Token) -> Result<String, ParserError>;
    fn parse_until_statement_end(&mut self) -> Result<String, ParserError>;
    fn is_statement_end(&mut self) -> bool;
}

impl ParserExt for Parser<'_> {
    fn parse_identifier(&mut self) -> Result<Ident, ParserError> {
        self.parse_identifier()
    }

    fn parse_literal_string(&mut self) -> Result<String, ParserError> {
        self.parse_literal_string()
    }

    fn parse_literal_int(&mut self) -> Result<i64, ParserError> {
        let token = self.next_token();
        match &token.token {
            Token::Number(s, _) => s
                .parse()
                .map_err(|e| error_at_span(&format!("Invalid integer '{}': {}", s, e), &token)),
            _ => Err(error_at_span(
                &format!("Expected integer, got '{}'", token.token),
                &token,
            )),
        }
    }

    fn expect_word(&mut self, word: &str) -> Result<(), ParserError> {
        let token = self.next_token();
        match &token.token {
            Token::Word(w) if w.value.to_uppercase() == word.to_uppercase() => Ok(()),
            _ => Err(error_at_span(
                &format!("Expected '{}', got '{}'", word, token.token),
                &token,
            )),
        }
    }

    fn parse_keyword_seq(&mut self, keywords: &[&str]) -> bool {
        for kw in keywords {
            let token = self.peek_token();
            match &token.token {
                Token::Word(w) if w.value.to_uppercase() == kw.to_uppercase() => {
                    self.next_token();
                }
                _ => return false,
            }
        }
        true
    }

    fn parse_policy_operation(&mut self) -> Result<PolicyOperation, ParserError> {
        let token = self.next_token();
        match &token.token {
            Token::Word(w) => match w.value.to_uppercase().as_str() {
                "SELECT" => Ok(PolicyOperation::Select),
                "INSERT" => Ok(PolicyOperation::Insert),
                "UPDATE" => Ok(PolicyOperation::Update),
                "DELETE" => Ok(PolicyOperation::Delete),
                "ALL" => Ok(PolicyOperation::All),
                _ => Err(error_at_span(
                    &format!("Unknown operation '{}'", w.value),
                    &token,
                )),
            },
            _ => Err(error_at_span(
                &format!("Expected operation, got '{}'", token.token),
                &token,
            )),
        }
    }

    fn parse_operation_list(&mut self) -> Result<Vec<PolicyOperation>, ParserError> {
        let mut ops = vec![self.parse_policy_operation()?];
        while self.consume_token(&Token::Comma) {
            ops.push(self.parse_policy_operation()?);
        }
        Ok(ops)
    }

    fn parse_until_token(&mut self, end: &Token) -> Result<String, ParserError> {
        let mut parts = Vec::new();
        let mut depth = 0;

        loop {
            let token = self.peek_token();
            if &token.token == end && depth == 0 {
                break;
            }
            match &token.token {
                Token::LParen => depth += 1,
                Token::RParen => depth -= 1,
                Token::EOF => {
                    return Err(error_at_span(
                        &format!("Unexpected end of input, expected '{}'", end),
                        &token,
                    ));
                }
                _ => {}
            }
            parts.push(self.next_token().to_string());
        }

        Ok(parts.join(" "))
    }

    fn parse_until_statement_end(&mut self) -> Result<String, ParserError> {
        let mut parts = Vec::new();
        loop {
            let token = self.peek_token();
            match &token.token {
                Token::SemiColon | Token::EOF => break,
                _ => parts.push(self.next_token().to_string()),
            }
        }
        Ok(parts.join(" ").trim().to_string())
    }

    fn is_statement_end(&mut self) -> bool {
        matches!(self.peek_token().token, Token::SemiColon | Token::EOF)
    }
}

/// Convenience function matching original API
pub fn parse_rewrite(sql: &str) -> Option<String> {
    let mut parser = CustomParser::new(sql, &PLUGIN_REGISTRY).ok()?;
    parser.parse_rewrite().ok()
}

/// Convenience function matching original API
pub fn parse(sql: &str) -> Option<CustomStatement> {
    let mut parser = CustomParser::new(sql, &PLUGIN_REGISTRY).ok()?;
    parser.parse().ok().flatten()
}
