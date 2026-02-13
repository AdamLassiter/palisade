use sqlparser::{
    parser::{Parser, ParserError},
    tokenizer::Token,
};

use crate::{
    parser::ParserExt, plugin::CustomPlugin, rewriter::escape_sql_string, statement::{CustomStatement, SetColumnSecurityStmt}
};

pub struct SetColumnSecurityPlugin;

impl CustomPlugin for SetColumnSecurityPlugin {
    fn prefix(&self) -> &'static [&'static str] {
        &["SET", "COLUMN", "SECURITY"]
    }

    fn parse(&self, parser: &mut Parser<'_>) -> Result<CustomStatement, ParserError> {
        let table = parser.parse_identifier()?.value;
        parser.expect_token(&Token::Period)?;
        let column = parser.parse_identifier()?.value;

        let mut read_label = None;
        let mut update_label = None;

        while !parser.is_statement_end() {
            if parser.parse_keyword_seq(&["READ"]) {
                read_label = Some(parser.parse_literal_string()?);
            } else if parser.parse_keyword_seq(&["UPDATE"]) {
                update_label = Some(parser.parse_literal_string()?);
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

    fn rewrite(&self, stmt: CustomStatement) -> String {
        match stmt {
            CustomStatement::SetColumnSecurity(stmt) => {
                let escaped_table = escape_sql_string(&stmt.table);
                let escaped_column = escape_sql_string(&stmt.column);

                let mut stmts = Vec::new();

                if let Some(read_label) = stmt.read_label {
                    let escaped = escape_sql_string(&read_label);
                    stmts.push(format!(
                        r#"
                        UPDATE sec_columns
                        SET read_label_id = sec_define_label('{escaped}')
                        WHERE logical_table = '{escaped_table}'
                          AND column_name = '{escaped_column}';
                        "#
                    ));
                }

                if let Some(update_label) = stmt.update_label {
                    let escaped = escape_sql_string(&update_label);
                    stmts.push(format!(
                        r#"
                        UPDATE sec_columns
                        SET update_label_id = sec_define_label('{escaped}')
                        WHERE logical_table = '{escaped_table}'
                          AND column_name = '{escaped_column}';
                        "#
                    ));
                }

                if stmts.is_empty() {
                    "SELECT 1;".to_string()
                } else {
                    stmts.join("\n")
                }
            }
            _ => unreachable!(),
        }
    }
}
