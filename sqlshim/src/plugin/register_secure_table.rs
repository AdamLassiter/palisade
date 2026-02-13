use sqlparser::{
    keywords::Keyword,
    parser::{Parser, ParserError},
};

use crate::{
    parser::ParserExt,
    plugin::CustomPlugin,
    rewriter::escape_sql_string,
    statement::{CustomStatement, RegisterSecureTableStmt},
};

pub struct RegisterSecureTablePlugin;

impl CustomPlugin for RegisterSecureTablePlugin {
    fn prefix(&self) -> &'static [&'static str] {
        &["REGISTER", "SECURE", "TABLE"]
    }

    fn parse(&self, parser: &mut Parser<'_>) -> Result<CustomStatement, ParserError> {
        let logical_name = parser.parse_identifier()?.value;

        parser.expect_keyword(Keyword::ON)?;
        let physical_name = parser.parse_identifier()?.value;

        parser.expect_keyword(Keyword::WITH)?;
        parser.expect_word("ROW")?;
        parser.expect_word("LABEL")?;

        let row_label_column = parser.parse_identifier()?.value;

        let mut table_label = None;
        let mut insert_label = None;

        while !parser.is_statement_end() {
            if parser.parse_keyword_seq(&["TABLE", "LABEL"]) {
                table_label = Some(parser.parse_literal_string()?);
            } else if parser.parse_keyword_seq(&["INSERT", "LABEL"]) {
                insert_label = Some(parser.parse_literal_string()?);
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

    fn rewrite(&self, stmt: CustomStatement) -> String {
        match stmt {
            CustomStatement::RegisterSecureTable(stmt) => {
                let escaped_logical = escape_sql_string(&stmt.logical_name);
                let escaped_physical = escape_sql_string(&stmt.physical_name);
                let escaped_row_col = escape_sql_string(&stmt.row_label_column);

                let table_label = stmt
                    .table_label
                    .map(|l| format!("sec_define_label('{}')", escape_sql_string(&l)))
                    .unwrap_or_else(|| "NULL".to_string());

                let insert_label = stmt
                    .insert_label
                    .map(|l| format!("sec_define_label('{}')", escape_sql_string(&l)))
                    .unwrap_or_else(|| "NULL".to_string());

                format!(
                    "SELECT sec_register_table('{escaped_logical}', '{escaped_physical}', '{escaped_row_col}', {table_label}, {insert_label});"
                )
            }
            _ => unreachable!(),
        }
    }
}
