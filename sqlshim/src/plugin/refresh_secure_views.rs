use sqlparser::parser::{Parser, ParserError};

use crate::{plugin::CustomPlugin, statement::CustomStatement};

pub struct RefreshSecureViewsPlugin;

impl CustomPlugin for RefreshSecureViewsPlugin {
    fn prefix(&self) -> &'static [&'static str] {
        &["REFRESH", "SECURE", "VIEWS"]
    }

    fn parse(&self, _parser: &mut Parser<'_>) -> Result<CustomStatement, ParserError> {
        Ok(CustomStatement::RefreshSecureViews)
    }

    fn rewrite(&self, stmt: CustomStatement) -> String {
        match stmt {
            CustomStatement::RefreshSecureViews => "SELECT sec_refresh_views();".to_string(),
            _ => unreachable!(),
        }
    }
}
