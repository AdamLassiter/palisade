mod clear_context;
mod create_policy;
mod create_secure_view;
mod define_label;
mod define_level;
mod drop_policy;
mod enable_audit;
mod explain_policy;
mod pop_context;
mod push_context;
mod refresh_secure_views;
mod register_secure_table;
mod set_column_security;
mod set_context;

use std::sync::LazyLock;

use sqlparser::{
    parser::{Parser, ParserError},
    tokenizer::Token,
};

use crate::statement::CustomStatement;

pub static PLUGIN_REGISTRY: LazyLock<PluginRegistry> = LazyLock::new(|| PluginRegistry {
    #[cfg(feature = "default_plugins")]
    plugins: vec![
        Box::new(clear_context::ClearContextPlugin),
        Box::new(create_policy::CreatePolicyPlugin),
        Box::new(create_secure_view::CreateSecureViewPlugin),
        Box::new(define_label::DefineLabelPlugin),
        Box::new(define_level::DefineLevelPlugin),
        Box::new(drop_policy::DropPolicyPlugin),
        Box::new(enable_audit::EnableAuditPlugin),
        Box::new(pop_context::PopContextPlugin),
        Box::new(push_context::PushContextPlugin),
        Box::new(refresh_secure_views::RefreshSecureViewsPlugin),
        Box::new(register_secure_table::RegisterSecureTablePlugin),
        Box::new(set_column_security::SetColumnSecurityPlugin),
        Box::new(set_context::SetContextPlugin),
    ],
    #[cfg(not(feature = "default_plugins"))]
    plugins: vec![],
});

pub struct PluginRegistry {
    plugins: Vec<Box<dyn CustomPlugin + Send + Sync + 'static>>,
}
impl PluginRegistry {
    pub fn register(&mut self, plugin: impl CustomPlugin + Send + Sync + 'static) {
        self.plugins.push(Box::new(plugin));
    }

    pub fn find_match<'r, 'p>(
        &'r self,
        parser: &'p mut Parser<'_>,
    ) -> Option<&'r (dyn CustomPlugin + Send + Sync + 'static)> {
        self.plugins
            .iter()
            .filter(|p| peek_prefix(parser, p.prefix()))
            .max_by_key(|p| p.prefix().len())
            .map(|v| &**v)
    }
}

fn peek_prefix(parser: &Parser<'_>, prefix_tokens: &[&str]) -> bool {
    for (i, t) in prefix_tokens.iter().enumerate() {
        let next_token = &parser.peek_nth_token_ref(i).token;
        if !matches!(&next_token, Token::Word(tok) if tok.value.to_uppercase() == t.to_uppercase())
        {
            return false;
        }
    }
    true
}

pub trait CustomPlugin {
    /// The keyword sequence that triggers this plugin
    fn prefix(&self) -> &'static [&'static str];

    /// Parse after prefix has been consumed
    fn parse(&self, parser: &mut Parser<'_>) -> Result<CustomStatement, ParserError>;

    /// Rewrite into SQL
    fn rewrite(&self, stmt: CustomStatement) -> String;
}
