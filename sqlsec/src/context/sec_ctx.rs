use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityContext {
    /// key -> set of values
    pub attrs: HashMap<String, HashSet<String>>,
}

impl SecurityContext {
    pub fn get_attrs(&self, key: &str) -> Vec<&String> {
        self.attrs
            .get(key)
            .iter()
            .flat_map(|set| set.iter())
            .collect()
    }

    pub fn set_attr(&mut self, key: &str, value: &str) {
        self.attrs
            .entry(key.to_string())
            .or_default()
            .insert(value.to_string());
    }

    pub fn clear_attr(&mut self, key: &str) {
        self.attrs.remove(key);
    }

    pub fn has(&self, key: &str, value: &str) -> bool {
        self.attrs
            .get(key)
            .map(|vals| vals.contains(value))
            .unwrap_or(false)
    }

    /// Merge another context into this one
    pub fn merge(&mut self, other: &SecurityContext) {
        for (k, v) in &other.attrs {
            self.attrs
                .entry(k.clone())
                .or_default()
                .extend(v.iter().cloned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_context_is_empty() {
        let ctx = SecurityContext::default();
        assert!(ctx.attrs.is_empty());
    }

    #[test]
    fn set_attr_inserts_value() {
        let mut ctx = SecurityContext::default();

        ctx.set_attr("role", "admin");

        assert!(ctx.has("role", "admin"));
    }

    #[test]
    fn set_attr_allows_multiple_values_for_same_key() {
        let mut ctx = SecurityContext::default();

        ctx.set_attr("role", "admin");
        ctx.set_attr("role", "user");

        assert!(ctx.has("role", "admin"));
        assert!(ctx.has("role", "user"));
    }

    #[test]
    fn set_attr_does_not_duplicate_values() {
        let mut ctx = SecurityContext::default();

        ctx.set_attr("role", "admin");
        ctx.set_attr("role", "admin"); // insert same value again

        let values = ctx.attrs.get("role").unwrap();
        assert_eq!(values.len(), 1);
    }

    #[test]
    fn clear_attr_removes_key_entirely() {
        let mut ctx = SecurityContext::default();

        ctx.set_attr("role", "admin");
        assert!(ctx.has("role", "admin"));

        ctx.clear_attr("role");

        assert!(!ctx.has("role", "admin"));
        assert!(!ctx.attrs.contains_key("role"));
    }

    #[test]
    fn has_returns_false_for_missing_key() {
        let ctx = SecurityContext::default();

        assert!(!ctx.has("missing", "value"));
    }

    #[test]
    fn merge_adds_other_context_values() {
        let mut ctx1 = SecurityContext::default();
        ctx1.set_attr("role", "admin");

        let mut ctx2 = SecurityContext::default();
        ctx2.set_attr("role", "user");
        ctx2.set_attr("team", "blue");

        ctx1.merge(&ctx2);

        // role should now contain both values
        assert!(ctx1.has("role", "admin"));
        assert!(ctx1.has("role", "user"));

        // new key should appear
        assert!(ctx1.has("team", "blue"));
    }

    #[test]
    fn merge_does_not_remove_existing_values() {
        let mut ctx1 = SecurityContext::default();
        ctx1.set_attr("role", "admin");

        let mut ctx2 = SecurityContext::default();
        ctx2.set_attr("role", "user");

        ctx1.merge(&ctx2);

        // original still present
        assert!(ctx1.has("role", "admin"));
    }

    #[test]
    fn merge_with_empty_context_changes_nothing() {
        let mut ctx1 = SecurityContext::default();
        ctx1.set_attr("role", "admin");

        let ctx2 = SecurityContext::default();

        ctx1.merge(&ctx2);

        assert!(ctx1.has("role", "admin"));
        assert_eq!(ctx1.attrs.len(), 1);
    }

    #[test]
    fn clone_and_equality_work() {
        let mut ctx1 = SecurityContext::default();
        ctx1.set_attr("role", "admin");

        let ctx2 = ctx1.clone();

        assert_eq!(ctx1, ctx2);
    }
}
