use crate::context::sec_ctx::SecurityContext;

#[derive(Debug, Clone)]
pub struct ContextStack {
    stack: Vec<(Option<String>, SecurityContext)>, // (optional name, context)
}

impl Default for ContextStack {
    fn default() -> Self {
        Self {
            stack: vec![(None, SecurityContext::default())],
        } // start with base context
    }
}

impl ContextStack {
    pub fn current(&self) -> &SecurityContext {
        &self.stack.last().unwrap().1
    }

    pub fn current_mut(&mut self) -> &mut SecurityContext {
        &mut self.stack.last_mut().unwrap().1
    }

    pub fn push(&mut self, name: Option<String>) {
        let new_ctx = self.current().clone();
        self.stack.push((name, new_ctx));
    }

    pub fn pop(&mut self) -> Option<(Option<String>, SecurityContext)> {
        if self.stack.len() > 1 {
            self.stack.pop()
        } else {
            None // never pop the base context
        }
    }

    pub fn push_named(&mut self, name: &str) {
        self.push(Some(name.to_string()));
    }

    pub fn pop_named(&mut self, name: &str) -> Option<SecurityContext> {
        if let Some(pos) = self
            .stack
            .iter()
            .rposition(|(n, _)| n.as_deref() == Some(name))
        {
            Some(self.stack.remove(pos).1)
        } else {
            None
        }
    }

    /// Context used for access checks
    pub fn effective(&self) -> &SecurityContext {
        &self.stack.last().unwrap().1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_stack_has_base_context() {
        let stack = ContextStack::default();

        // Should always start with exactly one base context
        assert_eq!(stack.stack.len(), 1);

        // Base context name should be None
        assert!(stack.stack[0].0.is_none());
    }

    #[test]
    fn push_adds_new_context_layer() {
        let mut stack = ContextStack::default();

        stack.push(None);

        // Now should have 2 contexts
        assert_eq!(stack.stack.len(), 2);

        // Top context should have no name
        assert!(stack.stack.last().unwrap().0.is_none());
    }

    #[test]
    fn push_clones_current_context() {
        let mut stack = ContextStack::default();

        let before = stack.current().clone();
        stack.push(None);

        let after = stack.current();

        // New context should be identical to previous
        assert_eq!(&before, after);
    }

    #[test]
    fn pop_removes_top_context_but_not_base() {
        let mut stack = ContextStack::default();

        stack.push(None);
        assert_eq!(stack.stack.len(), 2);

        let popped = stack.pop();
        assert!(popped.is_some());
        assert_eq!(stack.stack.len(), 1);

        // Base context cannot be popped
        let popped_again = stack.pop();
        assert!(popped_again.is_none());
        assert_eq!(stack.stack.len(), 1);
    }

    #[test]
    fn push_named_sets_name_correctly() {
        let mut stack = ContextStack::default();

        stack.push_named("admin");

        assert_eq!(stack.stack.len(), 2);
        assert_eq!(stack.stack.last().unwrap().0.as_deref(), Some("admin"));
    }

    #[test]
    fn pop_named_removes_correct_context() {
        let mut stack = ContextStack::default();

        stack.push_named("first");
        stack.push_named("second");
        stack.push_named("third");

        assert_eq!(stack.stack.len(), 4);

        // Remove "second" from the middle
        let removed = stack.pop_named("second");
        assert!(removed.is_some());

        // Stack should shrink
        assert_eq!(stack.stack.len(), 3);

        // Ensure "second" no longer exists
        assert!(stack.pop_named("second").is_none());

        // Ensure top is still "third"
        assert_eq!(stack.stack.last().unwrap().0.as_deref(), Some("third"));
    }

    #[test]
    fn pop_named_returns_none_if_not_found() {
        let mut stack = ContextStack::default();

        stack.push_named("exists");

        let result = stack.pop_named("missing");
        assert!(result.is_none());
    }

    #[test]
    fn effective_is_same_as_current() {
        let mut stack = ContextStack::default();

        stack.push_named("layer1");

        assert_eq!(stack.effective(), stack.current());
    }
}
