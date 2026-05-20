pub mod ctx_stack;
pub mod sec_ctx;

use std::collections::HashMap;

use once_cell::sync::Lazy;
use parking_lot::Mutex;

use crate::context::{ctx_stack::ContextStack, sec_ctx::SecurityContext};

/// Global map: db handle address -> SecurityContext
pub static CONTEXTS: Lazy<Mutex<HashMap<usize, ContextStack>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Get or create context for a connection
pub fn get_context_stack(db_ptr: usize) -> ContextStack {
    CONTEXTS.lock().entry(db_ptr).or_default().clone()
}

pub fn set_context_stack(db_ptr: usize, ctx: ContextStack) {
    CONTEXTS.lock().insert(db_ptr, ctx);
}

pub fn effective_context(db_ptr: usize) -> SecurityContext {
    get_context_stack(db_ptr).effective().clone()
}
