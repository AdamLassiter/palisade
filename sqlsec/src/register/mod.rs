pub mod assert_fresh;
pub mod audit;
pub mod clear_context;
pub mod define_label;
pub mod define_level;
pub mod label_visible;
pub mod pop_context;
pub mod push_context;
pub mod refresh_views;
pub mod register_table;
pub mod set_attr;

use std::{ffi::CString, fmt::Display};

use rusqlite::ffi::{sqlite3, sqlite3_context, sqlite3_result_error};

use crate::register::{
    assert_fresh::AssertFresh,
    audit::{AuditConfigure, AuditContext, AuditDisable, AuditEnable, AuditEvent},
    clear_context::ClearContext,
    define_label::DefineLabel,
    define_level::DefineLevel,
    label_visible::LabelVisible,
    pop_context::PopContext,
    push_context::PushContext,
    refresh_views::RefreshViews,
    register_table::RegisterTable,
    set_attr::SetAttr,
};

fn sqlite_error(ctx: *mut sqlite3_context, prefix: &str, e: impl Display) {
    let msg = CString::new(format!("{prefix}: {e}")).unwrap();
    unsafe {
        sqlite3_result_error(ctx, msg.as_ptr(), -1);
    }
}

trait Sqlite3FunctionV2 {
    fn register(db: *mut sqlite3);
}

/// Register all scalar functions using raw FFI
pub(crate) fn register_functions_ffi(db: *mut sqlite3) {
    AssertFresh::register(db);
    AuditConfigure::register(db);
    AuditContext::register(db);
    AuditDisable::register(db);
    AuditEnable::register(db);
    AuditEvent::register(db);
    ClearContext::register(db);
    DefineLabel::register(db);
    DefineLevel::register(db);
    PopContext::register(db);
    PushContext::register(db);
    RefreshViews::register(db);
    RegisterTable::register(db);
    LabelVisible::register(db);
    SetAttr::register(db);
}
