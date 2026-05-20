use std::ffi::{CStr, CString, c_char, c_int};

use rusqlite::ffi::{
    SQLITE_NULL,
    SQLITE_TRANSIENT,
    SQLITE_UTF8,
    sqlite3,
    sqlite3_context,
    sqlite3_context_db_handle,
    sqlite3_create_function_v2,
    sqlite3_result_int64,
    sqlite3_result_text,
    sqlite3_value,
    sqlite3_value_int64,
    sqlite3_value_text,
    sqlite3_value_type,
};

use crate::{
    audit::{audit_context_raw, audit_event_raw, configure_audit_raw, set_audit_enabled_raw},
    register::{Sqlite3FunctionV2, sqlite_error},
};

pub struct AuditContext;
pub struct AuditEvent;
pub struct AuditEnable;
pub struct AuditDisable;
pub struct AuditConfigure;

impl Sqlite3FunctionV2 for AuditContext {
    fn register(db: *mut sqlite3) {
        unsafe {
            sqlite3_create_function_v2(
                db,
                c"sec_audit_context".as_ptr(),
                0,
                SQLITE_UTF8,
                std::ptr::null_mut(),
                Some(ffi_sec_audit_context),
                None,
                None,
                None,
            );
        }
    }
}

impl Sqlite3FunctionV2 for AuditEvent {
    fn register(db: *mut sqlite3) {
        unsafe {
            sqlite3_create_function_v2(
                db,
                c"sec_audit_event".as_ptr(),
                8,
                SQLITE_UTF8,
                std::ptr::null_mut(),
                Some(ffi_sec_audit_event),
                None,
                None,
                None,
            );
        }
    }
}

impl Sqlite3FunctionV2 for AuditEnable {
    fn register(db: *mut sqlite3) {
        unsafe {
            sqlite3_create_function_v2(
                db,
                c"sec_audit_enable".as_ptr(),
                1,
                SQLITE_UTF8,
                std::ptr::null_mut(),
                Some(ffi_sec_audit_enable),
                None,
                None,
                None,
            );
        }
    }
}

impl Sqlite3FunctionV2 for AuditDisable {
    fn register(db: *mut sqlite3) {
        unsafe {
            sqlite3_create_function_v2(
                db,
                c"sec_audit_disable".as_ptr(),
                1,
                SQLITE_UTF8,
                std::ptr::null_mut(),
                Some(ffi_sec_audit_disable),
                None,
                None,
                None,
            );
        }
    }
}

impl Sqlite3FunctionV2 for AuditConfigure {
    fn register(db: *mut sqlite3) {
        unsafe {
            sqlite3_create_function_v2(
                db,
                c"sec_audit_configure".as_ptr(),
                3,
                SQLITE_UTF8,
                std::ptr::null_mut(),
                Some(ffi_sec_audit_configure),
                None,
                None,
                None,
            );
        }
    }
}

pub(crate) extern "C" fn ffi_sec_audit_context(
    ctx: *mut sqlite3_context,
    argc: c_int,
    _argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if argc != 0 {
            sqlite_error(ctx, "audit_context", "expected 0 arguments");
            return;
        }

        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        sqlite_text(ctx, &audit_context_raw(db_ptr));
    }
}

pub(crate) extern "C" fn ffi_sec_audit_event(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if argc != 8 {
            sqlite_error(ctx, "audit_event", "expected 8 arguments");
            return;
        }

        let logical = match required_text(ctx, argv, 0, "logical_table") {
            Some(v) => v,
            None => return,
        };
        let physical = match required_text(ctx, argv, 1, "physical_table") {
            Some(v) => v,
            None => return,
        };
        let operation = match required_text(ctx, argv, 2, "operation") {
            Some(v) => v,
            None => return,
        };
        let outcome = match required_text(ctx, argv, 3, "outcome") {
            Some(v) => v,
            None => return,
        };
        let row_pk_json = optional_text(argv, 4);
        let changed_columns_json = optional_text(argv, 5);
        let row_label_id = optional_i64(argv, 6);
        let error = optional_text(argv, 7);

        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        match audit_event_raw(
            db_ptr,
            &logical,
            &physical,
            &operation,
            &outcome,
            row_pk_json.as_deref(),
            changed_columns_json.as_deref(),
            row_label_id,
            error.as_deref(),
        ) {
            Ok(v) => sqlite3_result_int64(ctx, v),
            Err(e) => sqlite_error(ctx, "audit_event", e),
        }
    }
}

pub(crate) extern "C" fn ffi_sec_audit_enable(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    set_enabled(ctx, argc, argv, true);
}

pub(crate) extern "C" fn ffi_sec_audit_disable(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    set_enabled(ctx, argc, argv, false);
}

pub(crate) extern "C" fn ffi_sec_audit_configure(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if argc != 3 {
            sqlite_error(ctx, "audit_configure", "expected 3 arguments");
            return;
        }
        let logical = match required_text(ctx, argv, 0, "logical_table") {
            Some(v) => v,
            None => return,
        };
        let key = match required_text(ctx, argv, 1, "key") {
            Some(v) => v,
            None => return,
        };
        if sqlite3_value_type(*argv.add(2)) == SQLITE_NULL {
            sqlite_error(ctx, "audit_configure", "NULL argument 3 'value'");
            return;
        }
        let value = sqlite3_value_int64(*argv.add(2));

        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        match configure_audit_raw(db_ptr, &logical, &key, value) {
            Ok(v) => sqlite3_result_int64(ctx, v),
            Err(e) => sqlite_error(ctx, "audit_configure", e),
        }
    }
}

fn set_enabled(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
    enabled: bool,
) {
    unsafe {
        if argc != 1 {
            sqlite_error(ctx, "audit_enable", "expected 1 argument");
            return;
        }
        let logical = match required_text(ctx, argv, 0, "logical_table") {
            Some(v) => v,
            None => return,
        };
        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        match set_audit_enabled_raw(db_ptr, &logical, enabled) {
            Ok(v) => sqlite3_result_int64(ctx, v),
            Err(e) => sqlite_error(ctx, "audit_enable", e),
        }
    }
}

unsafe fn required_text(
    ctx: *mut sqlite3_context,
    argv: *mut *mut sqlite3_value,
    idx: usize,
    name: &str,
) -> Option<String> {
    let value = unsafe { sqlite3_value_text(*argv.add(idx)) };
    if value.is_null() {
        sqlite_error(ctx, "audit", format!("NULL argument {} '{name}'", idx + 1));
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(value as *const c_char) }
            .to_string_lossy()
            .into_owned(),
    )
}

unsafe fn optional_text(argv: *mut *mut sqlite3_value, idx: usize) -> Option<String> {
    if unsafe { sqlite3_value_type(*argv.add(idx)) } == SQLITE_NULL {
        return None;
    }
    let value = unsafe { sqlite3_value_text(*argv.add(idx)) };
    if value.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(value as *const c_char) }
            .to_string_lossy()
            .into_owned(),
    )
}

unsafe fn optional_i64(argv: *mut *mut sqlite3_value, idx: usize) -> Option<i64> {
    if unsafe { sqlite3_value_type(*argv.add(idx)) } == SQLITE_NULL {
        None
    } else {
        Some(unsafe { sqlite3_value_int64(*argv.add(idx)) })
    }
}

fn sqlite_text(ctx: *mut sqlite3_context, value: &str) {
    let msg = CString::new(value).unwrap_or_else(|_| CString::new("").unwrap());
    unsafe {
        sqlite3_result_text(ctx, msg.as_ptr(), -1, SQLITE_TRANSIENT());
    }
}
