use std::{
    ffi::{CStr, CString, c_char, c_int},
    fmt::Display,
};

use rusqlite::ffi::{
    SQLITE_NULL,
    SQLITE_UTF8,
    sqlite3,
    sqlite3_context,
    sqlite3_context_db_handle,
    sqlite3_create_function_v2,
    sqlite3_result_error,
    sqlite3_result_int,
    sqlite3_result_int64,
    sqlite3_value,
    sqlite3_value_int64,
    sqlite3_value_text,
    sqlite3_value_type,
};

use crate::{context, get_context_stack, label, set_context_stack, views};

fn sqlite_error(ctx: *mut sqlite3_context, prefix: &str, e: impl Display) {
    let msg = CString::new(format!("{prefix}: {e}")).unwrap();
    unsafe {
        sqlite3_result_error(ctx, msg.as_ptr(), -1);
    }
}

/// Register all scalar functions using raw FFI
pub(crate) fn register_functions_ffi(db: *mut sqlite3) {
    unsafe {
        // sec_set_attr(key, value)
        sqlite3_create_function_v2(
            db,
            c"sec_set_attr".as_ptr(),
            2,
            SQLITE_UTF8,
            std::ptr::null_mut(),
            Some(ffi_sec_set_attr),
            None,
            None,
            None,
        );

        // sec_clear_context()
        sqlite3_create_function_v2(
            db,
            c"sec_clear_context".as_ptr(),
            0,
            SQLITE_UTF8,
            std::ptr::null_mut(),
            Some(ffi_sec_clear_context),
            None,
            None,
            None,
        );

        // sec_push_context(key, value)
        sqlite3_create_function_v2(
            db,
            c"sec_push_context".as_ptr(),
            -1,
            SQLITE_UTF8,
            std::ptr::null_mut(),
            Some(ffi_sec_push_context),
            None,
            None,
            None,
        );

        // sec_pop_context()
        sqlite3_create_function_v2(
            db,
            c"sec_pop_context".as_ptr(),
            0,
            SQLITE_UTF8,
            std::ptr::null_mut(),
            Some(ffi_sec_pop_context),
            None,
            None,
            None,
        );

        // sec_define_label(expr)
        sqlite3_create_function_v2(
            db,
            c"sec_define_label".as_ptr(),
            1,
            SQLITE_UTF8,
            std::ptr::null_mut(),
            Some(ffi_sec_define_label),
            None,
            None,
            None,
        );

        // sec_row_visible(label_id)
        sqlite3_create_function_v2(
            db,
            c"sec_row_visible".as_ptr(),
            1,
            SQLITE_UTF8,
            std::ptr::null_mut(),
            Some(ffi_sec_row_visible),
            None,
            None,
            None,
        );

        // sec_refresh_views()
        sqlite3_create_function_v2(
            db,
            c"sec_refresh_views".as_ptr(),
            0,
            SQLITE_UTF8,
            std::ptr::null_mut(),
            Some(ffi_sec_refresh_views),
            None,
            None,
            None,
        );

        // sec_register_table(logical, physical, row_label_col, table_label_id)
        sqlite3_create_function_v2(
            db,
            c"sec_register_table".as_ptr(),
            5,
            SQLITE_UTF8,
            std::ptr::null_mut(),
            Some(ffi_sec_register_table),
            None,
            None,
            None,
        );
    }
}

pub(crate) extern "C" fn ffi_sec_set_attr(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if argc != 2 {
            sqlite_error(ctx, "set_attr", "expected 2 arguments");
            return;
        }

        let key = sqlite3_value_text(*argv);
        let val = sqlite3_value_text(*argv.add(1));

        if key.is_null() || val.is_null() {
            sqlite_error(ctx, "set_attr", "NULL argument 1 'key'");
            return;
        }
        if key.is_null() || val.is_null() {
            sqlite_error(ctx, "set_attr", "NULL argument 2 'value'");
            return;
        }

        let key = CStr::from_ptr(key as *const c_char).to_string_lossy();
        let val = CStr::from_ptr(val as *const c_char).to_string_lossy();

        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        let mut stack = get_context_stack(db_ptr);
        stack.current_mut().set_attr(&key, &val);
        set_context_stack(db_ptr, stack);

        match views::bump_generation_raw(db_ptr) {
            Ok(_) => sqlite3_result_int64(ctx, 1),
            Err(e) => {
                sqlite_error(ctx, "set_attr", e);
            }
        }
    }
}

pub(crate) extern "C" fn ffi_sec_clear_context(
    ctx: *mut sqlite3_context,
    _argc: c_int,
    _argv: *mut *mut sqlite3_value,
) {
    unsafe {
        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        set_context_stack(db_ptr, context::ContextStack::default());

        match views::bump_generation_raw(db_ptr) {
            Ok(_) => sqlite3_result_int64(ctx, 1),
            Err(e) => {
                sqlite_error(ctx, "clear_context", e);
            }
        }
    }
}

pub(crate) extern "C" fn ffi_sec_push_context(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        let mut stack = get_context_stack(db_ptr);

        let name = if argc == 1 {
            let name_ptr = sqlite3_value_text(*argv);
            if !name_ptr.is_null() {
                Some(
                    CStr::from_ptr(name_ptr as *const c_char)
                        .to_string_lossy()
                        .to_string(),
                )
            } else {
                None
            }
        } else {
            None
        };

        stack.push(name);
        set_context_stack(db_ptr, stack);

        match views::bump_generation_raw(db_ptr) {
            Ok(_) => sqlite3_result_int64(ctx, 1),
            Err(e) => {
                sqlite_error(ctx, "push_context", e);
            }
        }
    }
}

pub(crate) extern "C" fn ffi_sec_pop_context(
    ctx: *mut sqlite3_context,
    _argc: c_int,
    _argv: *mut *mut sqlite3_value,
) {
    unsafe {
        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        let mut stack = get_context_stack(db_ptr);

        if stack.pop().is_none() {
            sqlite_error(ctx, "pop_context", "cannot pop base context");
            return;
        }
        set_context_stack(db_ptr, stack);

        match views::bump_generation_raw(db_ptr) {
            Ok(_) => sqlite3_result_int64(ctx, 1),
            Err(e) => {
                sqlite_error(ctx, "pop_context", e);
            }
        }
    }
}

pub(crate) extern "C" fn ffi_sec_define_label(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if argc != 1 {
            sqlite_error(ctx, "define_label", "expected 1 argument");
            return;
        }

        let expr_ptr = sqlite3_value_text(*argv);
        if expr_ptr.is_null() {
            sqlite_error(ctx, "define_label", "NULL argument 1 'expr'");
            return;
        }

        let expr = CStr::from_ptr(expr_ptr as *const c_char).to_string_lossy();

        // Validate parse
        if label::parse(&expr).is_err() {
            sqlite_error(ctx, "define_label", "invalid label expression");
            return;
        }

        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        match label::define_label_raw(db_ptr, &expr) {
            Ok(id) => sqlite3_result_int64(ctx, id),
            Err(e) => {
                sqlite_error(ctx, "define_label", e);
            }
        }
    }
}

pub(crate) extern "C" fn ffi_sec_row_visible(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if argc != 1 {
            sqlite_error(ctx, "row_visible", "expected 1 argument");
            return;
        }

        let db_ptr = sqlite3_context_db_handle(ctx) as usize;

        let label_id = if sqlite3_value_type(*argv) == SQLITE_NULL {
            None
        } else {
            Some(sqlite3_value_int64(*argv))
        };

        let visible = match label_id {
            None => true,
            Some(id) => {
                let sec_ctx = context::effective_context(db_ptr);
                match label::evaluate_by_id(db_ptr, id, &sec_ctx) {
                    Ok(res) => res,
                    Err(e) => {
                        sqlite_error(ctx, "row_visible", e);
                        return;
                    }
                }
            }
        };

        sqlite3_result_int(ctx, if visible { 1 } else { 0 });
    }
}

pub(crate) extern "C" fn ffi_sec_refresh_views(
    ctx: *mut sqlite3_context,
    _argc: c_int,
    _argv: *mut *mut sqlite3_value,
) {
    unsafe {
        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        match views::refresh_views_raw(db_ptr) {
            Ok(_) => sqlite3_result_int(ctx, 1),
            Err(e) => {
                sqlite_error(ctx, "refresh_views", e);
            }
        }
    }
}

pub(crate) extern "C" fn ffi_sec_register_table(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if argc != 5 {
            sqlite_error(ctx, "register_table", "expected 5 arguments");
            return;
        }

        let logical_ptr = sqlite3_value_text(*argv);
        let physical_ptr = sqlite3_value_text(*argv.add(1));
        let row_col_ptr = sqlite3_value_text(*argv.add(2));

        let table_label_id = if sqlite3_value_type(*argv.add(3)) == SQLITE_NULL {
            None
        } else {
            Some(sqlite3_value_int64(*argv.add(3)))
        };
        let insert_label_id = if sqlite3_value_type(*argv.add(4)) == SQLITE_NULL {
            None
        } else {
            Some(sqlite3_value_int64(*argv.add(4)))
        };

        if logical_ptr.is_null() {
            sqlite_error(ctx, "register_table", "NULL argument 1 'logical'");
            return;
        }
        if physical_ptr.is_null() {
            sqlite_error(ctx, "register_table", "NULL argument 2 ''physical'");
            return;
        }
        if row_col_ptr.is_null() {
            sqlite_error(ctx, "register_table", "NULL argument 3 'row_label_col'");
            return;
        }

        let logical = CStr::from_ptr(logical_ptr as *const c_char).to_string_lossy();
        let physical = CStr::from_ptr(physical_ptr as *const c_char).to_string_lossy();
        let row_col = CStr::from_ptr(row_col_ptr as *const c_char).to_string_lossy();

        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        match views::register_table_raw(
            db_ptr,
            &logical,
            &physical,
            &row_col,
            table_label_id,
            insert_label_id,
        ) {
            Ok(_) => sqlite3_result_int(ctx, 1),
            Err(e) => {
                sqlite_error(ctx, "register_table", e);
            }
        }
    }
}
