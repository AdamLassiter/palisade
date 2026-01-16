use std::ffi::{CStr, c_char, c_int};

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

use crate::{context, get_context, label, set_context, views};

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
            4,
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
            sqlite3_result_error(ctx, c"expected 2 arguments".as_ptr(), -1);
            return;
        }

        let key = sqlite3_value_text(*argv);
        let val = sqlite3_value_text(*argv.add(1));

        if key.is_null() || val.is_null() {
            sqlite3_result_error(ctx, c"NULL argument".as_ptr(), -1);
            return;
        }

        let key = CStr::from_ptr(key as *const c_char).to_string_lossy();
        let val = CStr::from_ptr(val as *const c_char).to_string_lossy();

        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        let mut sec_ctx = get_context(db_ptr);
        sec_ctx.set_attr(&key, &val);
        set_context(db_ptr, sec_ctx);

        sqlite3_result_int(ctx, 1);
    }
}

pub(crate) extern "C" fn ffi_sec_clear_context(
    ctx: *mut sqlite3_context,
    _argc: c_int,
    _argv: *mut *mut sqlite3_value,
) {
    unsafe {
        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        set_context(db_ptr, context::SecurityContext::default());
        sqlite3_result_int(ctx, 1);
    }
}

pub(crate) extern "C" fn ffi_sec_define_label(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if argc != 1 {
            sqlite3_result_error(ctx, c"expected 1 argument".as_ptr(), -1);
            return;
        }

        let expr_ptr = sqlite3_value_text(*argv);
        if expr_ptr.is_null() {
            sqlite3_result_error(ctx, c"NULL argument".as_ptr(), -1);
            return;
        }

        let expr = CStr::from_ptr(expr_ptr as *const c_char).to_string_lossy();

        // Validate parse
        if label::parse(&expr).is_err() {
            sqlite3_result_error(ctx, c"invalid label expression".as_ptr(), -1);
            return;
        }

        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        match label::define_label_raw(db_ptr, &expr) {
            Ok(id) => sqlite3_result_int64(ctx, id),
            Err(_) => sqlite3_result_error(ctx, c"failed to define label".as_ptr(), -1),
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
            sqlite3_result_error(ctx, c"expected 1 argument".as_ptr(), -1);
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
                let sec_ctx = get_context(db_ptr);
                label::evaluate_by_id(db_ptr, id, &sec_ctx).unwrap_or(false)
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
            Err(_) => sqlite3_result_error(ctx, c"failed to refresh views".as_ptr(), -1),
        }
    }
}

pub(crate) extern "C" fn ffi_sec_register_table(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if argc != 4 {
            sqlite3_result_error(ctx, c"expected 4 arguments".as_ptr(), -1);
            return;
        }

        let logical_ptr = sqlite3_value_text(*argv);
        let physical_ptr = sqlite3_value_text(*argv.add(1));
        let row_col_ptr = sqlite3_value_text(*argv.add(2));

        if logical_ptr.is_null() || physical_ptr.is_null() || row_col_ptr.is_null() {
            sqlite3_result_error(ctx, c"NULL argument".as_ptr(), -1);
            return;
        }

        let logical = CStr::from_ptr(logical_ptr as *const c_char).to_string_lossy();
        let physical = CStr::from_ptr(physical_ptr as *const c_char).to_string_lossy();
        let row_col = CStr::from_ptr(row_col_ptr as *const c_char).to_string_lossy();

        let table_label = if sqlite3_value_type(*argv.add(3)) == SQLITE_NULL {
            None
        } else {
            Some(sqlite3_value_int64(*argv.add(3)))
        };

        let db_ptr = sqlite3_context_db_handle(ctx) as usize;
        match views::register_table_raw(db_ptr, &logical, &physical, &row_col, table_label) {
            Ok(_) => sqlite3_result_int(ctx, 1),
            Err(_) => sqlite3_result_error(ctx, c"failed to register table".as_ptr(), -1),
        }
    }
}
