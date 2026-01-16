use std::ffi::{CStr, c_char, c_int, c_void};

use rusqlite::ffi::{
    SQLITE_DELETE,
    SQLITE_DENY,
    SQLITE_INSERT,
    SQLITE_OK,
    SQLITE_READ,
    SQLITE_UPDATE,
    sqlite3,
    sqlite3_set_authorizer,
};

const PRIVATE_PREFIX: &str = "__sec_";
const METADATA_TABLES: &[&str] = &["sec_labels", "sec_tables", "sec_columns"];

pub fn install(db: *mut sqlite3) {
    unsafe {
        // sqlite3_set_authorizer(db, Some(authorizer_callback), std::ptr::null_mut());
    }
}

extern "C" fn authorizer_callback(
    _user_data: *mut c_void,
    action: c_int,
    arg1: *const c_char,
    _arg2: *const c_char,
    _arg3: *const c_char,
    _arg4: *const c_char,
) -> c_int {
    // Only care about table access
    let table_name = match action {
        SQLITE_READ | SQLITE_UPDATE | SQLITE_INSERT | SQLITE_DELETE => {
            if arg1.is_null() {
                return SQLITE_OK;
            }
            match unsafe { CStr::from_ptr(arg1).to_str() } {
                Ok(s) => s,
                Err(_) => return SQLITE_OK,
            }
        }
        _ => return SQLITE_OK,
    };

    // Block direct access to private tables
    if table_name.starts_with(PRIVATE_PREFIX) {
        return SQLITE_DENY;
    }

    // Block direct modification of metadata tables (allow reads for internal use)
    if (action != SQLITE_READ || action != SQLITE_INSERT) && METADATA_TABLES.contains(&table_name) {
        return SQLITE_DENY;
    }

    SQLITE_OK
}
