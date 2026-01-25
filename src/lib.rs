pub mod context;
pub mod init;
pub mod label;
pub mod register;
pub mod views;

use std::{
    ffi::{CString, c_char, c_int},
    ptr,
};

use rusqlite::{
    ffi::{
        SQLITE_ERROR,
        SQLITE_OK,
        rusqlite_extension_init2,
        sqlite3,
        sqlite3_api_routines,
        sqlite3_malloc,
    },
};

use crate::init::init_extension_ffi;

/// Initialize the extension entry point for SQLite.
///
/// # Safety
/// Must only be invoked by SQLite when loading the extension.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_sqlsec_init(
    db: *mut sqlite3,
    pz_err_msg: *mut *mut c_char,
    p_api: *mut sqlite3_api_routines,
) -> c_int {
    // Safety: called by SQLite loader
    if let Err(e) = unsafe { rusqlite_extension_init2(p_api) } {
        set_err_message(pz_err_msg, &format!("failed to init SQLite API: {e:?}"));
        return SQLITE_ERROR;
    }

    match unsafe { init_extension_ffi(db) } {
        Ok(_) => SQLITE_OK,
        Err(e) => {
            set_err_message(pz_err_msg, &format!("sqlsec initialization failed: {e}"));
            SQLITE_ERROR
        }
    }
}

/// Set the SQLite extension error message.
///
/// Allocates a C string using `sqlite3_malloc` and writes its pointer to `pz_err_msg`.
fn set_err_message(pz_err_msg: *mut *mut c_char, msg: &str) {
    unsafe {
        if pz_err_msg.is_null() {
            return;
        }

        // Compose message and ensure null terminator
        let msg_owned = CString::new(msg).unwrap_or_else(|_| CString::new("error").unwrap());
        let bytes = msg_owned.as_bytes_with_nul();

        // Allocate memory that SQLite expects to own
        let buf = sqlite3_malloc(bytes.len() as i32) as *mut c_char;
        if buf.is_null() {
            return;
        }

        ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buf, bytes.len());
        *pz_err_msg = buf;
    }
}
