#[cfg(false)]
mod authorizer;
pub mod context;
pub mod label;
pub mod register;
pub mod views;

use std::{
    collections::HashMap,
    ffi::{CString, c_char, c_int},
    mem::forget,
    ptr,
};

use context::SecurityContext;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rusqlite::{
    Connection,
    Result,
    ffi::{
        SQLITE_ERROR,
        SQLITE_OK,
        rusqlite_extension_init2,
        sqlite3,
        sqlite3_api_routines,
        sqlite3_malloc,
    },
};

/// Global map: db handle address -> SecurityContext
pub static CONTEXTS: Lazy<Mutex<HashMap<usize, SecurityContext>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Get or create context for a connection
pub fn get_context(db_ptr: usize) -> SecurityContext {
    CONTEXTS.lock().entry(db_ptr).or_default().clone()
}

pub fn set_context(db_ptr: usize, ctx: SecurityContext) {
    CONTEXTS.lock().insert(db_ptr, ctx);
}

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
        Ok(_) => {
            // Install authorizer
            #[cfg(false)]
            authorizer::install(db);
            SQLITE_OK
        }
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

/// Initialize the database objects when extension loads via FFI.
unsafe fn init_extension_ffi(db: *mut sqlite3) -> Result<()> {
    let conn = unsafe { Connection::from_handle(db) }?;

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS sec_labels (
            id   INTEGER PRIMARY KEY,
            expr TEXT NOT NULL UNIQUE
        );

        CREATE TABLE IF NOT EXISTS sec_tables (
            logical_name   TEXT PRIMARY KEY,
            physical_name  TEXT NOT NULL,
            row_label_col  TEXT NOT NULL,
            table_label_id INTEGER REFERENCES sec_labels(id)
        );

        CREATE TABLE IF NOT EXISTS sec_columns (
            logical_table TEXT NOT NULL,
            column_name   TEXT NOT NULL,
            label_id      INTEGER REFERENCES sec_labels(id),
            PRIMARY KEY (logical_table, column_name)
        );
        "#,
    )?;

    // Ensure we don’t close SQLite’s internal handle
    forget(conn);

    // Register scalar functions
    register::register_functions_ffi(db);

    Ok(())
}
