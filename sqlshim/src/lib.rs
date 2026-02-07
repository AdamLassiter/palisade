use std::{
    ffi::{CStr, CString},
    mem::transmute,
};

use libc::{RTLD_NEXT, c_char, c_int, c_void};

//
// SQLite signature:
//
// int sqlite3_exec(
//   sqlite3*,                                  /* An open database */
//   const char *sql,                           /* SQL to be evaluated */
//   int (*callback)(void*,int,char**,char**),   /* Callback function */
//   void *,                                    /* 1st argument to callback */
//   char **errmsg                              /* Error msg written here */
// );
//

type Sqlite3 = c_void;

type ExecCallback = Option<
    unsafe extern "C" fn(
        arg: *mut c_void,
        ncols: c_int,
        values: *mut *mut c_char,
        colnames: *mut *mut c_char,
    ) -> c_int,
>;

type SqliteExecFn = unsafe extern "C" fn(
    db: *mut Sqlite3,
    sql: *const c_char,
    callback: ExecCallback,
    arg: *mut c_void,
    errmsg: *mut *mut c_char,
) -> c_int;

/// Resolve the real sqlite3_exec using dlsym(RTLD_NEXT, ...)
fn real_sqlite3_exec() -> SqliteExecFn {
    let symbol = CString::new("sqlite3_exec").unwrap();

    let addr = unsafe { libc::dlsym(RTLD_NEXT, symbol.as_ptr()) };

    if addr.is_null() {
        panic!("lazyshim: failed to resolve real sqlite3_exec");
    }

    unsafe { transmute::<*mut c_void, SqliteExecFn>(addr) }
}

/// Very naive rewrite hook.
/// Replace this with a real parser later.
fn rewrite_sql(input: &str) -> String {
    if input.trim_start().starts_with("CREATE POLICY") {
        // Example rewrite:
        // CREATE POLICY ... → INSERT INTO metadata + CREATE VIEW ...
        return format!(
            "-- rewritten by lazyshim\n\
             INSERT INTO lazysql_policies(dummy) VALUES ('example');\n\
             -- original:\n\
             -- {}\n",
            input.trim()
        );
    }

    // Otherwise pass through unchanged
    input.to_string()
}

///
/// This is the function LD_PRELOAD will intercept.
///
/// # Safety
/// We must ensure that we call the real sqlite3_exec with properly rewritten SQL and that we handle C strings correctly.
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_exec(
    db: *mut Sqlite3,
    sql: *const c_char,
    callback: ExecCallback,
    arg: *mut c_void,
    errmsg: *mut *mut c_char,
) -> c_int {
    // Convert SQL input into Rust string
    let sql_str = if sql.is_null() {
        ""
    } else {
        unsafe { &CStr::from_ptr(sql).to_string_lossy().to_string() }
    };

    // Debug logging
    if std::env::var("LAZYSQL_DEBUG").is_ok() {
        eprintln!("lazyshim: intercepted sqlite3_exec:");
        eprintln!("--- original SQL ---\n{}", sql_str);
    }

    // Rewrite SQL
    let rewritten = rewrite_sql(sql_str);

    if std::env::var("LAZYSQL_DEBUG").is_ok() {
        eprintln!("--- rewritten SQL ---\n{}", rewritten);
    }

    // Convert rewritten SQL back to C string
    let rewritten_c = CString::new(rewritten).unwrap();

    // Call the real sqlite3_exec
    let real_exec = real_sqlite3_exec();

    unsafe { real_exec(db, rewritten_c.as_ptr(), callback, arg, errmsg) }
}
