use std::{
    ffi::{CStr, CString},
    slice::from_raw_parts,
};

use libc::{RTLD_NEXT, c_char, c_int, c_void};

use crate::{
    Exec,
    ExecCallback,
    PrepareV2,
    PrepareV3,
    Sqlite3,
    SqliteStmt,
    debug,
    parse_and_rewrite,
};

pub(crate) unsafe fn resolve_prepare_v2() -> PrepareV2 {
    let cname = CString::new("sqlite3_prepare_v2").unwrap();
    let addr = unsafe { libc::dlsym(RTLD_NEXT, cname.as_ptr()) };
    if addr.is_null() {
        panic!("sqlshim: could not resolve sqlite3_prepare_v2");
    }
    unsafe { std::mem::transmute(addr) }
}

pub(crate) unsafe fn resolve_prepare_v3() -> PrepareV3 {
    let cname = CString::new("sqlite3_prepare_v3").unwrap();
    let addr = unsafe { libc::dlsym(RTLD_NEXT, cname.as_ptr()) };
    if addr.is_null() {
        panic!("sqlshim: could not resolve sqlite3_prepare_v3");
    }
    unsafe { std::mem::transmute(addr) }
}

pub(crate) unsafe fn resolve_exec() -> Exec {
    let cname = CString::new("sqlite3_exec").unwrap();
    let addr = unsafe { libc::dlsym(RTLD_NEXT, cname.as_ptr()) };
    if addr.is_null() {
        panic!("sqlshim: could not resolve sqlite3_exec");
    }
    unsafe { std::mem::transmute(addr) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_prepare_v2(
    db: *mut Sqlite3,
    z_sql: *const c_char,
    n_byte: c_int,
    pp_stmt: *mut *mut SqliteStmt,
    pz_tail: *mut *const c_char,
) -> c_int {
    let real = unsafe { resolve_prepare_v2() };
    let sql = sqlite3_to_str(&z_sql, n_byte);

    if let Some(new_sql) = parse_and_rewrite(sql) {
        if debug() {
            eprintln!("sqlshim: prepare_v2 rewrite!");
            eprintln!("  original: {}", sql.trim());
            eprintln!("  rewritten: {}", new_sql.trim());
        }
        let csql = CString::new(new_sql).unwrap();
        return unsafe { real(db, csql.as_ptr(), -1, pp_stmt, pz_tail) };
    }

    unsafe { real(db, z_sql, n_byte, pp_stmt, pz_tail) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_prepare_v3(
    db: *mut Sqlite3,
    z_sql: *const c_char,
    n_byte: c_int,
    prep_flags: u32,
    pp_stmt: *mut *mut SqliteStmt,
    pz_tail: *mut *const c_char,
) -> c_int {
    let real = unsafe { resolve_prepare_v3() };
    let sql = sqlite3_to_str(&z_sql, n_byte);

    if let Some(new_sql) = parse_and_rewrite(sql) {
        if debug() {
            eprintln!("sqlshim: prepare_v3 rewrite!");
            eprintln!("  original: {}", sql.trim());
            eprintln!("  rewritten: {}", new_sql.trim());
        }
        let csql = CString::new(new_sql).unwrap();
        return unsafe { real(db, csql.as_ptr(), -1, prep_flags, pp_stmt, pz_tail) };
    }

    unsafe { real(db, z_sql, n_byte, prep_flags, pp_stmt, pz_tail) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_exec(
    db: *mut Sqlite3,
    sql: *const c_char,
    callback: ExecCallback,
    arg: *mut c_void,
    errmsg: *mut *mut c_char,
) -> c_int {
    let real = unsafe { resolve_exec() };
    let sql_str = unsafe { CStr::from_ptr(sql).to_string_lossy() };

    // sqlite3_exec can contain multiple statements - we need to handle each
    // For now, try to rewrite the whole thing if it's a single custom statement
    if let Some(new_sql) = parse_and_rewrite(&sql_str) {
        if debug() {
            eprintln!("sqlshim: exec rewrite!");
            eprintln!("  original: {}", sql_str.trim());
            eprintln!("  rewritten: {}", new_sql.trim());
        }
        let csql = CString::new(new_sql).unwrap();
        return unsafe { real(db, csql.as_ptr(), callback, arg, errmsg) };
    }

    unsafe { real(db, sql, callback, arg, errmsg) }
}

fn sqlite3_to_str(z_sql: &*const c_char, n_byte: c_int) -> &str {
    if z_sql.is_null() {
        return "";
    }

    let bytes = unsafe { from_raw_parts::<'_, u8>(*z_sql as *const u8, n_byte as usize) };

    str::from_utf8(bytes).expect("Invalid UTF-8 in SQL string")
}
