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
    let sql = sql_from_prepare_args(z_sql, n_byte);

    if let Some(sql) = sql.as_deref() {
        if let Some(new_sql) = parse_and_rewrite(sql) {
            if debug() {
                eprintln!("sqlshim: prepare_v2 rewrite!");
                eprintln!("  original: {}", sql.trim());
                eprintln!("  rewritten: {}", new_sql.trim());
            }
            if let Ok(csql) = CString::new(new_sql) {
                return unsafe { real(db, csql.as_ptr(), -1, pp_stmt, pz_tail) };
            }
        }
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
    let sql = sql_from_prepare_args(z_sql, n_byte);

    if let Some(sql) = sql.as_deref() {
        if let Some(new_sql) = parse_and_rewrite(sql) {
            if debug() {
                eprintln!("sqlshim: prepare_v3 rewrite!");
                eprintln!("  original: {}", sql.trim());
                eprintln!("  rewritten: {}", new_sql.trim());
            }
            if let Ok(csql) = CString::new(new_sql) {
                return unsafe { real(db, csql.as_ptr(), -1, prep_flags, pp_stmt, pz_tail) };
            }
        }
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
    if sql.is_null() {
        return unsafe { real(db, sql, callback, arg, errmsg) };
    }
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

fn sql_from_prepare_args(z_sql: *const c_char, n_byte: c_int) -> Option<String> {
    if z_sql.is_null() {
        return None;
    }

    let bytes = if n_byte < 0 {
        unsafe { CStr::from_ptr(z_sql).to_bytes() }
    } else {
        let raw = unsafe { from_raw_parts::<'_, u8>(z_sql as *const u8, n_byte as usize) };
        let len = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        &raw[..len]
    };

    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_from_prepare_args_handles_null_pointer() {
        assert_eq!(sql_from_prepare_args(std::ptr::null(), -1), None);
    }

    #[test]
    fn sql_from_prepare_args_handles_nbyte_negative() {
        let sql = CString::new("SELECT 1").unwrap();
        assert_eq!(
            sql_from_prepare_args(sql.as_ptr(), -1).as_deref(),
            Some("SELECT 1")
        );
    }

    #[test]
    fn sql_from_prepare_args_handles_nbyte_zero() {
        let sql = CString::new("SELECT 1").unwrap();
        assert_eq!(sql_from_prepare_args(sql.as_ptr(), 0).as_deref(), Some(""));
    }

    #[test]
    fn sql_from_prepare_args_trims_embedded_trailing_null() {
        let sql = b"SELECT 1\0DROP\0";
        assert_eq!(
            sql_from_prepare_args(sql.as_ptr() as *const c_char, sql.len() as c_int).as_deref(),
            Some("SELECT 1")
        );
    }

    #[test]
    fn sql_from_prepare_args_rejects_invalid_utf8() {
        let bytes = [0xFFu8, 0x00u8];
        assert_eq!(
            sql_from_prepare_args(bytes.as_ptr() as *const c_char, bytes.len() as c_int),
            None
        );
    }
}
