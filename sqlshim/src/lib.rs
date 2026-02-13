mod ffi;
mod parser;
mod plugin;
mod rewriter;
mod statement;

use libc::{c_char, c_int, c_void};

type Sqlite3 = c_void;
type SqliteStmt = c_void;
type ExecCallback = Option<
    unsafe extern "C" fn(
        arg: *mut c_void,
        argc: c_int,
        argv: *mut *mut c_char,
        col_names: *mut *mut c_char,
    ) -> c_int,
>;

type PrepareV2 = unsafe extern "C" fn(
    db: *mut Sqlite3,
    z_sql: *const c_char,
    n_byte: c_int,
    pp_stmt: *mut *mut SqliteStmt,
    pz_tail: *mut *const c_char,
) -> c_int;

type PrepareV3 = unsafe extern "C" fn(
    db: *mut Sqlite3,
    z_sql: *const c_char,
    n_byte: c_int,
    prep_flags: u32,
    pp_stmt: *mut *mut SqliteStmt,
    pz_tail: *mut *const c_char,
) -> c_int;

type Exec = unsafe extern "C" fn(
    db: *mut Sqlite3,
    sql: *const c_char,
    callback: ExecCallback,
    arg: *mut c_void,
    errmsg: *mut *mut c_char,
) -> c_int;

fn debug() -> bool {
    std::env::var("SQLSHIM_DEBUG").is_ok()
}

fn disabled() -> bool {
    std::env::var("SQLSHIM_DISABLE").is_ok()
}

fn parse_and_rewrite(sql: &str) -> Option<String> {
    if disabled() {
        return None;
    }

    let result = parser::parse_rewrite(sql).map(|stmt| {
        if debug() {
            eprintln!("sqlshim: rewrite: {:?}", stmt);
        }
        stmt
    });

    if debug() && result.is_none() {
        eprintln!("sqlshim: passthrough: {}", sql.trim());
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statement::*;

    #[test]
    fn test_parse_define_label() {
        let sql = "DEFINE LABEL 'true';";
        let stmt = parser::parse(sql).unwrap();
        match stmt {
            statement::CustomStatement::DefineLabel(d) => assert_eq!(d.expr, "true"),
            _ => panic!("Expected DefineLabel"),
        }
    }

    #[test]
    fn test_parse_define_level() {
        let sql = "DEFINE LEVEL clearance 'secret' = 2;";
        let stmt = parser::parse(sql).unwrap();
        match stmt {
            statement::CustomStatement::DefineLevelStmt(d) => {
                assert_eq!(d.attribute, "clearance");
                assert_eq!(d.name, "secret");
                assert_eq!(d.value, 2);
            }
            _ => panic!("Expected DefineLevelStmt"),
        }
    }

    #[test]
    fn test_parse_create_policy() {
        let sql = "CREATE POLICY test_pol ON users FOR SELECT USING (role='admin');";
        let stmt = parser::parse(sql).unwrap();
        match stmt {
            statement::CustomStatement::CreatePolicy(p) => {
                assert_eq!(p.name, "test_pol");
                assert_eq!(p.table, "users");
                assert_eq!(p.operation, Some(PolicyOperation::Select));
                assert_eq!(p.using_expr, "role = 'admin'");
            }
            _ => panic!("Expected CreatePolicy"),
        }
    }

    #[test]
    fn test_parse_set_context() {
        let sql = "SET CONTEXT role = 'admin';";
        let stmt = parser::parse(sql).unwrap();
        match stmt {
            statement::CustomStatement::SetContext(s) => {
                assert_eq!(s.key, "role");
                assert_eq!(s.value, "admin");
            }
            _ => panic!("Expected SetContext"),
        }
    }

    #[test]
    fn test_passthrough_normal_sql() {
        let sql = "SELECT * FROM users WHERE id = 1;";
        assert!(parser::parse(sql).is_none());
    }

    #[test]
    fn test_rewrite_define_label() {
        let sql = "DEFINE LABEL 'role=admin';";
        let rewritten = parse_and_rewrite(sql).unwrap();
        assert!(rewritten.contains("sec_define_label"));
        assert!(rewritten.contains("role=admin"));
    }
}
