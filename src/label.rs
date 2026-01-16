use crate::context::SecurityContext;
use nom::{
    branch::alt,
    bytes::complete::take_while1,
    character::complete::char,
    combinator::map,
    multi::separated_list1,
    sequence::{delimited, separated_pair},
    IResult,
};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rusqlite::{Connection, Error, Result};
use std::{collections::HashMap, mem::forget};

/// A single requirement: key=value
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrReq {
    pub key: String,
    pub value: String,
}

/// OR-group: any of these requirements satisfies the clause
pub type Clause = Vec<AttrReq>;

/// AND of OR-groups (CNF)
#[derive(Debug, Clone, Default)]
pub struct Label {
    pub clauses: Vec<Clause>,
    pub always_true: bool,
}

impl Label {
    pub fn evaluate(&self, ctx: &SecurityContext) -> bool {
        if self.always_true {
            return true;
        }

        // All clauses must pass (AND)
        self.clauses.iter().all(|clause| {
            // At least one requirement in clause must match (OR)
            clause.iter().any(|req| ctx.has(&req.key, &req.value))
        })
    }
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn ident(input: &str) -> IResult<&str, &str> {
    take_while1(is_ident_char)(input)
}

fn attr_req(input: &str) -> IResult<&str, AttrReq> {
    map(separated_pair(ident, char('='), ident), |(k, v)| AttrReq {
        key: k.to_string(),
        value: v.to_string(),
    })(input)
}

fn clause(input: &str) -> IResult<&str, Clause> {
    alt((
        delimited(char('('), separated_list1(char('|'), attr_req), char(')')),
        map(attr_req, |r| vec![r]),
    ))(input)
}

fn label_expr(input: &str) -> IResult<&str, Label> {
    if input.trim() == "true" {
        return Ok((
            "",
            Label {
                clauses: vec![],
                always_true: true,
            },
        ));
    }

    map(separated_list1(char('&'), clause), |clauses| Label {
        clauses,
        always_true: false,
    })(input)
}

pub fn parse(expr: &str) -> std::result::Result<Label, String> {
    let trimmed = expr.trim();
    match label_expr(trimmed) {
        Ok(("", label)) => Ok(label),
        Ok((rest, _)) => Err(format!("unexpected trailing: {rest}")),
        Err(e) => Err(format!("parse error: {e}")),
    }
}

// ============================================================================
// Label cache and DB operations
// ============================================================================

static LABEL_CACHE: Lazy<Mutex<HashMap<i64, Label>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Define a label using a Connection reference (for tests and direct use)
pub fn define_label(conn: &Connection, expr: &str) -> Result<i64> {
    conn.execute(
        "INSERT OR IGNORE INTO sec_labels (expr) VALUES (?1)",
        [expr],
    )?;

    let id: i64 = conn.query_row(
        "SELECT id FROM sec_labels WHERE expr = ?1",
        [expr],
        |r| r.get(0),
    )?;

    if let Ok(label) = parse(expr) {
        LABEL_CACHE.lock().insert(id, label);
    }

    Ok(id)
}

/// Define a label from raw db pointer (for FFI)
pub fn define_label_raw(db_ptr: usize, expr: &str) -> Result<i64> {
    let conn = unsafe { Connection::from_handle(db_ptr as *mut _)? };
    let result = define_label(&conn, expr);
    forget(conn);
    result
}

/// Evaluate label by ID against context (using Connection)
pub fn evaluate_by_id_conn(conn: &Connection, label_id: i64, ctx: &SecurityContext) -> Result<bool> {
    // Check cache first
    if let Some(label) = LABEL_CACHE.lock().get(&label_id) {
        return Ok(label.evaluate(ctx));
    }
    // Load from DB
    let expr: String = conn.query_row(
        "SELECT expr FROM sec_labels WHERE id = ?1",
        [label_id],
        |r| r.get(0),
    )?;

    let label = parse(&expr).map_err(|_| Error::InvalidQuery)?;

    LABEL_CACHE.lock().insert(label_id, label.clone());

    Ok(label.evaluate(ctx))
}

/// Evaluate label by ID from raw pointer (for FFI)
pub fn evaluate_by_id(db_ptr: usize, label_id: i64, ctx: &SecurityContext) -> Result<bool> {
    let conn = unsafe { Connection::from_handle(db_ptr as *mut _)? };
    let result = evaluate_by_id_conn(&conn, label_id, ctx);
    forget(conn);
    result
}

/// Check if a label allows access (using Connection)
pub fn is_visible_conn(conn: &Connection, label_id: Option<i64>, ctx: &SecurityContext) -> bool {
    match label_id {
        None => true,
        Some(id) => evaluate_by_id_conn(conn, id, ctx).unwrap_or(false),
    }
}

/// Check if a label allows access from raw pointer (for FFI)
pub fn is_visible(db_ptr: usize, label_id: Option<i64>, ctx: &SecurityContext) -> bool {
    match label_id {
        None => true,
        Some(id) => evaluate_by_id(db_ptr, id, ctx).unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple() {
        let label = parse("role=admin").unwrap();
        assert_eq!(label.clauses.len(), 1);
        assert_eq!(label.clauses[0].len(), 1);
    }

    #[test]
    fn parse_or_group() {
        let label = parse("(role=admin|role=auditor)").unwrap();
        assert_eq!(label.clauses.len(), 1);
        assert_eq!(label.clauses[0].len(), 2);
    }

    #[test]
    fn parse_and_of_ors() {
        let label = parse("(role=admin|role=auditor)&team=finance").unwrap();
        assert_eq!(label.clauses.len(), 2);
    }

    #[test]
    fn evaluate_simple() {
        let label = parse("role=admin").unwrap();
        let mut ctx = SecurityContext::default();

        assert!(!label.evaluate(&ctx));

        ctx.set_attr("role", "admin");
        assert!(label.evaluate(&ctx));
    }

    #[test]
    fn evaluate_or() {
        let label = parse("(role=admin|role=auditor)").unwrap();
        let mut ctx = SecurityContext::default();

        ctx.set_attr("role", "auditor");
        assert!(label.evaluate(&ctx));
    }

    #[test]
    fn evaluate_and() {
        let label = parse("role=admin&team=finance").unwrap();
        let mut ctx = SecurityContext::default();

        ctx.set_attr("role", "admin");
        assert!(!label.evaluate(&ctx));

        ctx.set_attr("team", "finance");
        assert!(label.evaluate(&ctx));
    }
}