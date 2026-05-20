use std::mem::forget;

use rusqlite::{Connection, OptionalExtension, Result, params};

use crate::context::{effective_context, sec_ctx::SecurityContext};

pub(crate) fn context_json(ctx: &SecurityContext) -> String {
    let mut keys = ctx.attrs.keys().collect::<Vec<_>>();
    keys.sort();

    let entries = keys
        .into_iter()
        .map(|key| {
            let mut values = ctx
                .attrs
                .get(key)
                .map(|set| set.iter().collect::<Vec<_>>())
                .unwrap_or_default();
            values.sort();
            let values = values
                .into_iter()
                .map(|value| format!("\"{}\"", json_escape(value)))
                .collect::<Vec<_>>()
                .join(",");
            format!("\"{}\":[{}]", json_escape(key), values)
        })
        .collect::<Vec<_>>()
        .join(",");

    format!("{{{entries}}}")
}

pub(crate) fn audit_context_raw(db_ptr: usize) -> String {
    context_json(&effective_context(db_ptr))
}

pub(crate) fn set_audit_enabled(conn: &Connection, logical: &str, enabled: bool) -> Result<i64> {
    ensure_audit_config(conn, logical)?;
    conn.execute(
        "UPDATE sec_audit_config SET enabled = ?2 WHERE logical_table = ?1",
        params![logical, if enabled { 1 } else { 0 }],
    )?;
    Ok(1)
}

pub(crate) fn set_audit_enabled_raw(db_ptr: usize, logical: &str, enabled: bool) -> Result<i64> {
    let conn = unsafe { Connection::from_handle(db_ptr as *mut _)? };
    let result = set_audit_enabled(&conn, logical, enabled);
    forget(conn);
    result
}

pub(crate) fn configure_audit(
    conn: &Connection,
    logical: &str,
    key: &str,
    value: i64,
) -> Result<i64> {
    ensure_audit_config(conn, logical)?;
    let normalized = if value == 0 { 0 } else { 1 };
    let column = match key {
        "enabled" => "enabled",
        "audit_insert" => "audit_insert",
        "audit_update" => "audit_update",
        "audit_delete" => "audit_delete",
        "include_context" => "include_context",
        "include_changed_columns" => "include_changed_columns",
        _ => return Err(invalid(format!("unknown audit config key '{key}'"))),
    };
    conn.execute(
        &format!("UPDATE sec_audit_config SET {column} = ?2 WHERE logical_table = ?1"),
        params![logical, normalized],
    )?;
    Ok(1)
}

pub(crate) fn configure_audit_raw(
    db_ptr: usize,
    logical: &str,
    key: &str,
    value: i64,
) -> Result<i64> {
    let conn = unsafe { Connection::from_handle(db_ptr as *mut _)? };
    let result = configure_audit(&conn, logical, key, value);
    forget(conn);
    result
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn audit_event_raw(
    db_ptr: usize,
    logical_table: &str,
    physical_table: &str,
    operation: &str,
    outcome: &str,
    row_pk_json: Option<&str>,
    changed_columns_json: Option<&str>,
    row_label_id: Option<i64>,
    error: Option<&str>,
) -> Result<i64> {
    let conn = unsafe { Connection::from_handle(db_ptr as *mut _)? };
    let result = audit_event(
        &conn,
        db_ptr,
        logical_table,
        physical_table,
        operation,
        outcome,
        row_pk_json,
        changed_columns_json,
        row_label_id,
        error,
    );
    forget(conn);
    result
}

#[allow(clippy::too_many_arguments)]
fn audit_event(
    conn: &Connection,
    db_ptr: usize,
    logical_table: &str,
    physical_table: &str,
    operation: &str,
    outcome: &str,
    row_pk_json: Option<&str>,
    changed_columns_json: Option<&str>,
    row_label_id: Option<i64>,
    error: Option<&str>,
) -> Result<i64> {
    let operation = operation.to_ascii_uppercase();
    if !matches!(operation.as_str(), "INSERT" | "UPDATE" | "DELETE") {
        return Err(invalid(format!(
            "unsupported audit operation '{operation}'"
        )));
    }
    if !matches!(outcome, "success" | "denied") {
        return Err(invalid(format!("unsupported audit outcome '{outcome}'")));
    }

    ensure_audit_config(conn, logical_table)?;
    let config = load_audit_config(conn, logical_table)?;
    if !config.enabled || !config.audits_operation(&operation) {
        return Ok(0);
    }

    let context_json = if config.include_context {
        audit_context_raw(db_ptr)
    } else {
        "{}".to_string()
    };
    let changed_columns_json = if config.include_changed_columns {
        changed_columns_json
    } else {
        None
    };

    conn.execute(
        r#"
        INSERT INTO sec_audit_log (
            logical_table,
            physical_table,
            operation,
            outcome,
            row_pk_json,
            changed_columns_json,
            context_json,
            row_label_id,
            error
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
        params![
            logical_table,
            physical_table,
            operation,
            outcome,
            row_pk_json,
            changed_columns_json,
            context_json,
            row_label_id,
            error,
        ],
    )?;

    Ok(1)
}

fn ensure_audit_config(conn: &Connection, logical: &str) -> Result<()> {
    conn.execute(
        r#"
        INSERT OR IGNORE INTO sec_audit_config (
            logical_table,
            enabled,
            audit_insert,
            audit_update,
            audit_delete,
            include_context,
            include_changed_columns
        )
        VALUES (?1, 1, 1, 1, 1, 1, 1)
        "#,
        [logical],
    )?;
    Ok(())
}

struct AuditConfig {
    enabled: bool,
    audit_insert: bool,
    audit_update: bool,
    audit_delete: bool,
    include_context: bool,
    include_changed_columns: bool,
}

impl AuditConfig {
    fn audits_operation(&self, operation: &str) -> bool {
        match operation {
            "INSERT" => self.audit_insert,
            "UPDATE" => self.audit_update,
            "DELETE" => self.audit_delete,
            _ => false,
        }
    }
}

fn load_audit_config(conn: &Connection, logical: &str) -> Result<AuditConfig> {
    conn.query_row(
        r#"
        SELECT enabled,
               audit_insert,
               audit_update,
               audit_delete,
               include_context,
               include_changed_columns
        FROM sec_audit_config
        WHERE logical_table = ?1
        "#,
        [logical],
        |row| {
            Ok(AuditConfig {
                enabled: row.get::<_, i64>(0)? != 0,
                audit_insert: row.get::<_, i64>(1)? != 0,
                audit_update: row.get::<_, i64>(2)? != 0,
                audit_delete: row.get::<_, i64>(3)? != 0,
                include_context: row.get::<_, i64>(4)? != 0,
                include_changed_columns: row.get::<_, i64>(5)? != 0,
            })
        },
    )
    .optional()?
    .ok_or_else(|| invalid(format!("missing audit config for table '{logical}'")))
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

fn invalid<T: ToString>(msg: T) -> rusqlite::Error {
    rusqlite::Error::UserFunctionError(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        msg.to_string(),
    )))
}

#[cfg(test)]
mod tests {
    use super::context_json;
    use crate::context::sec_ctx::SecurityContext;

    #[test]
    fn context_json_is_stable_and_escaped() {
        let mut ctx = SecurityContext::default();
        ctx.set_attr("role", "admin");
        ctx.set_attr("role", "user");
        ctx.set_attr("team", "finance\"north");

        assert_eq!(
            context_json(&ctx),
            r#"{"role":["admin","user"],"team":["finance\"north"]}"#
        );
    }
}
