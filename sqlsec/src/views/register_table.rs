use std::mem::forget;

use rusqlite::{Connection, Result};

use crate::views::{get_physical_columns, get_primary_key_columns, invalid};

fn is_without_rowid(conn: &Connection, table: &str) -> Result<bool> {
    let sql: Option<String> = conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
        [table],
        |row| row.get(0),
    )?;

    Ok(sql
        .map(|s| s.to_uppercase().contains("WITHOUT ROWID"))
        .unwrap_or(false))
}

/// Register a table using Connection reference
pub fn register_table(
    conn: &Connection,
    logical: &str,
    physical: &str,
    row_label_col: &str,
    table_label_id: Option<i64>,
    insert_label_id: Option<i64>,
) -> Result<()> {
    // 1. Physical table exists (implicit via PRAGMA failure)
    let cols = get_physical_columns(conn, physical)?;

    // 2. Row label column exists
    if !cols.iter().any(|c| c == row_label_col) {
        return Err(invalid(format!(
            "row label column '{row_label_col}' does not exist, candidates are: {}",
            cols.join(", ")
        )));
    }

    // 3. Primary key exists
    let pk_cols = get_primary_key_columns(conn, physical)?;
    if pk_cols.is_empty() {
        return Err(invalid(format!(
            "secured table '{physical}' must have a PRIMARY KEY"
        )));
    }

    // 4. Reject WITHOUT ROWID tables
    if is_without_rowid(conn, physical)? {
        return Err(invalid(format!(
            "WITHOUT ROWID table '{physical}' is not supported"
        )));
    }

    // 5. Column name sanity
    let mut seen = std::collections::HashSet::new();
    for col in &cols {
        if !seen.insert(col.to_lowercase()) {
            return Err(invalid(format!("duplicate column name '{col}' detected")));
        }
    }

    // ---- safe to register ----

    conn.execute(
        r#"
        INSERT OR REPLACE INTO sec_tables
        (logical_name, physical_name, row_label_col, table_label_id, insert_label_id)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        rusqlite::params![
            logical,
            physical,
            row_label_col,
            table_label_id,
            insert_label_id
        ],
    )?;

    for col in cols {
        conn.execute(
            r#"
            INSERT OR IGNORE INTO sec_columns (logical_table, column_name, read_label_id, update_label_id)
            VALUES (?1, ?2, NULL, NULL)
            "#,
            rusqlite::params![logical, col],
        )?;
    }

    Ok(())
}

/// Register a table from raw pointer (for FFI)
pub fn register_table_raw(
    db_ptr: usize,
    logical: &str,
    physical: &str,
    row_label_col: &str,
    table_label_id: Option<i64>,
    insert_label_id: Option<i64>,
) -> Result<()> {
    let conn = unsafe { Connection::from_handle(db_ptr as *mut _)? };
    let result = register_table(
        &conn,
        logical,
        physical,
        row_label_col,
        table_label_id,
        insert_label_id,
    );
    forget(conn);
    result
}
