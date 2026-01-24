use std::{io::ErrorKind, mem::forget};

use rusqlite::{Connection, Error, Result};

use crate::{
    context::{SecurityContext, effective_context},
    label,
};

#[derive(Debug)]
pub struct SecTable {
    logical_name: String,
    physical_name: String,
    row_label_col: String,
    table_label_id: Option<i64>,
    insert_label_id: Option<i64>,
}

#[derive(Debug)]
struct SecColumn {
    column_name: String,
    label_id: Option<i64>,
}

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
            "row label column '{row_label_col}' does not exist"
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
            INSERT OR IGNORE INTO sec_columns (logical_table, column_name, label_id)
            VALUES (?1, ?2, NULL)
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

fn get_physical_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info(\"{}\")", table))?;
    let cols = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>>>()?;
    Ok(cols)
}

fn annotate(err: Error, table: &str) -> Error {
    Error::UserFunctionError(Box::new(std::io::Error::other(format!(
        "sqlsec refresh failed for table '{}': {}",
        table, err
    ))))
}

pub fn bump_generation(conn: &mut Connection) -> Result<()> {
    conn.execute(
        r#"
        UPDATE sec_meta
        SET value = value + 1
        WHERE key = 'generation';
        "#,
        [],
    )?;
    Ok(())
}

pub fn bump_generation_raw(db_ptr: usize) -> Result<()> {
    let mut conn = unsafe { Connection::from_handle(db_ptr as *mut _)? };

    let result = bump_generation(&mut conn);

    forget(conn);
    result
}

/// Refresh views using Connection reference
pub fn refresh_views(conn: &mut Connection, ctx: &SecurityContext) -> Result<()> {
    let tx = conn.transaction()?; // BEGIN

    let tables = load_sec_tables(&tx)?;

    for table in tables {
        refresh_single_view(&tx, &table, ctx).map_err(|e| annotate(e, &table.logical_name))?;
    }

    tx.execute_batch(
        r#"
        INSERT OR REPLACE INTO sec_meta (key, value)
        VALUES ('last_refresh_generation',
            (SELECT value FROM sec_meta WHERE key = 'generation'));

        INSERT OR REPLACE INTO sec_meta (key, value)
        VALUES ('views_initialized', 1);
        "#,
    )?;

    tx.commit()?; // COMMIT
    Ok(())
}

/// Refresh views from raw pointer (for FFI)
pub fn refresh_views_raw(db_ptr: usize) -> Result<()> {
    let mut conn = unsafe { Connection::from_handle(db_ptr as *mut _)? };

    let ctx = effective_context(db_ptr);

    let result = refresh_views(&mut conn, &ctx);

    forget(conn);
    result
}

fn load_sec_tables(conn: &Connection) -> Result<Vec<SecTable>> {
    let mut stmt = conn.prepare(
        "SELECT logical_name, physical_name, row_label_col, table_label_id, insert_label_id FROM sec_tables",
    )?;

    let tables = stmt
        .query_map([], |row| {
            Ok(SecTable {
                logical_name: row.get(0)?,
                physical_name: row.get(1)?,
                row_label_col: row.get(2)?,
                table_label_id: row.get(3)?,
                insert_label_id: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>>>()?;

    Ok(tables)
}

fn load_sec_columns(conn: &Connection, logical_table: &str) -> Result<Vec<SecColumn>> {
    let mut stmt =
        conn.prepare("SELECT column_name, label_id FROM sec_columns WHERE logical_table = ?1")?;

    let cols = stmt
        .query_map([logical_table], |row| {
            Ok(SecColumn {
                column_name: row.get(0)?,
                label_id: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>>>()?;

    Ok(cols)
}

fn refresh_single_view(conn: &Connection, table: &SecTable, ctx: &SecurityContext) -> Result<()> {
    // Check table-level visibility
    if !label::is_visible_conn(conn, table.table_label_id, ctx) {
        conn.execute(
            &format!("DROP VIEW IF EXISTS \"{}\"", table.logical_name),
            [],
        )?;
        return Ok(());
    }

    // Get columns and filter by visibility
    let all_columns = load_sec_columns(conn, &table.logical_name)?;
    let visible_columns: Vec<&str> = all_columns
        .iter()
        .filter(|c| label::is_visible_conn(conn, c.label_id, ctx))
        .map(|c| c.column_name.as_str())
        .collect();

    if visible_columns.is_empty() {
        conn.execute(
            &format!("DROP VIEW IF EXISTS \"{}\"", table.logical_name),
            [],
        )?;
        return Ok(());
    }

    // Build SELECT list
    let select_cols = visible_columns
        .iter()
        .map(|c| format!("\"{}\"", c))
        .collect::<Vec<_>>()
        .join(", ");

    // Build the view DDL
    let view_sql = format!(
        r#"
        DROP VIEW IF EXISTS "{}";
        CREATE TEMP VIEW "{}" AS
        SELECT {}
        FROM "{}"
        WHERE sec_row_visible("{}");
        "#,
        table.logical_name,
        table.logical_name,
        select_cols,
        table.physical_name,
        table.row_label_col
    );

    conn.execute_batch(&view_sql)?;

    // Create INSTEAD OF triggers for writes
    create_write_triggers(conn, table, &visible_columns)?;

    Ok(())
}

fn get_primary_key_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info(\"{}\")", table))?;

    let mut pk_cols: Vec<(i64, String)> = Vec::new();

    let rows = stmt.query_map([], |row| {
        let name: String = row.get(1)?;
        let pk: i64 = row.get(5)?;
        Ok((pk, name))
    })?;

    for row in rows {
        let (pk, name) = row?;
        if pk > 0 {
            pk_cols.push((pk, name));
        }
    }

    // Sort by PK position (important for composite keys)
    pk_cols.sort_by_key(|(pk, _)| *pk);

    Ok(pk_cols.into_iter().map(|(_, name)| name).collect())
}

fn invalid<T: ToString>(msg: T) -> Error {
    Error::UserFunctionError(Box::new(std::io::Error::new(
        ErrorKind::InvalidInput,
        msg.to_string(),
    )))
}

fn trigger_err(err: rusqlite::Error, table: &str, kind: &str) -> rusqlite::Error {
    rusqlite::Error::UserFunctionError(Box::new(std::io::Error::other(format!(
        "failed to create {} trigger for table '{}': {}",
        kind, table, err
    ))))
}

fn create_write_triggers(conn: &Connection, table: &SecTable, visible_cols: &[&str]) -> Result<()> {
    let logical = &table.logical_name;
    let physical = &table.physical_name;
    let row_label_col = &table.row_label_col;

    let insert_cols = visible_cols
        .iter()
        .map(|c| format!("\"{}\"", c))
        .collect::<Vec<_>>()
        .join(", ");

    let insert_vals = visible_cols
        .iter()
        .map(|c| format!("NEW.\"{}\"", c))
        .collect::<Vec<_>>()
        .join(", ");

    let refesh_guard = r#"
        SELECT CASE
            WHEN (SELECT value FROM sec_meta WHERE key = 'generation')
               != (SELECT value FROM sec_meta WHERE key = 'last_refresh_generation')
            THEN RAISE(ABORT, 'security views are stale: call sec_refresh_views()')
        END;
        "#;

    let row_label_assignment = if table.insert_label_id.is_some() {
        format!(
            r#"COALESCE(
                (
                    SELECT insert_label_id
                    FROM sec_tables
                    WHERE logical_name = '{logical}'
                      AND insert_label_id IS NOT NULL
                      AND sec_row_visible(insert_label_id)
                ),
                (
                    SELECT table_label_id
                    FROM sec_tables
                    WHERE logical_name = '{logical}'
                ),
                1
            )"#
        )
    } else if let Some(table_label_id) = table.table_label_id {
        table_label_id.to_string()
    } else {
        "1".to_string()
    };

    let insert_guard = format!(
        r#"
        SELECT CASE
            WHEN NEW."{row_label_col}" IS NOT NULL
             AND (SELECT allow_explicit_label
                  FROM sec_tables
                  WHERE logical_name = '{logical}') = 0
            THEN RAISE(ABORT, 'explicit row_label_id not allowed')
        END;
        "#
    );

    let visibility_guard = format!(
        r#"
        SELECT CASE
            WHEN NEW."{row_label_col}" IS NOT NULL
             AND NOT sec_row_visible(NEW."{row_label_col}")
            THEN RAISE(ABORT, 'row_label_id not visible')
        END;
        "#
    );

    let insert_trigger = format!(
        r#"
        DROP TRIGGER IF EXISTS "{logical}_sec_ins";
        CREATE TEMP TRIGGER "{logical}_sec_ins"
        INSTEAD OF INSERT ON "{logical}"
        BEGIN
            {refesh_guard}
            {insert_guard}
            {visibility_guard}

            INSERT INTO "{physical}" ("{row_label_col}", {insert_cols})
            VALUES (
                {row_label_assignment},
                {insert_vals}
            );
        END;
        "#
    );

    let update_sets = visible_cols
        .iter()
        .map(|c| format!("\"{}\" = NEW.\"{}\"", c, c))
        .collect::<Vec<_>>()
        .join(", ");

    let pk_cols = get_primary_key_columns(conn, physical)?;

    if pk_cols.is_empty() {
        return Err(invalid(format!(
            "secured table '{physical}' must have a PRIMARY KEY"
        )));
    }

    let pk_where_old = {
        let prefix: &str = "OLD";
        let pk_cols: &[String] = &pk_cols;
        pk_cols
            .iter()
            .map(|c| format!("\"{}\" = {}.\"{}\"", c, prefix, c))
            .collect::<Vec<_>>()
            .join(" AND ")
    };

    let pk_guard = pk_cols
        .iter()
        .map(|c| format!("OLD.\"{}\" != NEW.\"{}\"", c, c))
        .collect::<Vec<_>>()
        .join(" OR ");
    let pk_guard = format!(
        r#"
            SELECT CASE WHEN {pk_guard}
                THEN RAISE(ABORT, 'cannot update primary key')
            END;
        "#
    );

    let label_guard = format!(
        r#"
        SELECT CASE
            WHEN NEW."{col}" != OLD."{col}"
            THEN RAISE(ABORT, 'cannot update row_label_id')
        END;
        "#,
        col = row_label_col
    );

    let update_trigger = format!(
        r#"
        DROP TRIGGER IF EXISTS "{logical}_sec_upd";
        CREATE TEMP TRIGGER "{logical}_sec_upd"
        INSTEAD OF UPDATE ON "{logical}"
        BEGIN
            {refesh_guard}
            {pk_guard}
            {label_guard}

            UPDATE "{physical}"
            SET {update_sets}
            WHERE {pk_where_old}
              AND sec_row_visible("{row_label_col}");
        END;
        "#
    );

    let delete_trigger = format!(
        r#"
        DROP TRIGGER IF EXISTS "{logical}_sec_del";
        CREATE TEMP TRIGGER "{logical}_sec_del"
        INSTEAD OF DELETE ON "{logical}"
        BEGIN
            {refesh_guard}

            DELETE FROM "{physical}"
            WHERE {pk_where_old}
              AND sec_row_visible("{row_label_col}");
        END;
        "#
    );

    conn.execute_batch(&insert_trigger)
        .map_err(|e| trigger_err(e, logical, "INSERT"))?;

    conn.execute_batch(&update_trigger)
        .map_err(|e| trigger_err(e, logical, "UPDATE"))?;

    conn.execute_batch(&delete_trigger)
        .map_err(|e| trigger_err(e, logical, "DELETE"))?;

    Ok(())
}
