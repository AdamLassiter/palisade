use rusqlite::{Connection, Result};

use crate::{context::SecurityContext, get_context, label};

#[derive(Debug)]
struct SecTable {
    logical_name: String,
    physical_name: String,
    row_label_col: String,
    table_label_id: Option<i64>,
}

#[derive(Debug)]
struct SecColumn {
    column_name: String,
    label_id: Option<i64>,
}

/// Register a table using Connection reference
pub fn register_table(
    conn: &Connection,
    logical: &str,
    physical: &str,
    row_label_col: &str,
    table_label_id: Option<i64>,
) -> Result<()> {
    conn.execute(
        r#"
        INSERT OR REPLACE INTO sec_tables 
        (logical_name, physical_name, row_label_col, table_label_id)
        VALUES (?1, ?2, ?3, ?4)
        "#,
        rusqlite::params![logical, physical, row_label_col, table_label_id],
    )?;

    // Auto-populate sec_columns from physical table schema
    let cols = get_physical_columns(conn, physical)?;
    for col in cols {
        if col != row_label_col {
            conn.execute(
                r#"
                INSERT OR IGNORE INTO sec_columns (logical_table, column_name, label_id)
                VALUES (?1, ?2, NULL)
                "#,
                rusqlite::params![logical, col],
            )?;
        }
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
) -> Result<()> {
    let conn = unsafe { Connection::from_handle(db_ptr as *mut _)? };
    let result = register_table(&conn, logical, physical, row_label_col, table_label_id);
    std::mem::forget(conn);
    result
}

fn get_physical_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info(\"{}\")", table))?;
    let cols = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>>>()?;
    Ok(cols)
}

/// Refresh views using Connection reference
pub fn refresh_views(conn: &Connection, ctx: &SecurityContext) -> Result<()> {
    let tables = load_sec_tables(conn)?;

    for table in tables {
        refresh_single_view(conn, &table, ctx)?;
    }

    Ok(())
}

/// Refresh views from raw pointer (for FFI)
pub fn refresh_views_raw(db_ptr: usize) -> Result<()> {
    let conn = unsafe { Connection::from_handle(db_ptr as *mut _)? };
    let ctx = get_context(db_ptr);
    let result = refresh_views(&conn, &ctx);
    std::mem::forget(conn);
    result
}

fn load_sec_tables(conn: &Connection) -> Result<Vec<SecTable>> {
    let mut stmt = conn.prepare(
        "SELECT logical_name, physical_name, row_label_col, table_label_id FROM sec_tables",
    )?;

    let tables = stmt
        .query_map([], |row| {
            Ok(SecTable {
                logical_name: row.get(0)?,
                physical_name: row.get(1)?,
                row_label_col: row.get(2)?,
                table_label_id: row.get(3)?,
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

    let insert_trigger = format!(
        r#"
        DROP TRIGGER IF EXISTS "{logical}_sec_ins";
        CREATE TEMP TRIGGER "{logical}_sec_ins"
        INSTEAD OF INSERT ON "{logical}"
        BEGIN
            INSERT INTO "{physical}" ("{row_label_col}", {insert_cols})
            VALUES (
                COALESCE(NEW."{row_label_col}", 1),
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

    let update_trigger = format!(
        r#"
        DROP TRIGGER IF EXISTS "{logical}_sec_upd";
        CREATE TEMP TRIGGER "{logical}_sec_upd"
        INSTEAD OF UPDATE ON "{logical}"
        BEGIN
            UPDATE "{physical}"
            SET {update_sets}
            WHERE rowid = OLD.rowid
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
            DELETE FROM "{physical}"
            WHERE rowid = OLD.rowid
              AND sec_row_visible("{row_label_col}");
        END;
        "#
    );

    conn.execute_batch(&insert_trigger)?;
    conn.execute_batch(&update_trigger)?;
    conn.execute_batch(&delete_trigger)?;

    Ok(())
}
