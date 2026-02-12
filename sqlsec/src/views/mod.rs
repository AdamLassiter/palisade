pub mod bump_generation;
pub mod refresh_views;
pub mod register_table;
pub mod write_triggers;

use std::io::ErrorKind;

use rusqlite::{Connection, Error, Result};

#[derive(Debug)]
pub struct SecTable {
    logical_name: String,
    physical_name: String,
    row_label_col: String,
    table_label_id: Option<i64>,
    insert_label_id: Option<i64>,
}

#[derive(Debug)]
pub struct SecColumn {
    column_name: String,
    read_label_id: Option<i64>,
    update_label_id: Option<i64>,
}

fn get_physical_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info(\"{}\")", table))?;
    let cols = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>>>()?;

    if cols.is_empty() {
        return Err(invalid(format!(
            "table '{table}' does not exist",
        )));
    }

    Ok(cols)
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

fn get_sec_columns(conn: &Connection, logical_table: &str) -> Result<Vec<SecColumn>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT column_name, read_label_id, update_label_id
        FROM sec_columns
        WHERE logical_table = ?1
        "#,
    )?;

    let cols = stmt
        .query_map([logical_table], |row| {
            Ok(SecColumn {
                column_name: row.get(0)?,
                read_label_id: row.get(1)?,
                update_label_id: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>>>()?;

    Ok(cols)
}

fn get_sec_tables(conn: &Connection) -> Result<Vec<SecTable>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT logical_name, physical_name, row_label_col, table_label_id, insert_label_id
        FROM sec_tables
        "#,
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
