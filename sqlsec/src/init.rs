use std::mem::forget;

use rusqlite::{Connection, Result, ffi::sqlite3};

use crate::register::register_functions_ffi;

/// Initialize the database objects when extension loads via FFI.
pub(crate) unsafe fn init_extension_ffi(db: *mut sqlite3) -> Result<()> {
    let conn = unsafe { Connection::from_handle(db) }?;

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS sec_labels (
            id   INTEGER PRIMARY KEY,
            expr TEXT NOT NULL UNIQUE
        );

        CREATE TABLE IF NOT EXISTS sec_levels (
            attr_name   TEXT NOT NULL,
            level_name  TEXT NOT NULL,
            level_value INTEGER NOT NULL,
            PRIMARY KEY (attr_name, level_name)
        );

        CREATE TABLE IF NOT EXISTS sec_tables (
            logical_name   TEXT PRIMARY KEY,
            physical_name  TEXT NOT NULL,
            row_label_col  TEXT NOT NULL,
            table_label_id INTEGER REFERENCES sec_labels(id),
            insert_label_id INTEGER REFERENCES sec_labels(id),
            allow_implicit_label INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS sec_columns (
            logical_table   TEXT NOT NULL,
            column_name     TEXT NOT NULL,
            read_label_id   INTEGER REFERENCES sec_labels(id),
            update_label_id INTEGER REFERENCES sec_labels(id),
            PRIMARY KEY (logical_table, column_name)
        );

        CREATE TABLE IF NOT EXISTS sec_meta (
            key   TEXT PRIMARY KEY,
            value INTEGER
        );

        CREATE TABLE IF NOT EXISTS sec_audit_config (
            logical_table TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 1,
            audit_insert INTEGER NOT NULL DEFAULT 1,
            audit_update INTEGER NOT NULL DEFAULT 1,
            audit_delete INTEGER NOT NULL DEFAULT 1,
            include_context INTEGER NOT NULL DEFAULT 1,
            include_changed_columns INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS sec_audit_log (
            id INTEGER PRIMARY KEY,
            occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            logical_table TEXT NOT NULL,
            physical_table TEXT NOT NULL,
            operation TEXT NOT NULL,
            outcome TEXT NOT NULL,
            row_pk_json TEXT,
            changed_columns_json TEXT,
            context_json TEXT NOT NULL,
            row_label_id INTEGER,
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_sec_audit_log_table_time
            ON sec_audit_log(logical_table, occurred_at);
        CREATE INDEX IF NOT EXISTS idx_sec_audit_log_operation
            ON sec_audit_log(operation, outcome);

        INSERT OR IGNORE INTO sec_meta VALUES ('generation', 0);
        INSERT OR IGNORE INTO sec_meta VALUES ('last_refresh_generation', 0);
        INSERT OR IGNORE INTO sec_meta VALUES ('views_initialized', 0);
        "#,
    )?;

    // Ensure we don’t close SQLite’s internal handle
    forget(conn);

    // Register scalar functions
    register_functions_ffi(db);

    Ok(())
}
