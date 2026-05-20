use rusqlite::{Connection, Result};

use crate::{
    context::effective_context,
    label::evaluate::is_visible_conn,
    views::{SecTable, get_primary_key_columns, get_sec_columns, invalid},
};

pub fn create_write_triggers(
    conn: &Connection,
    table: &SecTable,
    visible_cols: &[&str],
) -> Result<()> {
    create_insert_trigger(conn, table, visible_cols)?;
    create_update_trigger(conn, table, visible_cols)?;
    create_delete_trigger(conn, table)?;

    Ok(())
}

fn create_delete_trigger(conn: &Connection, table: &SecTable) -> Result<(), rusqlite::Error> {
    let logical = &table.logical_name;
    let physical = &table.physical_name;
    let row_label_col = &table.row_label_col;

    let pk_cols = pk_cols(conn, physical)?;
    let pk_where_old = pk_where_old(&pk_cols);
    let pk_json_old = pk_json_expr("OLD", &pk_cols);
    let audit_success = audit_event_expr(
        table,
        "DELETE",
        "success",
        &pk_json_old,
        "NULL",
        &format!("OLD.\"{row_label_col}\""),
        "NULL",
    );

    let refesh_guard = refresh_guard();

    let delete_trigger = format!(
        r#"
        DROP TRIGGER IF EXISTS "{logical}_sec_del";
        CREATE TEMP TRIGGER "{logical}_sec_del"
        INSTEAD OF DELETE ON "{logical}"
        BEGIN
            {refesh_guard}

            DELETE FROM "{physical}"
            WHERE {pk_where_old}
              AND sec_label_visible("{row_label_col}");

            {audit_success}
        END;
        "#
    );

    conn.execute_batch(&delete_trigger)
        .map_err(|e| trigger_err(e, logical, "DELETE"))?;
    Ok(())
}

fn create_update_trigger(
    conn: &Connection,
    table: &SecTable,
    visible_cols: &[&str],
) -> Result<(), rusqlite::Error> {
    let logical = &table.logical_name;
    let physical = &table.physical_name;
    let row_label_col = &table.row_label_col;

    let update_sets = visible_cols
        .iter()
        .map(|c| format!("\"{}\" = NEW.\"{}\"", c, c))
        .collect::<Vec<_>>()
        .join(", ");

    let pk_cols = pk_cols(conn, physical)?;
    let pk_where_old = pk_where_old(&pk_cols);
    let pk_json_new = pk_json_expr("NEW", &pk_cols);
    let changed_columns_json = changed_columns_json_expr(visible_cols);

    let refresh_guard = refresh_guard();
    let update_pk_guard = update_pk_guard(pk_cols);
    let update_label_guard = update_label_guard(row_label_col);
    let column_policy_guards = column_update_policy_guards(conn, logical)?;
    let audit_success = audit_event_expr(
        table,
        "UPDATE",
        "success",
        &pk_json_new,
        &changed_columns_json,
        &format!("NEW.\"{row_label_col}\""),
        "NULL",
    );

    let update_trigger = format!(
        r#"
        DROP TRIGGER IF EXISTS "{logical}_sec_upd";
        CREATE TEMP TRIGGER "{logical}_sec_upd"
        INSTEAD OF UPDATE ON "{logical}"
        BEGIN
            {refresh_guard}
            {update_pk_guard}
            {update_label_guard}
            {column_policy_guards}

            UPDATE "{physical}"
            SET {update_sets}
            WHERE {pk_where_old}
              AND sec_label_visible("{row_label_col}");

            {audit_success}
        END;
        "#
    );

    conn.execute_batch(&update_trigger)
        .map_err(|e| trigger_err(e, logical, "UPDATE"))?;
    Ok(())
}

fn create_insert_trigger(
    conn: &Connection,
    table: &SecTable,
    visible_cols: &[&str],
) -> Result<(), rusqlite::Error> {
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
    let row_label_assignment = if table.insert_label_id.is_some() {
        format!(
            r#"COALESCE(
                (
                    SELECT insert_label_id
                    FROM sec_tables
                    WHERE logical_name = '{logical}'
                      AND insert_label_id IS NOT NULL
                      AND sec_label_visible(insert_label_id)
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

    let refesh_guard = refresh_guard();
    let implicit_label_guard = implicit_label_guard(logical, row_label_col);
    let label_visible_guard = label_visible_guard(row_label_col);
    let pk_cols = pk_cols(conn, physical)?;
    let pk_json_new = pk_json_expr("NEW", &pk_cols);
    let audit_success = audit_event_expr(
        table,
        "INSERT",
        "success",
        &pk_json_new,
        "NULL",
        &row_label_assignment,
        "NULL",
    );

    let insert_trigger = format!(
        r#"
        DROP TRIGGER IF EXISTS "{logical}_sec_ins";
        CREATE TEMP TRIGGER "{logical}_sec_ins"
        INSTEAD OF INSERT ON "{logical}"
        BEGIN
            {refesh_guard}
            {implicit_label_guard}
            {label_visible_guard}

            INSERT INTO "{physical}" ("{row_label_col}", {insert_cols})
            VALUES (
                {row_label_assignment},
                {insert_vals}
            );

            {audit_success}
        END;
        "#
    );

    conn.execute_batch(&insert_trigger)
        .map_err(|e| trigger_err(e, logical, "INSERT"))?;
    Ok(())
}

fn update_pk_guard(pk_cols: Vec<String>) -> String {
    let pk_updated = pk_cols
        .iter()
        .map(|col| format!("OLD.\"{col}\" != NEW.\"{col}\""))
        .collect::<Vec<_>>()
        .join(" OR ");
    format!(
        r#"
            SELECT CASE WHEN {pk_updated}
                THEN RAISE(ABORT, 'cannot update primary key')
            END;
        "#
    )
}

fn label_visible_guard(row_label_col: &String) -> String {
    format!(
        r#"
        SELECT CASE
            WHEN NEW."{row_label_col}" IS NOT NULL
             AND NOT sec_label_visible(NEW."{row_label_col}")
            THEN RAISE(ABORT, 'row_label_col {row_label_col} not visible')
        END;
        "#
    )
}

fn update_label_guard(row_label_col: &String) -> String {
    format!(
        r#"
        SELECT CASE
            WHEN NEW."{row_label_col}" != OLD."{row_label_col}"
            THEN RAISE(ABORT, 'cannot update raw_label_col {row_label_col}')
        END;
        "#,
    )
}

fn implicit_label_guard(logical: &String, row_label_col: &String) -> String {
    format!(
        r#"
        SELECT CASE
            WHEN NEW."{row_label_col}" IS NULL
             AND (SELECT allow_implicit_label
                  FROM sec_tables
                  WHERE logical_name = '{logical}') = 0
            THEN RAISE(ABORT, 'implicit row_label_col {row_label_col} not allowed')
        END;
        "#
    )
}

fn refresh_guard() -> &'static str {
    (r#"
    SELECT CASE
        WHEN (SELECT value FROM sec_meta WHERE key = 'generation')
          != (SELECT value FROM sec_meta WHERE key = 'last_refresh_generation')
        THEN RAISE(ABORT, 'security views are stale: call sec_refresh_views()')
    END;
    "#) as _
}

fn pk_cols(conn: &Connection, physical: &String) -> Result<Vec<String>, rusqlite::Error> {
    let pk_cols = get_primary_key_columns(conn, physical)?;
    if pk_cols.is_empty() {
        return Err(invalid(format!(
            "secured table '{physical}' must have a PRIMARY KEY"
        )));
    }
    Ok(pk_cols)
}

fn pk_where_old(pk_cols: &[String]) -> String {
    let pk_cols: &[String] = pk_cols;
    pk_cols
        .iter()
        .map(|col| format!("\"{col}\" = OLD.\"{col}\""))
        .collect::<Vec<_>>()
        .join(" AND ")
}

fn trigger_err(err: rusqlite::Error, table: &str, kind: &str) -> rusqlite::Error {
    rusqlite::Error::UserFunctionError(Box::new(std::io::Error::other(format!(
        "failed to create {} trigger for table '{}': {}",
        kind, table, err
    ))))
}

fn column_update_policy_guards(
    conn: &Connection,
    logical: &str,
) -> Result<String, rusqlite::Error> {
    let mut guards = Vec::new();

    let ctx = effective_context(unsafe { conn.handle() as usize });
    let all_columns = get_sec_columns(conn, logical)?;

    // Generate guards for columns that have a policy AND the user doesn't satisfy it
    let protected_columns = all_columns
        .iter()
        .filter(|c| c.update_label_id.is_some() && !is_visible_conn(conn, c.update_label_id, &ctx));

    for col in protected_columns {
        let col_name = &col.column_name;
        guards.push(format!(
            r#"
            SELECT CASE
                WHEN OLD."{col_name}" IS NOT NEW."{col_name}"
                THEN RAISE(ABORT, 'update denied on column {col_name}')
            END;
            "#
        ));
    }

    Ok(guards.join("\n"))
}

fn audit_event_expr(
    table: &SecTable,
    operation: &str,
    outcome: &str,
    row_pk_json: &str,
    changed_columns_json: &str,
    row_label_id: &str,
    error: &str,
) -> String {
    format!(
        "SELECT sec_audit_event({}, {}, {}, {}, {row_pk_json}, {changed_columns_json}, {row_label_id}, {error});",
        sql_string_literal(&table.logical_name),
        sql_string_literal(&table.physical_name),
        sql_string_literal(operation),
        sql_string_literal(outcome),
    )
}

fn pk_json_expr(prefix: &str, pk_cols: &[String]) -> String {
    let args = pk_cols
        .iter()
        .flat_map(|col| [sql_string_literal(col), format!("{prefix}.\"{col}\"")])
        .collect::<Vec<_>>()
        .join(", ");
    format!("json_object({args})")
}

fn changed_columns_json_expr(cols: &[&str]) -> String {
    if cols.is_empty() {
        return "'[]'".to_string();
    }

    let pieces = cols
        .iter()
        .map(|col| {
            format!(
                "CASE WHEN OLD.\"{col}\" IS NOT NEW.\"{col}\" THEN {} ELSE '' END",
                sql_string_literal(&format!(",\"{}\"", json_string_escape(col)))
            )
        })
        .collect::<Vec<_>>()
        .join(" || ");

    format!("'[' || substr(({pieces}), 2) || ']'")
}

fn sql_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn json_string_escape(value: &str) -> String {
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
