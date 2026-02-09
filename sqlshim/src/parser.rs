use crate::statement::*;

fn parse_operation(s: &str) -> PolicyOperation {
    match s.to_uppercase().as_str() {
        "SELECT" => PolicyOperation::Select,
        "INSERT" => PolicyOperation::Insert,
        "UPDATE" => PolicyOperation::Update,
        "DELETE" => PolicyOperation::Delete,
        _ => PolicyOperation::All,
    }
}

/// Attempt to parse a custom statement. Returns None if it's standard SQL.
pub fn parse(sql: &str) -> Option<CustomStatement> {
    let trimmed = sql.trim();
    let upper = trimmed.to_uppercase();

    // DEFINE LABEL 'expr'
    if upper.starts_with("DEFINE LABEL") {
        return parse_define_label(trimmed);
    }

    // DEFINE LEVEL attr 'name' = value
    if upper.starts_with("DEFINE LEVEL") {
        return parse_define_level(trimmed);
    }

    // CREATE POLICY
    if upper.starts_with("CREATE POLICY") {
        return parse_create_policy(trimmed);
    }

    // DROP POLICY
    if upper.starts_with("DROP POLICY") {
        return parse_drop_policy(trimmed);
    }

    // SET CONTEXT
    if upper.starts_with("SET CONTEXT") {
        return parse_set_context(trimmed);
    }

    // CLEAR CONTEXT
    if upper.starts_with("CLEAR CONTEXT") {
        return Some(CustomStatement::ClearContext);
    }

    // PUSH CONTEXT
    if upper.starts_with("PUSH CONTEXT") {
        return Some(CustomStatement::PushContext);
    }

    // POP CONTEXT
    if upper.starts_with("POP CONTEXT") {
        return Some(CustomStatement::PopContext);
    }

    // REFRESH SECURITY VIEWS
    if upper.starts_with("REFRESH SECURITY VIEWS") {
        return Some(CustomStatement::RefreshSecurityViews);
    }

    // REGISTER SECURE TABLE
    if upper.starts_with("REGISTER SECURE TABLE") {
        return parse_register_secure_table(trimmed);
    }

    // SET COLUMN SECURITY
    if upper.starts_with("SET COLUMN SECURITY") {
        return parse_set_column_security(trimmed);
    }

    // CREATE TENANT TABLE
    if upper.starts_with("CREATE TENANT TABLE") {
        return parse_create_tenant_table(trimmed);
    }

    // SET TENANT
    if upper.starts_with("SET TENANT") {
        return parse_set_tenant(trimmed);
    }

    // EXPORT TENANT
    if upper.starts_with("EXPORT TENANT") {
        return parse_export_tenant(trimmed);
    }

    // IMPORT TENANT
    if upper.starts_with("IMPORT TENANT") {
        return parse_import_tenant(trimmed);
    }

    // CREATE TEMPORAL TABLE
    if upper.starts_with("CREATE TEMPORAL TABLE") {
        return parse_create_temporal_table(trimmed);
    }

    // RESTORE table TO
    if upper.starts_with("RESTORE") && upper.contains(" TO ") {
        return parse_restore_table(trimmed);
    }

    // CREATE CHANGEFEED
    if upper.starts_with("CREATE CHANGEFEED") {
        return parse_create_changefeed(trimmed);
    }

    // DROP CHANGEFEED
    if upper.starts_with("DROP CHANGEFEED") {
        return parse_drop_changefeed(trimmed);
    }

    // ENCRYPT COLUMN
    if upper.starts_with("ENCRYPT COLUMN") {
        return parse_encrypt_column(trimmed);
    }

    // ROTATE ENCRYPTION KEY
    if upper.starts_with("ROTATE ENCRYPTION KEY") {
        return parse_rotate_key(trimmed);
    }

    // ENABLE AUDIT
    if upper.starts_with("ENABLE AUDIT") {
        return parse_enable_audit(trimmed);
    }

    // EXPLAIN POLICY
    if upper.starts_with("EXPLAIN POLICY") {
        return parse_explain_policy(trimmed);
    }

    None
}

fn extract_quoted_string(s: &str) -> Option<(&str, &str)> {
    let s = s.trim();
    if !s.starts_with('\'') {
        return None;
    }
    let rest = &s[1..];
    if let Some(end) = rest.find('\'') {
        Some((&rest[..end], &rest[end + 1..]))
    } else {
        None
    }
}

fn parse_define_label(sql: &str) -> Option<CustomStatement> {
    // DEFINE LABEL 'expr';
    let rest = sql
        .strip_prefix("DEFINE")
        .or_else(|| sql.strip_prefix("define"))?
        .trim()
        .strip_prefix("LABEL")
        .or_else(|| sql.trim()[6..].trim().strip_prefix("label"))?
        .trim();

    let (expr, _) = extract_quoted_string(rest)?;
    Some(CustomStatement::DefineLabel(DefineLabelStmt {
        expr: expr.to_string(),
    }))
}

fn parse_define_level(sql: &str) -> Option<CustomStatement> {
    // DEFINE LEVEL attr 'name' = value;
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("DEFINE LEVEL")? + 12..];
    let rest = rest.trim();

    // Get attribute name (first word)
    let attr_end = rest.find(|c: char| c.is_whitespace())?;
    let attr = &rest[..attr_end];
    let rest = rest[attr_end..].trim();

    // Get quoted name
    let (name, rest) = extract_quoted_string(rest)?;
    let rest = rest.trim();

    // Get = value
    let rest = rest.strip_prefix('=')?.trim();
    let value_str = rest.trim_end_matches(';').trim();
    let value: i64 = value_str.parse().ok()?;

    Some(CustomStatement::DefineLevelStmt(DefineLevelStmt {
        attribute: attr.to_string(),
        name: name.to_string(),
        value,
    }))
}

fn parse_create_policy(sql: &str) -> Option<CustomStatement> {
    // CREATE POLICY name ON table [FOR op] USING (expr);
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("CREATE POLICY")? + 13..];
    let rest = rest.trim();

    // Get policy name
    let name_end = rest.find(|c: char| c.is_whitespace())?;
    let name = &rest[..name_end];
    let rest = rest[name_end..].trim();

    // Skip ON
    let upper_rest = rest.to_uppercase();
    let rest = &rest[upper_rest.find("ON")? + 2..].trim();

    // Get table name
    let table_end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    let table = &rest[..table_end];
    let rest = rest[table_end..].trim();

    // Check for FOR clause
    let upper_rest = rest.to_uppercase();
    let (operation, rest) = if upper_rest.starts_with("FOR") {
        let rest = &rest[3..].trim();
        let op_end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
        let op_str = &rest[..op_end];
        let op = parse_operation(op_str);
        (Some(op), rest[op_end..].trim())
    } else {
        (None, rest)
    };

    // Find USING
    let upper_rest = rest.to_uppercase();
    let using_pos = upper_rest.find("USING")?;
    let rest = &rest[using_pos + 5..].trim();

    // Extract expression in parentheses
    let rest = rest.strip_prefix('(')?.trim();
    let paren_end = rest.rfind(')')?;
    let expr = &rest[..paren_end];

    Some(CustomStatement::CreatePolicy(CreatePolicyStmt {
        name: name.to_string(),
        table: table.to_string(),
        operation,
        using_expr: expr.trim().to_string(),
    }))
}

fn parse_drop_policy(sql: &str) -> Option<CustomStatement> {
    // DROP POLICY name ON table;
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("DROP POLICY")? + 11..];
    let rest = rest.trim();

    let name_end = rest.find(|c: char| c.is_whitespace())?;
    let name = &rest[..name_end];
    let rest = rest[name_end..].trim();

    let upper_rest = rest.to_uppercase();
    let rest = &rest[upper_rest.find("ON")? + 2..].trim();

    let table = rest.trim_end_matches(';').trim();

    Some(CustomStatement::DropPolicy(DropPolicyStmt {
        name: name.to_string(),
        table: table.to_string(),
    }))
}

fn parse_set_context(sql: &str) -> Option<CustomStatement> {
    // SET CONTEXT key = 'value';
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("SET CONTEXT")? + 11..];
    let rest = rest.trim();

    let eq_pos = rest.find('=')?;
    let key = rest[..eq_pos].trim();
    let rest = rest[eq_pos + 1..].trim();

    let (value, _) = extract_quoted_string(rest)?;

    Some(CustomStatement::SetContext(SetContextStmt {
        key: key.to_string(),
        value: value.to_string(),
    }))
}

fn parse_register_secure_table(sql: &str) -> Option<CustomStatement> {
    // REGISTER SECURE TABLE logical ON physical WITH ROW LABEL col [TABLE LABEL 'x'] [INSERT LABEL 'y'];
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("REGISTER SECURE TABLE")? + 21..];
    let rest = rest.trim();

    // logical name
    let logical_end = rest.find(|c: char| c.is_whitespace())?;
    let logical = &rest[..logical_end];
    let rest = rest[logical_end..].trim();

    // ON physical
    let upper_rest = rest.to_uppercase();
    let rest = &rest[upper_rest.find("ON")? + 2..].trim();
    let physical_end = rest.find(|c: char| c.is_whitespace())?;
    let physical = &rest[..physical_end];
    let rest = rest[physical_end..].trim();

    // WITH ROW LABEL col
    let upper_rest = rest.to_uppercase();
    let rest = &rest[upper_rest.find("WITH ROW LABEL")? + 14..].trim();
    let col_end = rest
        .find(|c: char| c.is_whitespace())
        .unwrap_or(rest.trim_end_matches(';').len());
    let row_label_col = rest[..col_end].trim_end_matches(';');
    let rest = rest[col_end..].trim();

    // Optional TABLE LABEL
    let upper_rest = rest.to_uppercase();
    let table_label = if let Some(pos) = upper_rest.find("TABLE LABEL") {
        let r = &rest[pos + 11..].trim();
        extract_quoted_string(r).map(|(s, _)| s.to_string())
    } else {
        None
    };

    // Optional INSERT LABEL
    let insert_label = if let Some(pos) = upper_rest.find("INSERT LABEL") {
        let r = &rest[pos + 12..].trim();
        extract_quoted_string(r).map(|(s, _)| s.to_string())
    } else {
        None
    };

    Some(CustomStatement::RegisterSecureTable(
        RegisterSecureTableStmt {
            logical_name: logical.to_string(),
            physical_name: physical.to_string(),
            row_label_column: row_label_col.to_string(),
            table_label,
            insert_label,
        },
    ))
}

fn parse_set_column_security(sql: &str) -> Option<CustomStatement> {
    // SET COLUMN SECURITY table.column READ 'x' UPDATE 'y';
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("SET COLUMN SECURITY")? + 19..];
    let rest = rest.trim();

    // table.column
    let dot_pos = rest.find('.')?;
    let table = &rest[..dot_pos];
    let rest = &rest[dot_pos + 1..];
    let col_end = rest.find(|c: char| c.is_whitespace())?;
    let column = &rest[..col_end];
    let rest = rest[col_end..].trim();

    let upper_rest = rest.to_uppercase();

    // READ label
    let read_label = if let Some(pos) = upper_rest.find("READ") {
        let r = &rest[pos + 4..].trim();
        extract_quoted_string(r).map(|(s, _)| s.to_string())
    } else {
        None
    };

    // UPDATE label
    let update_label = if let Some(pos) = upper_rest.find("UPDATE") {
        let r = &rest[pos + 6..].trim();
        extract_quoted_string(r).map(|(s, _)| s.to_string())
    } else {
        None
    };

    Some(CustomStatement::SetColumnSecurity(SetColumnSecurityStmt {
        table: table.to_string(),
        column: column.to_string(),
        read_label,
        update_label,
    }))
}

fn parse_create_tenant_table(sql: &str) -> Option<CustomStatement> {
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("CREATE TENANT TABLE")? + 19..];
    let rest = rest.trim();

    let paren_pos = rest.find('(')?;
    let name = rest[..paren_pos].trim();
    let rest = &rest[paren_pos + 1..];
    let end_paren = rest.rfind(')')?;
    let columns = &rest[..end_paren];

    Some(CustomStatement::CreateTenantTable(CreateTenantTableStmt {
        name: name.to_string(),
        columns: columns.to_string(),
    }))
}

fn parse_set_tenant(sql: &str) -> Option<CustomStatement> {
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("SET TENANT")? + 10..];
    let rest = rest.trim().strip_prefix('=')?.trim();
    let (tenant, _) = extract_quoted_string(rest)?;

    Some(CustomStatement::SetTenant(SetTenantStmt {
        tenant_id: tenant.to_string(),
    }))
}

fn parse_export_tenant(sql: &str) -> Option<CustomStatement> {
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("EXPORT TENANT")? + 13..];
    let rest = rest.trim();
    let (tenant, rest) = extract_quoted_string(rest)?;

    let upper_rest = rest.to_uppercase();
    let path = if let Some(pos) = upper_rest.find("TO") {
        let r = &rest[pos + 2..].trim();
        extract_quoted_string(r).map(|(s, _)| s.to_string())
    } else {
        None
    };

    Some(CustomStatement::ExportTenant(ExportTenantStmt {
        tenant_id: tenant.to_string(),
        path,
    }))
}

fn parse_import_tenant(sql: &str) -> Option<CustomStatement> {
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("IMPORT TENANT")? + 13..];
    let rest = rest.trim();
    let (tenant, rest) = extract_quoted_string(rest)?;

    let upper_rest = rest.to_uppercase();
    let path = if let Some(pos) = upper_rest.find("FROM") {
        let r = &rest[pos + 4..].trim();
        extract_quoted_string(r).map(|(s, _)| s.to_string())
    } else {
        None
    };

    Some(CustomStatement::ImportTenant(ImportTenantStmt {
        tenant_id: tenant.to_string(),
        path,
    }))
}

fn parse_create_temporal_table(sql: &str) -> Option<CustomStatement> {
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("CREATE TEMPORAL TABLE")? + 21..];
    let rest = rest.trim();

    let paren_pos = rest.find('(')?;
    let name = rest[..paren_pos].trim();
    let rest = &rest[paren_pos + 1..];
    let end_paren = rest.rfind(')')?;
    let columns = &rest[..end_paren];

    Some(CustomStatement::CreateTemporalTable(
        CreateTemporalTableStmt {
            name: name.to_string(),
            columns: columns.to_string(),
        },
    ))
}

fn parse_restore_table(sql: &str) -> Option<CustomStatement> {
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("RESTORE")? + 7..];
    let rest = rest.trim();

    let to_pos = rest.to_uppercase().find(" TO ")?;
    let table = rest[..to_pos].trim();
    let rest = &rest[to_pos + 4..].trim();

    let (timestamp, rest) = extract_quoted_string(rest)?;

    let upper_rest = rest.to_uppercase();
    let where_clause = upper_rest
        .find("WHERE")
        .map(|pos| rest[pos + 5..].trim().trim_end_matches(';').to_string());

    Some(CustomStatement::RestoreTable(RestoreTableStmt {
        table: table.to_string(),
        timestamp: timestamp.to_string(),
        where_clause,
    }))
}

fn parse_create_changefeed(sql: &str) -> Option<CustomStatement> {
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("CREATE CHANGEFEED")? + 17..];
    let rest = rest.trim();

    let on_pos = rest.to_uppercase().find(" ON ")?;
    let name = rest[..on_pos].trim();
    let rest = &rest[on_pos + 4..].trim();

    let upper_rest = rest.to_uppercase();
    let (table, filter) = if let Some(pos) = upper_rest.find("WHERE") {
        (
            rest[..pos].trim().to_string(),
            Some(rest[pos + 5..].trim().trim_end_matches(';').to_string()),
        )
    } else {
        (rest.trim_end_matches(';').trim().to_string(), None)
    };

    Some(CustomStatement::CreateChangefeed(CreateChangefeedStmt {
        name: name.to_string(),
        table,
        filter,
    }))
}

fn parse_drop_changefeed(sql: &str) -> Option<CustomStatement> {
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("DROP CHANGEFEED")? + 15..];
    let name = rest.trim().trim_end_matches(';').trim();

    Some(CustomStatement::DropChangefeed(DropChangefeedStmt {
        name: name.to_string(),
    }))
}

fn parse_encrypt_column(sql: &str) -> Option<CustomStatement> {
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("ENCRYPT COLUMN")? + 14..];
    let rest = rest.trim();

    let dot_pos = rest.find('.')?;
    let table = &rest[..dot_pos];
    let rest = &rest[dot_pos + 1..];

    let with_pos = rest.to_uppercase().find(" WITH ")?;
    let column = rest[..with_pos].trim();
    let rest = &rest[with_pos + 6..].trim();

    // KEY('name')
    let rest = rest
        .to_uppercase()
        .strip_prefix("KEY")
        .map(|_| &rest[3..])?
        .trim()
        .strip_prefix('(')?;
    let (key_name, _) = extract_quoted_string(rest)?;

    Some(CustomStatement::EncryptColumn(EncryptColumnStmt {
        table: table.to_string(),
        column: column.to_string(),
        key_name: key_name.to_string(),
    }))
}

fn parse_rotate_key(sql: &str) -> Option<CustomStatement> {
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("ROTATE ENCRYPTION KEY")? + 21..];
    let rest = rest.trim();

    let table = rest
        .to_uppercase()
        .find("FOR")
        .map(|pos| rest[pos + 3..].trim().trim_end_matches(';').to_string());

    Some(CustomStatement::RotateEncryptionKey(RotateKeyStmt {
        table,
    }))
}

fn parse_enable_audit(sql: &str) -> Option<CustomStatement> {
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("ENABLE AUDIT ON")? + 15..];
    let rest = rest.trim();

    let upper_rest = rest.to_uppercase();
    let (table, operations) = if let Some(pos) = upper_rest.find(" FOR ") {
        let table = rest[..pos].trim();
        let ops_str = rest[pos + 5..].trim().trim_end_matches(';');
        let ops: Vec<PolicyOperation> = ops_str
            .split(',')
            .map(|s| parse_operation(s.trim()))
            .collect();
        (table.to_string(), ops)
    } else {
        (
            rest.trim_end_matches(';').trim().to_string(),
            vec![PolicyOperation::All],
        )
    };

    Some(CustomStatement::EnableAudit(EnableAuditStmt {
        table,
        operations,
    }))
}

fn parse_explain_policy(sql: &str) -> Option<CustomStatement> {
    let upper = sql.to_uppercase();
    let rest = &sql[upper.find("EXPLAIN POLICY ON")? + 17..];
    let rest = rest.trim();

    let for_pos = rest.to_uppercase().find(" FOR ")?;
    let table = rest[..for_pos].trim();
    let rest = &rest[for_pos + 5..].trim();

    // USER = 'name'
    let eq_pos = rest.find('=')?;
    let rest = rest[eq_pos + 1..].trim();
    let (user, _) = extract_quoted_string(rest)?;

    Some(CustomStatement::ExplainPolicy(ExplainPolicyStmt {
        table: table.to_string(),
        user: user.to_string(),
    }))
}
