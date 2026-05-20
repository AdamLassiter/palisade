use std::mem::forget;

use rusqlite::{Connection, Error, Result};

use crate::{
    context::sec_ctx::SecurityContext,
    label::{CompareOp, LABEL_CACHE, LEVELS_CACHE, Label, parse::parse},
};

impl Label {
    pub fn evaluate(&self, ctx: &SecurityContext) -> bool {
        if self.always_true {
            return true;
        }

        self.clauses.iter().all(|clause| {
            clause.iter().any(|req| match req.op {
                CompareOp::Eq => ctx.has(&req.key, &req.value),
                _ => evaluate_comparison(ctx, &req.key, req.op, &req.value),
            })
        })
    }
}

fn evaluate_comparison(ctx: &SecurityContext, key: &str, op: CompareOp, required: &str) -> bool {
    let levels = LEVELS_CACHE.lock();
    let attr_levels = match levels.get(key) {
        Some(l) => l,
        None => return false, // No levels defined for this attr
    };

    let required_level = match attr_levels.get(required) {
        Some(l) => *l,
        None => return false, // Unknown level name
    };

    // Check if user has any value for this attr that satisfies the comparison
    ctx.get_attrs(key).iter().any(|user_value| {
        let user_level = match attr_levels.get(user_value.as_str()) {
            Some(l) => *l,
            None => return false,
        };

        match op {
            CompareOp::Eq => user_level == required_level,
            CompareOp::Ge => user_level >= required_level,
            CompareOp::Gt => user_level > required_level,
            CompareOp::Le => user_level <= required_level,
            CompareOp::Lt => user_level < required_level,
        }
    })
}

pub fn load_levels(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("SELECT attr_name, level_name, level_value FROM sec_levels")?;

    let mut cache = LEVELS_CACHE.lock();
    cache.clear();

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;

    for row in rows {
        let (attr, name, value) = row?;
        cache.entry(attr).or_default().insert(name, value);
    }

    Ok(())
}

pub fn evaluate_label_expr(expr: &str, ctx: &SecurityContext) -> Option<i64> {
    match parse(expr) {
        Ok(label) => {
            if label.evaluate(ctx) {
                Some(1)
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

pub fn evaluate_by_id_conn(
    conn: &Connection,
    label_id: i64,
    ctx: &SecurityContext,
) -> Result<bool> {
    if let Some(label) = LABEL_CACHE.lock().get(&label_id) {
        return Ok(label.evaluate(ctx));
    }

    let expr: String = conn.query_row(
        "SELECT expr FROM sec_labels WHERE id = ?1",
        [label_id],
        |r| r.get(0),
    )?;

    let label = parse(&expr).map_err(|_| Error::InvalidQuery)?;
    LABEL_CACHE.lock().insert(label_id, label.clone());

    Ok(label.evaluate(ctx))
}

pub fn evaluate_by_id(db_ptr: usize, label_id: i64, ctx: &SecurityContext) -> Result<bool> {
    let conn = unsafe { Connection::from_handle(db_ptr as *mut _)? };
    let result = evaluate_by_id_conn(&conn, label_id, ctx);
    forget(conn);
    result
}

pub fn is_visible_conn(conn: &Connection, label_id: Option<i64>, ctx: &SecurityContext) -> bool {
    match label_id {
        None => true,
        Some(id) => evaluate_by_id_conn(conn, id, ctx).unwrap_or(false),
    }
}

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
    fn evaluate_simple() {
        let label = parse("role=admin").unwrap();
        let mut ctx = SecurityContext::default();

        assert!(!label.evaluate(&ctx));

        ctx.set_attr("role", "admin");
        assert!(label.evaluate(&ctx));
    }

    #[test]
    fn evaluate_comparison() {
        // Setup levels
        {
            let mut cache = LEVELS_CACHE.lock();
            cache.clear();
            let mut clearance = std::collections::HashMap::new();
            clearance.insert("public".to_string(), 0);
            clearance.insert("confidential".to_string(), 1);
            clearance.insert("secret".to_string(), 2);
            clearance.insert("top_secret".to_string(), 3);
            cache.insert("clearance".to_string(), clearance);
        }

        let label = parse("clearance>=confidential").unwrap();

        let mut ctx = SecurityContext::default();
        ctx.set_attr("clearance", "public");
        assert!(!label.evaluate(&ctx)); // 0 >= 1 is false

        ctx.set_attr("clearance", "confidential");
        assert!(label.evaluate(&ctx)); // 1 >= 1

        ctx.set_attr("clearance", "secret");
        assert!(label.evaluate(&ctx)); // 2 >= 1

        ctx.set_attr("clearance", "top_secret");
        assert!(label.evaluate(&ctx)); // 3 >= 1
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
