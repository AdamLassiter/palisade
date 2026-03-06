use rusqlite::{Connection, Result, params};

use crate::helpers::TestRunner;

pub(crate) fn run_sqlsec_tests(t: &mut TestRunner, mode: &str) -> Result<()> {
    t.section("sqlsec Direct Function-Call Tests");

    let conn = Connection::open(":memory:")?;
    unsafe {
        conn.load_extension_enable()?;
        match conn.load_extension(format!("../sqlsec/target/{mode}/libsqlsec"), None::<&str>) {
            Ok(()) => t.ok("loaded sqlsec extension"),
            Err(e) => {
                t.fail("load sqlsec extension", &e);
                return Ok(());
            }
        }
        conn.load_extension_disable()?;
    }

    t.section("sqlsec Labels, Levels, and Visibility");
    let public_label: i64 = conn.query_row("SELECT sec_define_label('true')", [], |r| r.get(0))?;
    let admin_label: i64 =
        conn.query_row("SELECT sec_define_label('role=admin')", [], |r| r.get(0))?;
    let finance_label: i64 = conn.query_row(
        "SELECT sec_define_label('role=admin&team=finance')",
        [],
        |r| r.get(0),
    )?;
    if public_label > 0 && admin_label > 0 && finance_label > 0 {
        t.ok("sec_define_label created ids");
    } else {
        t.fail("sec_define_label", &"label ids must be > 0");
    }

    let defined_level: i64 = conn.query_row(
        "SELECT sec_define_level(?1, ?2, ?3)",
        params!["clearance", "secret", 2i64],
        |r| r.get(0),
    )?;
    t.assert_eq("sec_define_level return value", &defined_level, &2i64);

    let level_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sec_levels WHERE attr_name='clearance' AND level_name='secret' AND level_value=2",
        [],
        |r| r.get(0),
    )?;
    t.assert_eq("sec_levels row inserted", &level_count, &1i64);

    let _: i64 = conn.query_row(
        "SELECT sec_set_attr(?1, ?2)",
        params!["role", "user"],
        |r| r.get(0),
    )?;
    let visible_as_user: i64 =
        conn.query_row("SELECT sec_label_visible(?1)", params![admin_label], |r| {
            r.get(0)
        })?;
    t.assert_eq("admin label hidden from role=user", &visible_as_user, &0i64);

    let _: i64 = conn.query_row(
        "SELECT sec_set_attr(?1, ?2)",
        params!["role", "admin"],
        |r| r.get(0),
    )?;
    let visible_as_admin: i64 =
        conn.query_row("SELECT sec_label_visible(?1)", params![admin_label], |r| {
            r.get(0)
        })?;
    t.assert_eq(
        "admin label visible to role=admin",
        &visible_as_admin,
        &1i64,
    );

    t.section("sqlsec Register + Refresh + Staleness");
    conn.execute_batch(
        "CREATE TABLE __sec_docs (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            row_label_id INTEGER NOT NULL,
            amount INTEGER NOT NULL
         );",
    )?;

    conn.execute(
        "INSERT INTO __sec_docs (id, title, row_label_id, amount) VALUES (?1, ?2, ?3, ?4)",
        params![1i64, "public-doc", public_label, 10i64],
    )?;
    conn.execute(
        "INSERT INTO __sec_docs (id, title, row_label_id, amount) VALUES (?1, ?2, ?3, ?4)",
        params![2i64, "admin-doc", admin_label, 20i64],
    )?;
    t.ok("seeded __sec_docs rows");

    let registered: i64 = conn.query_row(
        "SELECT sec_register_table(?1, ?2, ?3, NULL, NULL)",
        params!["docs", "__sec_docs", "row_label_id"],
        |r| r.get(0),
    )?;
    t.assert_eq("sec_register_table", &registered, &1i64);

    let refreshed: i64 = conn.query_row("SELECT sec_refresh_views()", [], |r| r.get(0))?;
    t.assert_eq("sec_refresh_views", &refreshed, &1i64);

    let docs_as_admin: i64 = conn.query_row("SELECT COUNT(*) FROM docs", [], |r| r.get(0))?;
    t.assert_eq("docs visible as admin", &docs_as_admin, &2i64);

    let _: i64 = conn.query_row("SELECT sec_clear_context()", [], |r| r.get(0))?;
    let _: i64 = conn.query_row(
        "SELECT sec_set_attr(?1, ?2)",
        params!["role", "user"],
        |r| r.get(0),
    )?;
    match conn.query_row("SELECT sec_assert_fresh()", [], |r| r.get::<_, i64>(0)) {
        Ok(_) => t.fail(
            "sec_assert_fresh should fail when stale",
            &"expected SQLITE error",
        ),
        Err(_) => t.ok("sec_assert_fresh fails when generation changed"),
    }
    match conn.query_row("SELECT COUNT(*) FROM docs", [], |r| r.get::<_, i64>(0)) {
        Ok(_) => t.fail("stale docs read should fail", &"expected SQLITE error"),
        Err(_) => t.ok("docs view rejects stale reads before refresh"),
    }

    let refreshed: i64 = conn.query_row("SELECT sec_refresh_views()", [], |r| r.get(0))?;
    t.assert_eq("refresh after context change", &refreshed, &1i64);

    let user_can_read_admin_doc: i64 =
        conn.query_row("SELECT sec_label_visible(?1)", params![admin_label], |r| {
            r.get(0)
        })?;
    t.assert_eq(
        "user cannot read admin doc after refresh",
        &user_can_read_admin_doc,
        &0i64,
    );

    let docs_as_user: i64 = conn.query_row("SELECT COUNT(*) FROM docs", [], |r| r.get(0))?;
    t.assert_eq("docs visible as user", &docs_as_user, &1i64);

    t.section("sqlsec Context Stack");
    let _: i64 = conn.query_row("SELECT sec_push_context('temp')", [], |r| r.get(0))?;
    let _: i64 = conn.query_row(
        "SELECT sec_set_attr(?1, ?2)",
        params!["role", "admin"],
        |r| r.get(0),
    )?;
    let _: i64 = conn.query_row("SELECT sec_refresh_views()", [], |r| r.get(0))?;
    let docs_in_pushed_ctx: i64 = conn.query_row("SELECT COUNT(*) FROM docs", [], |r| r.get(0))?;
    t.assert_eq(
        "docs visible in pushed admin context",
        &docs_in_pushed_ctx,
        &2i64,
    );

    let _: i64 = conn.query_row("SELECT sec_pop_context()", [], |r| r.get(0))?;
    let _: i64 = conn.query_row("SELECT sec_refresh_views()", [], |r| r.get(0))?;
    let docs_after_pop: i64 = conn.query_row("SELECT COUNT(*) FROM docs", [], |r| r.get(0))?;
    t.assert_eq("docs visibility restored after pop", &docs_after_pop, &1i64);

    let _: i64 = conn.query_row("SELECT sec_clear_context()", [], |r| r.get(0))?;
    let _: i64 = conn.query_row("SELECT sec_refresh_views()", [], |r| r.get(0))?;
    let docs_after_clear: i64 = conn.query_row("SELECT COUNT(*) FROM docs", [], |r| r.get(0))?;
    t.assert_eq("docs visible after clear_context", &docs_after_clear, &1i64);

    Ok(())
}
