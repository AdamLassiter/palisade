use std::{
    collections::HashMap,
    fs,
    thread,
    time::{Duration, Instant},
};

use rusqlite::Connection;

use crate::{
    db::{
        open_cluster_replica_conn,
        open_cluster_replica_raft_conn,
        open_validation_conn,
        validate_ciphertext,
    },
    types::{
        Aggregate,
        AppResult,
        CONVERGENCE_TIMEOUT,
        Config,
        Engine,
        NodeInfo,
        ReadSurface,
        Runtime,
        SharedOracle,
        ValidationReport,
    },
    util::table_name,
};

pub(crate) fn run_validation_with_retries(
    cfg: &Config,
    runtime: &Runtime,
    oracle: &SharedOracle,
    report: &mut ValidationReport,
) -> AppResult<()> {
    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    for _ in 0..10 {
        let mut candidate = ValidationReport::default();
        match validate_database(cfg, runtime, oracle, &mut candidate) {
            Ok(()) => {
                *report = candidate;
                return Ok(());
            }
            Err(err) => {
                let msg = err.to_string();
                if msg.contains("locked") || msg.contains("busy") {
                    last_err = Some(err);
                    thread::sleep(Duration::from_millis(250));
                    continue;
                }
                return Err(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| "validation failed".into()))
}

fn validate_database(
    cfg: &Config,
    runtime: &Runtime,
    oracle: &SharedOracle,
    report: &mut ValidationReport,
) -> AppResult<()> {
    let leader_conn = open_validation_conn(cfg, runtime, true)?;
    let expected = oracle.lock().map_err(|_| "oracle lock poisoned")?;
    let actual = collect_aggregate(&leader_conn, cfg.engine)?;

    let expected_accounts = (crate::types::TENANTS * crate::types::ACCOUNTS_PER_TENANT) as i64;
    if actual.account_count != expected_accounts {
        return Err(format!(
            "account count mismatch: expected {expected_accounts}, got {}",
            actual.account_count
        )
        .into());
    }
    report.ok(format!("account count = {}", actual.account_count));

    if actual.total_balance != expected.expected_total_balance() {
        return Err(format!(
            "total balance mismatch: expected {}, got {}",
            expected.expected_total_balance(),
            actual.total_balance
        )
        .into());
    }
    report.ok(format!(
        "total balance conserved at {}",
        actual.total_balance
    ));

    if actual.transfer_count != expected.transfer_count as i64 {
        return Err(format!(
            "transfer count mismatch: expected {}, got {}",
            expected.transfer_count, actual.transfer_count
        )
        .into());
    }
    report.ok(format!("transfer row count = {}", actual.transfer_count));

    if actual.audit_count != expected.audit_count as i64 {
        return Err(format!(
            "audit count mismatch: expected {}, got {}",
            expected.audit_count, actual.audit_count
        )
        .into());
    }
    report.ok(format!("audit row count = {}", actual.audit_count));
    drop(leader_conn);

    let validation_conn = open_validation_conn(cfg, runtime, true)?;
    let negative_balances: i64 = validation_conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM {} WHERE balance < 0",
            table_name(cfg.engine, "accounts", ReadSurface::Physical)
        ),
        [],
        |r| r.get(0),
    )?;
    if negative_balances != 0 {
        return Err(format!("found {negative_balances} negative balances").into());
    }
    report.ok("no negative balances");

    validate_order_states(&validation_conn, cfg.engine, &expected.orders)?;
    report.ok(format!("validated {} order states", expected.orders.len()));

    drop(expected);

    if cfg.engine.uses_evfs() {
        validate_ciphertext(&runtime.leader_db_path)?;
        report.ok("evfs ciphertext sanity check passed");
    }

    if cfg.engine.uses_cluster() {
        validate_cluster(cfg, runtime, actual)?;
        report.ok("raft convergence and follower write rejection passed");
    }

    Ok(())
}

fn validate_order_states(
    conn: &Connection,
    engine: Engine,
    expected_orders: &HashMap<i64, String>,
) -> AppResult<()> {
    let physical_orders = table_name(engine, "orders", ReadSurface::Physical);
    let mut stmt = conn.prepare(&format!(
        "SELECT id, status FROM {physical_orders} ORDER BY id"
    ))?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
    let actual: HashMap<i64, String> = rows.collect::<Result<_, _>>()?;
    if actual != *expected_orders {
        return Err("order state map mismatch".into());
    }
    Ok(())
}

fn validate_cluster(cfg: &Config, runtime: &Runtime, leader_actual: Aggregate) -> AppResult<()> {
    wait_for_replica_match(cfg, runtime, leader_actual)?;

    for follower in &runtime.followers {
        let before = collect_aggregate(&open_cluster_replica_conn(follower)?, cfg.engine)?;
        let write_err = probe_follower_write_rejection(cfg, follower)?;
        println!(
            "validation: follower {} rejected write probe: {}",
            follower.node_id, write_err
        );
        let wal_residue = follower_wal_residue_size(follower)?;
        println!(
            "validation: follower {} local wal residue {} bytes",
            follower.node_id, wal_residue
        );
        let after = collect_aggregate(&open_cluster_replica_conn(follower)?, cfg.engine)?;
        if !same_aggregate(before, after) {
            println!(
                "validation: follower {} aggregate changed before={:?} after={:?}",
                follower.node_id, before, after
            );
            return Err(format!(
                "follower {} unexpectedly changed state after a write attempt",
                follower.node_id
            )
            .into());
        }
        if wal_residue != 0 {
            return Err(format!(
                "follower {} left local WAL residue after rejected write: {} bytes",
                follower.node_id, wal_residue
            )
            .into());
        }
    }

    Ok(())
}

fn wait_for_replica_match(
    cfg: &Config,
    runtime: &Runtime,
    leader_actual: Aggregate,
) -> AppResult<()> {
    let deadline = Instant::now() + CONVERGENCE_TIMEOUT;
    loop {
        let mut all_match = true;
        for follower in &runtime.followers {
            let conn = open_cluster_replica_conn(follower)?;
            let agg = collect_aggregate(&conn, cfg.engine)?;
            if !same_aggregate(leader_actual, agg) {
                all_match = false;
                break;
            }
        }
        if all_match {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for followers to match leader aggregates".into());
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn same_aggregate(a: Aggregate, b: Aggregate) -> bool {
    a.account_count == b.account_count
        && a.transfer_count == b.transfer_count
        && a.order_count == b.order_count
        && a.audit_count == b.audit_count
        && a.total_balance == b.total_balance
        && a.transfer_amount_sum == b.transfer_amount_sum
        && a.balance_checksum == b.balance_checksum
}

fn collect_aggregate(conn: &Connection, engine: Engine) -> AppResult<Aggregate> {
    let physical_accounts = table_name(engine, "accounts", ReadSurface::Physical);
    let physical_orders = table_name(engine, "orders", ReadSurface::Physical);
    let physical_transfers = table_name(engine, "transfers", ReadSurface::Physical);
    let physical_audit = table_name(engine, "audit_log", ReadSurface::Physical);

    Ok(Aggregate {
        account_count: conn.query_row(
            &format!("SELECT COUNT(*) FROM {physical_accounts}"),
            [],
            |r| r.get(0),
        )?,
        transfer_count: conn.query_row(
            &format!("SELECT COUNT(*) FROM {physical_transfers}"),
            [],
            |r| r.get(0),
        )?,
        order_count: conn.query_row(
            &format!("SELECT COUNT(*) FROM {physical_orders}"),
            [],
            |r| r.get(0),
        )?,
        audit_count: conn.query_row(
            &format!("SELECT COUNT(*) FROM {physical_audit}"),
            [],
            |r| r.get(0),
        )?,
        total_balance: conn.query_row(
            &format!("SELECT COALESCE(SUM(balance), 0) FROM {physical_accounts}"),
            [],
            |r| r.get(0),
        )?,
        transfer_amount_sum: conn.query_row(
            &format!("SELECT COALESCE(SUM(amount), 0) FROM {physical_transfers}"),
            [],
            |r| r.get(0),
        )?,
        balance_checksum: conn.query_row(
            &format!("SELECT COALESCE(SUM(id * balance), 0) FROM {physical_accounts}"),
            [],
            |r| r.get(0),
        )?,
    })
}

fn probe_follower_write_rejection(cfg: &Config, follower: &NodeInfo) -> AppResult<String> {
    let conn = open_cluster_replica_raft_conn(follower)?;
    let table = table_name(cfg.engine, "accounts", ReadSurface::Physical);

    match conn.execute_batch("BEGIN IMMEDIATE;") {
        Ok(()) => {
            let write_result = conn.execute(
                &format!("UPDATE {table} SET balance = balance + 1 WHERE id = 1"),
                [],
            );
            let commit_result = match write_result {
                Ok(_) => conn.execute_batch("COMMIT;"),
                Err(_) => conn.execute_batch("ROLLBACK;"),
            };
            let _ = conn.execute_batch("ROLLBACK;");

            match (write_result, commit_result) {
                (Err(err), _) => Ok(err.to_string()),
                (Ok(_), Err(err)) => Ok(err.to_string()),
                (Ok(_), Ok(())) => Err(format!(
                    "follower {} unexpectedly committed write probe",
                    follower.node_id
                )
                .into()),
            }
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Ok(err.to_string())
        }
    }
}

fn follower_wal_residue_size(follower: &NodeInfo) -> AppResult<u64> {
    let wal_path = follower.db_path.with_extension("db-wal");
    match fs::metadata(&wal_path) {
        Ok(meta) => Ok(meta.len()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(err.into()),
    }
}
