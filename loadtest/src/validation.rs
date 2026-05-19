use std::{
    collections::HashMap,
    fs,
    thread,
    time::{Duration, Instant},
};

use rusqlite::Connection;

use crate::{
    db::{
        is_lock_or_busy,
        open_cluster_replica_conn,
        open_cluster_replica_raft_conn,
        open_evfs_control_conn,
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
        RaftStatusDoc,
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
                if is_lock_or_busy(&msg) {
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
        validate_cluster(cfg, runtime, actual, report)?;
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

fn validate_cluster(
    cfg: &Config,
    runtime: &Runtime,
    leader_actual: Aggregate,
    report: &mut ValidationReport,
) -> AppResult<()> {
    let convergence_elapsed = wait_for_replica_match(cfg, runtime, leader_actual)?;
    report.ok(format!(
        "raft replicas converged in {:.2}s",
        convergence_elapsed.as_secs_f64()
    ));
    report_raft_stats(runtime, report)?;

    for follower in &runtime.followers {
        let before = collect_aggregate(&open_cluster_replica_conn(follower)?, cfg.engine)?;
        let probe_started = Instant::now();
        let write_err = probe_follower_write_rejection(cfg, follower)?;
        let probe_elapsed = probe_started.elapsed();
        report.ok(format!(
            "follower {} rejected write probe in {:.3}ms: {}",
            follower.node_id,
            probe_elapsed.as_secs_f64() * 1000.0,
            write_err
        ));
        let wal_residue = follower_wal_residue_size(follower)?;
        report.ok(format!(
            "follower {} local wal residue {} bytes",
            follower.node_id, wal_residue
        ));
        let after = collect_aggregate(&open_cluster_replica_conn(follower)?, cfg.engine)?;
        if !same_aggregate(before, after) {
            return Err(format!(
                "follower {} unexpectedly changed state after a write attempt: before={before:?} after={after:?}",
                follower.node_id,
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

fn report_raft_stats(runtime: &Runtime, report: &mut ValidationReport) -> AppResult<()> {
    let status_conn = open_evfs_control_conn(&runtime.leader_db_path, &runtime.libs)?;
    let status = read_raft_status(&status_conn)?;
    let leader_raft_vfs = runtime
        .leader_raft_vfs_name
        .as_deref()
        .ok_or("missing leader raft vfs for cluster validation")?;
    if let Some(leader) = status
        .nodes
        .iter()
        .find(|node| node.raft_vfs_name == leader_raft_vfs)
    {
        report.ok(format!(
            "raft submit syncs={} records={} frames={} avg_submit={:.3}ms max_submit={:.3}ms last_records={} last_frames={} last_submit={:.3}ms",
            leader.submit.submit_syncs,
            leader.submit.submit_records,
            leader.submit.submit_frames,
            avg_ms(leader.submit.submit_micros, leader.submit.submit_syncs),
            leader.submit.max_submit_micros as f64 / 1000.0,
            leader.submit.last_submit_records,
            leader.submit.last_submit_frames,
            leader.submit.last_submit_micros as f64 / 1000.0
        ));
        report.ok(format!(
            "raft leader xSync calls={} avg_total={:.3}ms avg_inner_sync={:.3}ms avg_drain={:.3}ms last_total={:.3}ms last_inner_sync={:.3}ms last_drain={:.3}ms",
            leader.submit.xsync_calls,
            avg_ms(leader.submit.xsync_micros, leader.submit.xsync_calls),
            avg_ms(leader.submit.xsync_inner_micros, leader.submit.xsync_calls),
            avg_ms(leader.submit.xsync_drain_micros, leader.submit.xsync_calls),
            leader.submit.last_xsync_micros as f64 / 1000.0,
            leader.submit.last_xsync_inner_micros as f64 / 1000.0,
            leader.submit.last_xsync_drain_micros as f64 / 1000.0
        ));
    }

    for follower in &runtime.followers {
        if let Some(node) = status
            .nodes
            .iter()
            .find(|node| node.raft_vfs_name == follower.raft_vfs_name)
        {
            report.ok(format!(
                "follower {} replay batches={} records={} frames={} wal_sync_policy={} wal_syncs={} last_batch_records={} last_apply={:.3}ms",
                follower.node_id,
                node.replay.applied_batches,
                node.replay.applied_records,
                node.replay.applied_frames,
                replay_wal_sync_policy(node),
                node.replay.wal_syncs,
                node.replay.last_batch_records,
                node.replay.last_apply_micros as f64 / 1000.0
            ));
            report.ok(format!(
                "follower {} replay apply timing avg_wal_write={:.3}ms avg_wal_sync={:.3}ms last_wal_write={:.3}ms last_wal_sync={:.3}ms last_wal_synced_offset={} pending_wal_sync_batches={} coalesced_wal_syncs={} avg_sync_batches={:.2} last_sync_batches={} avg_sync_delay={:.3}ms last_sync_delay={:.3}ms{}",
                follower.node_id,
                avg_ms(node.replay.wal_write_micros, node.replay.applied_batches),
                avg_ms(node.replay.wal_sync_micros, node.replay.wal_syncs),
                node.replay.last_wal_write_micros as f64 / 1000.0,
                node.replay.last_wal_sync_micros as f64 / 1000.0,
                node.replay.last_wal_synced_offset,
                node.replay.pending_wal_sync_batches,
                node.replay.coalesced_wal_syncs,
                avg_count(node.replay.wal_sync_batches, node.replay.wal_syncs),
                node.replay.last_wal_sync_batches,
                avg_ms(node.replay.wal_sync_delay_micros, node.replay.wal_syncs),
                node.replay.last_wal_sync_delay_micros as f64 / 1000.0,
                node.replay
                    .last_wal_sync_error
                    .as_ref()
                    .map(|err| format!(" last_wal_sync_error={err}"))
                    .unwrap_or_default()
            ));
            report.ok(format!(
                "follower {} materialization batches={} frames={} db_syncs={} queue_depth={} errors={} last_offset={} avg_db_write={:.3}ms avg_db_sync={:.3}ms avg_shm={:.3}ms last_db_write={:.3}ms last_db_sync={:.3}ms last_shm={:.3}ms{}",
                follower.node_id,
                node.replay.materialize_batches,
                node.replay.materialize_frames,
                node.replay.db_syncs,
                node.replay.materialize_queue_depth,
                node.replay.materialize_errors,
                node.replay.last_materialized_offset,
                avg_ms(node.replay.materialize_db_write_micros, node.replay.materialize_batches),
                avg_ms(node.replay.materialize_db_sync_micros, node.replay.db_syncs),
                avg_ms(
                    node.replay.materialize_shm_invalidate_micros,
                    node.replay.materialize_batches
                ),
                node.replay.last_materialize_db_write_micros as f64 / 1000.0,
                node.replay.last_materialize_db_sync_micros as f64 / 1000.0,
                node.replay.last_materialize_shm_invalidate_micros as f64 / 1000.0,
                node.replay
                    .last_materialize_error
                    .as_ref()
                    .map(|err| format!(" last_error={err}"))
                    .unwrap_or_default()
            ));
        }
    }

    Ok(())
}

fn avg_ms(total_micros: u64, count: u64) -> f64 {
    if count == 0 {
        0.0
    } else {
        total_micros as f64 / count as f64 / 1000.0
    }
}

fn avg_count(total: u64, count: u64) -> f64 {
    if count == 0 {
        0.0
    } else {
        total as f64 / count as f64
    }
}

fn replay_wal_sync_policy(node: &crate::types::RaftNodeStatus) -> &str {
    if node.replay.wal_sync_policy.is_empty() {
        "per-batch"
    } else {
        &node.replay.wal_sync_policy
    }
}

fn wait_for_replica_match(
    cfg: &Config,
    runtime: &Runtime,
    leader_actual: Aggregate,
) -> AppResult<Duration> {
    let started = Instant::now();
    let deadline = Instant::now() + CONVERGENCE_TIMEOUT;
    let status_conn = open_evfs_control_conn(&runtime.leader_db_path, &runtime.libs)?;
    let leader_raft_vfs = runtime
        .leader_raft_vfs_name
        .as_deref()
        .ok_or("missing leader raft vfs for cluster validation")?;
    let follower_vfs_names = runtime
        .followers
        .iter()
        .map(|follower| follower.raft_vfs_name.as_str())
        .collect::<Vec<_>>();
    let mut last_mismatch = "no replica comparison attempted".to_string();

    loop {
        let status = read_raft_status(&status_conn)?;
        let last_status = replay_status_summary(&status, leader_raft_vfs, &follower_vfs_names);

        if replicas_replayed_and_materialized_to_leader(
            &status,
            leader_raft_vfs,
            &follower_vfs_names,
        )? {
            let mut all_match = true;
            for follower in &runtime.followers {
                match collect_aggregate(&open_cluster_replica_conn(follower)?, cfg.engine) {
                    Ok(agg) if same_aggregate(leader_actual, agg) => {}
                    Ok(agg) => {
                        all_match = false;
                        last_mismatch = format!(
                            "follower {} aggregate mismatch: leader={leader_actual:?} follower={agg:?}",
                            follower.node_id
                        );
                        break;
                    }
                    Err(err) => {
                        all_match = false;
                        last_mismatch =
                            format!("follower {} aggregate read failed: {err}", follower.node_id);
                        break;
                    }
                }
            }
            if all_match {
                return Ok(started.elapsed());
            }
        }

        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for followers to match leader aggregates; {last_status}; {last_mismatch}"
            )
            .into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn read_raft_status(conn: &Connection) -> AppResult<RaftStatusDoc> {
    let status: String = conn.query_row("SELECT evfs_raft_status()", [], |r| r.get(0))?;
    Ok(serde_json::from_str(&status)?)
}

fn replicas_replayed_and_materialized_to_leader(
    status: &RaftStatusDoc,
    leader_raft_vfs: &str,
    follower_vfs_names: &[&str],
) -> AppResult<bool> {
    let leader_offset = status
        .nodes
        .iter()
        .find(|node| node.raft_vfs_name == leader_raft_vfs)
        .ok_or_else(|| format!("raft status missing leader vfs {leader_raft_vfs}"))?
        .committed_wal_offset as i64;

    for follower_vfs in follower_vfs_names {
        let follower = status
            .nodes
            .iter()
            .find(|node| node.raft_vfs_name == *follower_vfs)
            .ok_or_else(|| format!("raft status missing follower vfs {follower_vfs}"))?;
        if follower.replay.materialize_errors != 0 {
            return Err(format!(
                "follower {follower_vfs} materialization failed: {}",
                follower
                    .replay
                    .last_materialize_error
                    .as_deref()
                    .unwrap_or("unknown materialization error")
            )
            .into());
        }
        if follower.replay.last_applied_offset < leader_offset {
            return Ok(false);
        }
        if replay_wal_sync_policy(follower) == "per-batch"
            && follower.replay.last_wal_synced_offset < leader_offset
        {
            return Ok(false);
        }
        if follower.replay.last_materialized_offset < leader_offset {
            return Ok(false);
        }
    }

    Ok(true)
}

fn replay_status_summary(
    status: &RaftStatusDoc,
    leader_raft_vfs: &str,
    follower_vfs_names: &[&str],
) -> String {
    let leader_offset = status
        .nodes
        .iter()
        .find(|node| node.raft_vfs_name == leader_raft_vfs)
        .map(|node| node.committed_wal_offset as i64);
    let followers = follower_vfs_names
        .iter()
        .map(|follower_vfs| {
            let offsets = status
                .nodes
                .iter()
                .find(|node| node.raft_vfs_name == *follower_vfs)
                .map(|node| {
                    (
                        node.replay.last_applied_offset,
                        node.replay.last_wal_synced_offset,
                        node.replay.last_materialized_offset,
                        node.replay.materialize_queue_depth,
                        node.replay.pending_wal_sync_batches,
                    )
                });
            format!("{follower_vfs}=apply/wal_synced/materialized/materialize_queue/wal_pending={offsets:?}")
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "leader {leader_raft_vfs} committed={leader_offset:?}; follower replay/materialization {followers}"
    )
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
    conn.busy_handler(Some(|_| false))?;
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
