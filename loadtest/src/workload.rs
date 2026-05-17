use std::{
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};

use rusqlite::{OptionalExtension, params};

use crate::{
    db::{apply_context, configure_worker_conn, open_worker_conn, refresh_views},
    types::{
        AppResult,
        Config,
        ReadSurface,
        Role,
        Runtime,
        SharedCounter,
        SharedOracle,
        SimpleRng,
        WorkerMetrics,
    },
    util::{random_account_id, table_name, tenant_name, transition_for_rng, worker_spec},
};

pub(crate) fn run_workers(
    cfg: &Config,
    runtime: &Runtime,
    oracle: SharedOracle,
    next_order_id: SharedCounter,
    next_transfer_id: SharedCounter,
    next_audit_id: SharedCounter,
) -> AppResult<WorkerMetrics> {
    let end_at = Instant::now() + cfg.duration;
    let mut joins = Vec::with_capacity(cfg.workers);

    for worker_id in 0..cfg.workers {
        let worker_cfg = cfg.clone();
        let labels = runtime.labels.clone();
        let leader_db_path = runtime.leader_db_path.clone();
        let raft_vfs = if cfg.engine.uses_cluster() {
            Some("evfs_raft_node1".to_string())
        } else {
            None
        };
        let worker_oracle = oracle.clone();
        let worker_next_order_id = next_order_id.clone();
        let worker_next_transfer_id = next_transfer_id.clone();
        let worker_next_audit_id = next_audit_id.clone();
        let use_shim_syntax = runtime.use_shim_syntax;

        joins.push(thread::spawn(move || -> AppResult<WorkerMetrics> {
            let spec = worker_spec(worker_id);
            let mut rng = SimpleRng::new(worker_cfg.seed ^ ((worker_id as u64 + 1) * 0x9E37));
            let mut conn = open_worker_conn(&worker_cfg, &leader_db_path, raft_vfs.as_deref())?;
            configure_worker_conn(&conn)?;

            let mut metrics = WorkerMetrics::default();
            let effective_ramp = if worker_cfg.ramp > worker_cfg.duration {
                Duration::from_secs_f64(worker_cfg.duration.as_secs_f64() / 2.0)
            } else {
                worker_cfg.ramp
            };
            if effective_ramp.as_millis() > 0 {
                let stagger_ms = effective_ramp.as_millis() as u64 * worker_id as u64
                    / worker_cfg.workers as u64;
                thread::sleep(Duration::from_millis(stagger_ms));
            }

            let physical_accounts =
                table_name(worker_cfg.engine, "accounts", ReadSurface::Physical);
            let physical_orders = table_name(worker_cfg.engine, "orders", ReadSurface::Physical);
            let physical_transfers =
                table_name(worker_cfg.engine, "transfers", ReadSurface::Physical);
            let physical_audit = table_name(worker_cfg.engine, "audit_log", ReadSurface::Physical);

            while Instant::now() < end_at {
                if worker_cfg.engine.uses_security() {
                    apply_context(&conn, use_shim_syntax, spec.role, spec.tenant)?;
                    if worker_id % 5 == 0 {
                        refresh_views(&conn, use_shim_syntax)?;
                        metrics.refreshes += 1;
                    }
                }

                let choice = rng.range(100);
                let step = (|| -> AppResult<()> {
                    match spec.role {
                        Role::User if choice < 30 => {
                            let started = Instant::now();
                            let tenant_idx = spec.tenant.expect("user tenant");
                            let account_id = random_account_id(&mut rng, tenant_idx);
                            let _: i64 = conn.query_row(
                                &format!(
                                    "SELECT balance FROM {physical_accounts} WHERE id = ?1 AND tenant = ?2"
                                ),
                                params![account_id, tenant_name(tenant_idx)],
                                |r| r.get(0),
                            )?;
                            metrics.point_reads += 1;
                            WorkerMetrics::add_latency(&mut metrics.point_read_ns, started);
                        }
                        Role::User if choice < 55 => {
                            let started = Instant::now();
                            let tenant_idx = spec.tenant.expect("user tenant");
                            let _: i64 = conn.query_row(
                                &format!(
                                    "SELECT COUNT(*) FROM {physical_orders}
                                     WHERE tenant = ?1 AND status IN ('new', 'approved')"
                                ),
                                [tenant_name(tenant_idx)],
                                |r| r.get(0),
                            )?;
                            metrics.range_reads += 1;
                            WorkerMetrics::add_latency(&mut metrics.range_read_ns, started);
                        }
                        Role::Ops if choice < 65 => {
                            let started = Instant::now();
                            let tenant_idx = rng.range(crate::types::TENANTS as u64) as usize;
                            let from_id = random_account_id(&mut rng, tenant_idx);
                            let mut to_id = random_account_id(&mut rng, tenant_idx);
                            if to_id == from_id {
                                to_id = random_account_id(&mut rng, (tenant_idx + 1) % crate::types::TENANTS);
                            }
                            let amount = (rng.range(90) + 10) as i64;
                            let transfer_id =
                                worker_next_transfer_id.fetch_add(1, Ordering::Relaxed) as i64;
                            let audit_id =
                                worker_next_audit_id.fetch_add(1, Ordering::Relaxed) as i64;

                            match conn.unchecked_transaction() {
                                Ok(tx) => {
                                    let balance: Option<i64> = tx
                                        .query_row(
                                            &format!(
                                                "SELECT balance FROM {physical_accounts} WHERE id = ?1"
                                            ),
                                            [from_id],
                                            |r| r.get(0),
                                        )
                                        .optional()?;
                                    if balance.unwrap_or(0) >= amount {
                                        tx.execute(
                                            &format!(
                                                "UPDATE {physical_accounts} SET balance = balance - ?1 WHERE id = ?2"
                                            ),
                                            params![amount, from_id],
                                        )?;
                                        tx.execute(
                                            &format!(
                                                "UPDATE {physical_accounts} SET balance = balance + ?1 WHERE id = ?2"
                                            ),
                                            params![amount, to_id],
                                        )?;
                                        tx.execute(
                                            &format!(
                                                "INSERT INTO {physical_transfers}
                                                 (id, tenant, from_account_id, to_account_id, amount, ts, row_label_id)
                                                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
                                            ),
                                            params![
                                                transfer_id,
                                                tenant_name(tenant_idx),
                                                from_id,
                                                to_id,
                                                amount,
                                                transfer_id,
                                                labels.tenant_labels[tenant_idx]
                                            ],
                                        )?;
                                        tx.execute(
                                            &format!(
                                                "INSERT INTO {physical_audit}
                                                 (id, tenant, actor_role, action, ref_id, ts, detail, row_label_id)
                                                 VALUES (?1, ?2, 'ops', 'transfer', ?3, ?4, ?5, ?6)"
                                            ),
                                            params![
                                                audit_id,
                                                tenant_name(tenant_idx),
                                                transfer_id,
                                                transfer_id,
                                                format!("transfer {amount} from {from_id} to {to_id}"),
                                                labels.tenant_labels[tenant_idx]
                                            ],
                                        )?;
                                        tx.commit()?;
                                        worker_oracle
                                            .lock()
                                            .map_err(|_| "oracle lock poisoned")?
                                            .record_transfer(from_id, to_id, amount);
                                        metrics.transfers_ok += 1;
                                    } else {
                                        tx.rollback()?;
                                        metrics.transfers_skipped += 1;
                                    }
                                }
                                Err(_) => {
                                    metrics.errors += 1;
                                }
                            }
                            WorkerMetrics::add_latency(&mut metrics.transfer_ns, started);
                        }
                        Role::User if choice < 96 => {
                            let started = Instant::now();
                            let tenant_idx = spec.tenant.expect("user tenant");
                            let account_id = random_account_id(&mut rng, tenant_idx);
                            let order_id =
                                worker_next_order_id.fetch_add(1, Ordering::Relaxed) as i64;
                            let audit_id =
                                worker_next_audit_id.fetch_add(1, Ordering::Relaxed) as i64;
                            let amount = (rng.range(180) + 20) as i64;
                            let tx = conn.unchecked_transaction()?;
                            tx.execute(
                                &format!(
                                    "INSERT INTO {physical_orders}
                                     (id, tenant, account_id, amount, status, row_label_id)
                                     VALUES (?1, ?2, ?3, ?4, 'new', ?5)"
                                ),
                                params![
                                    order_id,
                                    tenant_name(tenant_idx),
                                    account_id,
                                    amount,
                                    labels.tenant_labels[tenant_idx]
                                ],
                            )?;
                            tx.execute(
                                &format!(
                                    "INSERT INTO {physical_audit}
                                     (id, tenant, actor_role, action, ref_id, ts, detail, row_label_id)
                                     VALUES (?1, ?2, 'user', 'create_order', ?3, ?4, ?5, ?6)"
                                ),
                                params![
                                    audit_id,
                                    tenant_name(tenant_idx),
                                    order_id,
                                    order_id,
                                    format!("created order {order_id}"),
                                    labels.tenant_labels[tenant_idx]
                                ],
                            )?;
                            tx.commit()?;
                            worker_oracle
                                .lock()
                                .map_err(|_| "oracle lock poisoned")?
                                .record_order_create(order_id);
                            metrics.orders_created += 1;
                            WorkerMetrics::add_latency(&mut metrics.order_create_ns, started);
                        }
                        Role::User => {
                            let started = Instant::now();
                            let tenant_idx = spec.tenant.expect("user tenant");
                            let max_order_id =
                                worker_next_order_id.load(Ordering::Relaxed) as i64 - 1;
                            if max_order_id > 0 {
                                let candidate = (rng.range(max_order_id as u64) + 1) as i64;
                                if let Some((from, to)) = transition_for_rng(&mut rng) {
                                    let tx = conn.unchecked_transaction()?;
                                    let changed = tx.execute(
                                        &format!(
                                            "UPDATE {physical_orders}
                                             SET status = ?1
                                             WHERE id = ?2 AND tenant = ?3 AND status = ?4"
                                        ),
                                        params![to, candidate, tenant_name(tenant_idx), from],
                                    )?;
                                    if changed == 1 {
                                        let audit_id = worker_next_audit_id
                                            .fetch_add(1, Ordering::Relaxed)
                                            as i64;
                                        tx.execute(
                                            &format!(
                                                "INSERT INTO {physical_audit}
                                                 (id, tenant, actor_role, action, ref_id, ts, detail, row_label_id)
                                                 VALUES (?1, ?2, 'user', 'advance_order', ?3, ?4, ?5, ?6)"
                                            ),
                                            params![
                                                audit_id,
                                                tenant_name(tenant_idx),
                                                candidate,
                                                candidate,
                                                format!("transitioned order {candidate} to {to}"),
                                                labels.tenant_labels[tenant_idx]
                                            ],
                                        )?;
                                        tx.commit()?;
                                        worker_oracle
                                            .lock()
                                            .map_err(|_| "oracle lock poisoned")?
                                            .record_order_transition(candidate, to);
                                        metrics.order_updates += 1;
                                    } else {
                                        tx.rollback()?;
                                    }
                                }
                            }
                            WorkerMetrics::add_latency(&mut metrics.order_update_ns, started);
                        }
                        _ => {
                            let started = Instant::now();
                            let _: i64 = conn.query_row(
                                &format!(
                                    "SELECT COUNT(*) FROM {physical_orders}
                                     WHERE status IN ('new', 'approved', 'settled')"
                                ),
                                [],
                                |r| r.get(0),
                            )?;
                            metrics.admin_scans += 1;
                            WorkerMetrics::add_latency(&mut metrics.admin_scan_ns, started);
                        }
                    }
                    Ok(())
                })();

                if let Err(err) = step {
                    let msg = err.to_string();
                    if msg.contains("locked") || msg.contains("busy") {
                        metrics.errors += 1;
                        thread::sleep(Duration::from_millis(10));
                        conn = open_worker_conn(&worker_cfg, &leader_db_path, raft_vfs.as_deref())?;
                        configure_worker_conn(&conn)?;
                        continue;
                    }
                    return Err(err);
                }
            }

            Ok(metrics)
        }));
    }

    let mut merged = WorkerMetrics::default();
    for join in joins {
        let worker_metrics = join.join().map_err(|_| "worker thread panicked")??;
        merged.merge(&worker_metrics);
    }
    Ok(merged)
}
