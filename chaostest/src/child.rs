use std::{
    io::{BufRead, Write},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use rusqlite::{Connection, OpenFlags, params};

use crate::{
    protocol::{ChildRequest, ChildResponse},
    status::RaftStatusDoc,
    types::{ACCOUNTS_PER_TENANT, AppResult, FollowerWalSync, INITIAL_BALANCE, TENANTS},
    util::{SimpleRng, account_id_for, is_lock_or_busy, tenant_name},
    workload::{
        Aggregate,
        WorkloadMetrics,
        aggregate,
        bootstrap_sqlsec,
        configure_conn,
        create_schema,
        load_sqlsec_on_conn,
        open_evfs_control_conn,
        raft_status_has_node,
        tenant_label_id,
        transfer_once,
        validate_ciphertext,
    },
};

#[derive(Debug)]
struct ChildConfig {
    mode: String,
    node_id: u64,
    db_path: PathBuf,
    listen_addr: String,
    peers_json: String,
    raft_vfs_name: String,
    sqlsec: PathBuf,
    sqlevfs: PathBuf,
    wal_sync: FollowerWalSync,
}

impl ChildConfig {
    fn parse(args: Vec<String>) -> AppResult<Self> {
        let mut mode = "debug".to_string();
        let mut node_id = None;
        let mut db_path = None;
        let mut listen_addr = None;
        let mut peers_json = None;
        let mut raft_vfs_name = None;
        let mut sqlsec = None;
        let mut sqlevfs = None;
        let mut wal_sync = FollowerWalSync::PerBatch;

        let mut i = 0usize;
        while i < args.len() {
            match args[i].as_str() {
                "--node" => {}
                "--mode" => {
                    i += 1;
                    mode = args.get(i).ok_or("missing --mode value")?.clone();
                }
                "--node-id" => {
                    i += 1;
                    node_id = Some(args.get(i).ok_or("missing --node-id value")?.parse()?);
                }
                "--db" => {
                    i += 1;
                    db_path = Some(PathBuf::from(args.get(i).ok_or("missing --db value")?));
                }
                "--listen" => {
                    i += 1;
                    listen_addr = Some(args.get(i).ok_or("missing --listen value")?.clone());
                }
                "--peers" => {
                    i += 1;
                    peers_json = Some(args.get(i).ok_or("missing --peers value")?.clone());
                }
                "--raft-vfs" => {
                    i += 1;
                    raft_vfs_name = Some(args.get(i).ok_or("missing --raft-vfs value")?.clone());
                }
                "--sqlsec" => {
                    i += 1;
                    sqlsec = Some(PathBuf::from(args.get(i).ok_or("missing --sqlsec value")?));
                }
                "--sqlevfs" => {
                    i += 1;
                    sqlevfs = Some(PathBuf::from(args.get(i).ok_or("missing --sqlevfs value")?));
                }
                "--wal-sync" => {
                    i += 1;
                    let value = args.get(i).ok_or("missing --wal-sync value")?;
                    wal_sync = FollowerWalSync::parse(value)
                        .ok_or_else(|| format!("unknown --wal-sync value '{value}'"))?;
                }
                other => return Err(format!("unknown child option '{other}'").into()),
            }
            i += 1;
        }

        Ok(Self {
            mode,
            node_id: node_id.ok_or("missing --node-id")?,
            db_path: db_path.ok_or("missing --db")?,
            listen_addr: listen_addr.ok_or("missing --listen")?,
            peers_json: peers_json.ok_or("missing --peers")?,
            raft_vfs_name: raft_vfs_name.ok_or("missing --raft-vfs")?,
            sqlsec: sqlsec.ok_or("missing --sqlsec")?,
            sqlevfs: sqlevfs.ok_or("missing --sqlevfs")?,
            wal_sync,
        })
    }
}

pub(crate) fn child_main(args: Vec<String>) -> AppResult<()> {
    let cfg = ChildConfig::parse(args)?;
    let mut node = ChaosNode::start(cfg)?;
    write_child_response(ChildResponse::ok(serde_json::json!({
        "ready": true,
        "node_id": node.cfg.node_id,
        "mode": node.cfg.mode,
    })))?;

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let request = serde_json::from_str::<ChildRequest>(&line);
        let response = match request {
            Ok(request) => match node.handle(request) {
                Ok(response) => response,
                Err(err) => ChildResponse::err(err),
            },
            Err(err) => ChildResponse::err(err),
        };
        let should_exit = matches!(response.result.as_ref().and_then(|v| v.get("shutdown")), Some(v) if v == true);
        write_child_response(response)?;
        if should_exit {
            break;
        }
    }
    Ok(())
}

fn write_child_response(response: ChildResponse) -> AppResult<()> {
    println!("{}", serde_json::to_string(&response)?);
    std::io::stdout().flush()?;
    Ok(())
}

struct ChaosNode {
    cfg: ChildConfig,
    control: Connection,
}

impl ChaosNode {
    fn start(cfg: ChildConfig) -> AppResult<Self> {
        let control = open_evfs_control_conn(&cfg.db_path, &cfg.sqlevfs)?;
        if !raft_status_has_node(&control, cfg.node_id)? {
            let options = serde_json::json!({
                "follower_wal_sync": {
                    "mode": cfg.wal_sync.as_str(),
                    "max_batches": 64,
                    "max_delay_ms": 5
                }
            })
            .to_string();
            control.query_row::<String, _, _>(
                "SELECT evfs_raft_init(?1, ?2, ?3, 'evfs', ?4, ?5)",
                params![
                    cfg.node_id as i64,
                    &cfg.listen_addr,
                    &cfg.peers_json,
                    &cfg.raft_vfs_name,
                    &options
                ],
                |r| r.get(0),
            )?;
        }
        wait_for_raft_started(&control, cfg.node_id, Duration::from_secs(10))?;
        Ok(Self { cfg, control })
    }

    fn handle(&mut self, request: ChildRequest) -> AppResult<ChildResponse> {
        match request {
            ChildRequest::Status => Ok(ChildResponse::ok(self.raft_status()?)),
            ChildRequest::AddNode {
                node_id,
                rpc_addr,
                wait_secs,
            } => {
                self.control.query_row::<String, _, _>(
                    "SELECT evfs_raft_add_node(?1, ?2, ?3)",
                    params![node_id as i64, rpc_addr, wait_secs as i64],
                    |r| r.get(0),
                )?;
                Ok(ChildResponse::ok(serde_json::json!({"added": node_id})))
            }
            ChildRequest::Seed { seed } => {
                self.seed(seed)?;
                Ok(ChildResponse::ok(serde_json::json!({"seeded": true})))
            }
            ChildRequest::RunWorkload {
                duration_secs,
                workers,
                seed,
            } => Ok(ChildResponse::ok(self.run_workload(
                Duration::from_secs(duration_secs),
                workers,
                seed,
            )?)),
            ChildRequest::ValidateLocal => Ok(ChildResponse::ok(self.validate_local()?)),
            ChildRequest::ProbeFollowerWrite => {
                let err = self.probe_follower_write()?;
                Ok(ChildResponse::ok(serde_json::json!({ "rejected": err })))
            }
            ChildRequest::Checkpoint => {
                self.writer_conn()?
                    .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
                Ok(ChildResponse::ok(serde_json::json!({"checkpoint": true})))
            }
            ChildRequest::Shutdown => {
                let _ =
                    self.control
                        .query_row::<String, _, _>("SELECT evfs_raft_stop()", [], |r| r.get(0));
                Ok(ChildResponse::ok(serde_json::json!({"shutdown": true})))
            }
        }
    }

    fn raft_status(&self) -> AppResult<RaftStatusDoc> {
        let status: String = self
            .control
            .query_row("SELECT evfs_raft_status()", [], |r| r.get(0))?;
        Ok(serde_json::from_str(&status)?)
    }

    fn writer_conn(&self) -> AppResult<Connection> {
        let conn = Connection::open_with_flags_and_vfs(
            &self.cfg.db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            self.cfg.raft_vfs_name.as_str(),
        )?;
        conn.busy_timeout(Duration::from_secs(5))?;
        load_sqlsec_on_conn(&conn, &self.cfg.sqlsec)?;
        Ok(conn)
    }

    fn evfs_conn(&self) -> AppResult<Connection> {
        let conn = Connection::open_with_flags_and_vfs(
            &self.cfg.db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            "evfs",
        )?;
        conn.busy_timeout(Duration::from_secs(5))?;
        load_sqlsec_on_conn(&conn, &self.cfg.sqlsec)?;
        Ok(conn)
    }

    fn seed(&self, _seed: u64) -> AppResult<()> {
        let conn = self.writer_conn()?;
        configure_conn(&conn)?;
        create_schema(&conn)?;
        bootstrap_sqlsec(&conn)?;

        let tx = conn.unchecked_transaction()?;
        for tenant_idx in 0..TENANTS {
            let tenant = tenant_name(tenant_idx);
            let label_id = tenant_label_id(&tx, tenant_idx)?;
            for account_offset in 0..ACCOUNTS_PER_TENANT {
                let id = account_id_for(tenant_idx, account_offset);
                tx.execute(
                    "INSERT OR IGNORE INTO __sec_accounts
                     (id, tenant, balance, status, secret_note, row_label_id)
                     VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
                    params![
                        id,
                        tenant,
                        INITIAL_BALANCE,
                        format!("secret-note-{tenant}-{account_offset}"),
                        label_id
                    ],
                )?;
            }
            for order_offset in 0..8_i64 {
                let order_id = tenant_idx as i64 * 1000 + order_offset + 1;
                tx.execute(
                    "INSERT OR IGNORE INTO __sec_orders
                     (id, tenant, account_id, amount, status, row_label_id)
                     VALUES (?1, ?2, ?3, 100, 'new', ?4)",
                    params![
                        order_id,
                        tenant,
                        account_id_for(tenant_idx, order_offset as usize),
                        label_id
                    ],
                )?;
                tx.execute(
                    "INSERT OR IGNORE INTO __sec_audit_log
                     (id, tenant, actor_role, action, ref_id, ts, detail, row_label_id)
                     VALUES (?1, ?2, 'system', 'seed_order', ?1, ?1, ?3, ?4)",
                    params![
                        order_id,
                        tenant,
                        format!("seeded order {order_id}"),
                        label_id
                    ],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn run_workload(
        &self,
        duration: Duration,
        workers: usize,
        seed: u64,
    ) -> AppResult<WorkloadMetrics> {
        let end_at = Instant::now() + duration;
        let mut joins = Vec::new();
        for worker_id in 0..workers {
            let db_path = self.cfg.db_path.clone();
            let raft_vfs = self.cfg.raft_vfs_name.clone();
            let sqlsec = self.cfg.sqlsec.clone();
            joins.push(thread::spawn(move || -> AppResult<WorkloadMetrics> {
                let conn = Connection::open_with_flags_and_vfs(
                    &db_path,
                    OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
                    raft_vfs.as_str(),
                )?;
                conn.busy_timeout(Duration::from_secs(5))?;
                load_sqlsec_on_conn(&conn, &sqlsec)?;
                let mut rng = SimpleRng::new(seed ^ ((worker_id as u64 + 1) * 0x9E37));
                let mut metrics = WorkloadMetrics::default();
                while Instant::now() < end_at {
                    match transfer_once(&conn, &mut rng, &mut metrics) {
                        Ok(()) => {}
                        Err(err) if is_lock_or_busy(&err.to_string()) => {
                            metrics.lock_conflicts += 1;
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(err) => return Err(err),
                    }
                }
                Ok(metrics)
            }));
        }
        let mut merged = WorkloadMetrics::default();
        for join in joins {
            merged.merge(&join.join().map_err(|_| "worker thread panicked")??);
        }
        Ok(merged)
    }

    fn validate_local(&self) -> AppResult<Aggregate> {
        let conn = self.evfs_conn()?;
        let aggregate = aggregate(&conn)?;
        let expected_accounts = (TENANTS * ACCOUNTS_PER_TENANT) as i64;
        if aggregate.account_count != expected_accounts {
            return Err(format!(
                "account count mismatch: expected {expected_accounts}, got {}",
                aggregate.account_count
            )
            .into());
        }
        if aggregate.total_balance != expected_accounts * INITIAL_BALANCE {
            return Err("total balance mismatch".into());
        }
        let negative: i64 = conn.query_row(
            "SELECT COUNT(*) FROM __sec_accounts WHERE balance < 0",
            [],
            |r| r.get(0),
        )?;
        if negative != 0 {
            return Err(format!("found {negative} negative balances").into());
        }
        let audit_configs: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sec_audit_config
             WHERE logical_table IN ('accounts', 'orders', 'transfers') AND enabled = 1",
            [],
            |r| r.get(0),
        )?;
        if audit_configs != 3 {
            return Err(format!("expected 3 sqlsec audit configs, got {audit_configs}").into());
        }
        let leaked: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sec_audit_log
             WHERE COALESCE(row_pk_json, '') ||
                   COALESCE(changed_columns_json, '') ||
                   context_json ||
                   COALESCE(error, '') LIKE '%secret-note-%'",
            [],
            |r| r.get(0),
        )?;
        if leaked != 0 {
            return Err("sqlsec audit log leaked secret_note marker".into());
        }
        validate_ciphertext(&self.cfg.db_path)?;
        Ok(aggregate)
    }

    fn probe_follower_write(&self) -> AppResult<String> {
        let conn = Connection::open_with_flags_and_vfs(
            &self.cfg.db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            self.cfg.raft_vfs_name.as_str(),
        )?;
        conn.busy_timeout(Duration::from_millis(100))?;
        match conn.execute(
            "INSERT INTO __sec_audit_log
             (id, tenant, actor_role, action, ref_id, ts, detail, row_label_id)
             VALUES (-1, 'probe', 'probe', 'probe', -1, -1, 'probe', 1)",
            [],
        ) {
            Ok(_) => Err("follower accepted write probe".into()),
            Err(err) => Ok(err.to_string()),
        }
    }
}

fn wait_for_raft_started(conn: &Connection, node_id: u64, timeout: Duration) -> AppResult<()> {
    let started = Instant::now();
    loop {
        let status: String = conn.query_row("SELECT evfs_raft_status()", [], |r| r.get(0))?;
        let doc: RaftStatusDoc = serde_json::from_str(&status)?;
        if doc.nodes.iter().any(|node| node.node_id == node_id) {
            return Ok(());
        }
        if started.elapsed() > timeout {
            return Err(format!("timed out waiting for raft node {node_id}").into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}
