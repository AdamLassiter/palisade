use std::{
    collections::HashMap,
    env,
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use rusqlite::{Connection, params};
use tempfile::Builder;

use crate::{
    db::{
        configure_setup_conn,
        create_schema,
        load_sqlevfs_on_conn,
        open_evfs_control_conn,
        open_writer_conn,
    },
    types::{
        ACCOUNTS_PER_TENANT,
        AppResult,
        Config,
        INITIAL_BALANCE,
        Labels,
        LibPaths,
        NodeInfo,
        RaftStatusDoc,
        Runtime,
        SharedCounter,
        SharedOracle,
        TENANTS,
    },
    util::{
        account_id_for,
        ephemeral_addr,
        evfs_keyring_path,
        grpc_uri,
        persist,
        table_name,
        tenant_name,
        transient,
    },
};

pub(crate) fn prepare_runtime(cfg: &Config) -> AppResult<Runtime> {
    transient("resolving repository paths and extension libraries");
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("loadtest manifest missing parent")?
        .to_path_buf();
    let libs = LibPaths {
        sqlsec: repo_root
            .join("sqlsec")
            .join("target")
            .join(&cfg.mode)
            .join("libsqlsec.so"),
        sqlevfs: repo_root
            .join("sqlevfs")
            .join("target")
            .join(&cfg.mode)
            .join("libsqlevfs.so"),
    };

    if cfg.engine.uses_security() && !libs.sqlsec.exists() {
        return Err(format!("missing sqlsec extension at {}", libs.sqlsec.display()).into());
    }
    if cfg.engine.uses_evfs() && !libs.sqlevfs.exists() {
        return Err(format!("missing sqlevfs extension at {}", libs.sqlevfs.display()).into());
    }
    if cfg.engine.uses_security() {
        persist(format!("sqlsec {}", libs.sqlsec.display()));
    }
    if cfg.engine.uses_evfs() {
        persist(format!("sqlevfs {}", libs.sqlevfs.display()));
    }

    let (workspace_guard, workspace_path) = if cfg.keep_artifacts {
        let path = std::env::temp_dir().join(format!(
            "palisade-loadtest-{}-{}",
            cfg.engine.as_str(),
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        (None, path)
    } else {
        let dir = Builder::new().prefix("palisade-loadtest-").tempdir()?;
        let path = dir.path().to_path_buf();
        (Some(dir), path)
    };
    persist(format!("workspace {}", workspace_path.display()));

    if cfg.engine.uses_evfs() {
        let path = workspace_path.join("evfs.key");
        fs::write(&path, [0x42_u8; 32])?;
        unsafe {
            env::set_var("EVFS_KEYFILE", &path);
        }
        persist(format!("evfs keyfile {}", path.display()));
    }

    if cfg.engine.uses_evfs() {
        transient("registering EVFS bootstrap connection");
        prepare_evfs_registration(&libs.sqlevfs)?;
    }

    let use_shim_syntax = env::var("LD_PRELOAD")
        .ok()
        .map(|v| v.contains("libsqlshim"))
        .unwrap_or(false);
    persist(format!(
        "sqlshim preload {}",
        if use_shim_syntax {
            "detected"
        } else {
            "not detected"
        }
    ));

    let leader_db_path = workspace_path.join("leader.db");
    let (leader_raft_vfs_name, followers) = if cfg.engine.uses_cluster() {
        transient("building raft cluster");
        let (leader_raft_vfs_name, followers) =
            build_cluster(&libs, &leader_db_path, &workspace_path)?;
        (Some(leader_raft_vfs_name), followers)
    } else {
        (None, Vec::new())
    };
    persist(format!("leader db {}", leader_db_path.display()));
    if !followers.is_empty() {
        persist(format!("followers {}", followers.len()));
    }

    let labels = Labels {
        tenant_labels: vec![0; TENANTS],
    };

    Ok(Runtime {
        workspace_path,
        _workspace_guard: workspace_guard,
        libs,
        leader_db_path,
        leader_raft_vfs_name,
        followers,
        labels,
        use_shim_syntax,
    })
}

fn prepare_evfs_registration(sqlevfs_path: &Path) -> AppResult<()> {
    transient(format!("loading sqlevfs from {}", sqlevfs_path.display()));
    let conn = Connection::open(":memory:")?;
    load_sqlevfs_on_conn(&conn, sqlevfs_path)?;
    Ok(())
}

fn sync_cluster_keyrings(runtime: &Runtime) -> AppResult<()> {
    let leader_sidecar = evfs_keyring_path(&runtime.leader_db_path);
    if !leader_sidecar.exists() {
        return Err(format!(
            "leader keyring sidecar missing after seed: {}",
            leader_sidecar.display()
        )
        .into());
    }

    for follower in &runtime.followers {
        fs::copy(&leader_sidecar, evfs_keyring_path(&follower.db_path))?;
    }
    persist("mirrored leader keyring sidecar to followers");
    Ok(())
}

fn build_cluster(
    libs: &LibPaths,
    leader_db_path: &Path,
    workspace_path: &Path,
) -> AppResult<(String, Vec<NodeInfo>)> {
    transient("allocating raft listener addresses");
    let leader_addr = ephemeral_addr()?;
    let follower_2_addr = ephemeral_addr()?;
    let follower_3_addr = ephemeral_addr()?;
    let leader_rpc_addr = grpc_uri(&leader_addr);
    let follower_2_rpc_addr = grpc_uri(&follower_2_addr);
    let follower_3_rpc_addr = grpc_uri(&follower_3_addr);
    let vfs_suffix = raft_vfs_suffix(workspace_path);
    let leader_raft_vfs_name = format!("evfs_raft_node1_{vfs_suffix}");
    let follower_2_raft_vfs_name = format!("evfs_raft_node2_{vfs_suffix}");
    let follower_3_raft_vfs_name = format!("evfs_raft_node3_{vfs_suffix}");
    persist(format!("raft node 1 {leader_rpc_addr} ({leader_addr})"));
    persist(format!(
        "raft node 2 {follower_2_rpc_addr} ({follower_2_addr})"
    ));
    persist(format!(
        "raft node 3 {follower_3_rpc_addr} ({follower_3_addr})"
    ));

    let nodes = vec![
        NodeInfo {
            node_id: 1,
            db_path: leader_db_path.to_path_buf(),
            listen_addr: leader_addr.clone(),
            rpc_addr: leader_rpc_addr.clone(),
            raft_vfs_name: leader_raft_vfs_name.clone(),
        },
        NodeInfo {
            node_id: 2,
            db_path: workspace_path.join("node2.db"),
            listen_addr: follower_2_addr.clone(),
            rpc_addr: follower_2_rpc_addr.clone(),
            raft_vfs_name: follower_2_raft_vfs_name,
        },
        NodeInfo {
            node_id: 3,
            db_path: workspace_path.join("node3.db"),
            listen_addr: follower_3_addr.clone(),
            rpc_addr: follower_3_rpc_addr.clone(),
            raft_vfs_name: follower_3_raft_vfs_name,
        },
    ];

    transient("opening leader control connection");
    let leader_control = open_evfs_control_conn(leader_db_path, libs)?;
    transient("starting raft node 1");
    leader_control.query_row::<String, _, _>(
        "SELECT evfs_raft_init(?1, ?2, ?3, 'evfs', ?4)",
        params![1_i64, &leader_addr, "{}", &nodes[0].raft_vfs_name],
        |r| r.get(0),
    )?;
    transient("waiting for leader election");
    wait_for_leader(
        &leader_control,
        1,
        &nodes[0].raft_vfs_name,
        Duration::from_secs(5),
    )?;
    persist("raft node 1 elected leader");

    for node in nodes.iter().skip(1) {
        transient(format!(
            "opening follower control node={} db={}",
            node.node_id,
            node.db_path.display()
        ));
        let conn = open_evfs_control_conn(&node.db_path, libs)?;
        let peers_json = serde_json::to_string(&HashMap::from([
            (1_u64, leader_rpc_addr.clone()),
            (
                if node.node_id == 2 { 3_u64 } else { 2_u64 },
                if node.node_id == 2 {
                    follower_3_rpc_addr.clone()
                } else {
                    follower_2_rpc_addr.clone()
                },
            ),
        ]))?;
        transient(format!("starting follower node {}", node.node_id));
        conn.query_row::<String, _, _>(
            "SELECT evfs_raft_init(?1, ?2, ?3, 'evfs', ?4)",
            params![
                node.node_id as i64,
                &node.listen_addr,
                peers_json,
                &node.raft_vfs_name
            ],
            |r| r.get(0),
        )?;
    }

    for node in nodes.iter().skip(1) {
        transient(format!(
            "adding node {} to membership via {}",
            node.node_id, node.rpc_addr
        ));
        leader_control.query_row::<String, _, _>(
            "SELECT evfs_raft_add_node(?1, ?2, 10)",
            params![node.node_id as i64, &node.rpc_addr],
            |r| r.get(0),
        )?;
    }

    transient("waiting for raft voter set [1, 2, 3]");
    let raft_vfs_names = nodes
        .iter()
        .map(|node| node.raft_vfs_name.as_str())
        .collect::<Vec<_>>();
    wait_for_voters(
        &leader_control,
        &raft_vfs_names,
        &[1, 2, 3],
        Duration::from_secs(10),
    )?;
    persist("raft cluster ready");
    Ok((leader_raft_vfs_name, nodes.into_iter().skip(1).collect()))
}

fn raft_vfs_suffix(workspace_path: &Path) -> String {
    workspace_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("runtime")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

pub(crate) fn seed_database(
    cfg: &Config,
    runtime: &mut Runtime,
    oracle: &SharedOracle,
    next_order_id: &SharedCounter,
    next_audit_id: &SharedCounter,
) -> AppResult<u64> {
    transient("opening writer connection");
    let conn = open_writer_conn(cfg, runtime)?;
    transient("configuring setup pragmas");
    configure_setup_conn(&conn)?;

    transient("creating schema");
    let labels = create_schema(cfg, runtime, &conn)?;
    runtime.labels = labels.clone();
    transient(format!(
        "ready with {} tenant labels",
        runtime.labels.tenant_labels.len()
    ));

    let physical_accounts = table_name(cfg.engine, "accounts", crate::types::ReadSurface::Physical);
    let physical_orders = table_name(cfg.engine, "orders", crate::types::ReadSurface::Physical);
    let physical_audit = table_name(cfg.engine, "audit_log", crate::types::ReadSurface::Physical);

    transient("inserting seed rows");
    let tx = conn.unchecked_transaction()?;
    let seeded_orders = {
        let mut ins_account = tx.prepare(&format!(
            "INSERT INTO {physical_accounts}
             (id, tenant, balance, status, secret_note, row_label_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        ))?;

        let mut ins_order = tx.prepare(&format!(
            "INSERT INTO {physical_orders}
             (id, tenant, account_id, amount, status, row_label_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        ))?;

        let mut ins_audit = tx.prepare(&format!(
            "INSERT INTO {physical_audit}
             (id, tenant, actor_role, action, ref_id, ts, detail, row_label_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
        ))?;

        let mut seeded_orders = 0_u64;
        let mut oracle_guard = oracle.lock().map_err(|_| "oracle lock poisoned")?;
        for tenant_idx in 0..TENANTS {
            let tenant = tenant_name(tenant_idx);
            for account_offset in 0..ACCOUNTS_PER_TENANT {
                let account_id = account_id_for(tenant_idx, account_offset);
                ins_account.execute(params![
                    account_id,
                    tenant,
                    INITIAL_BALANCE,
                    "open",
                    format!("secret-note-{tenant}-acct-{account_offset:02}"),
                    runtime.labels.tenant_labels[tenant_idx],
                ])?;

                if account_offset % 3 == 0 {
                    let order_id =
                        next_order_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as i64;
                    ins_order.execute(params![
                        order_id,
                        tenant,
                        account_id,
                        10 + account_offset as i64,
                        "new",
                        runtime.labels.tenant_labels[tenant_idx],
                    ])?;
                    oracle_guard.record_seed_order(order_id, "new");
                    seeded_orders += 1;
                }

                let audit_id =
                    next_audit_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as i64;
                ins_audit.execute(params![
                    audit_id,
                    tenant,
                    "system",
                    "seed_account",
                    account_id,
                    audit_id,
                    format!("seeded account {account_id}"),
                    runtime.labels.tenant_labels[tenant_idx],
                ])?;
                oracle_guard.audit_count += 1;
            }
        }
        seeded_orders
    };
    tx.commit()?;
    persist("seed transaction committed");
    if cfg.engine.uses_cluster() {
        sync_cluster_keyrings(runtime)?;
    }
    Ok(seeded_orders)
}

fn wait_for_leader(
    conn: &Connection,
    node_id: u64,
    raft_vfs_name: &str,
    timeout: Duration,
) -> AppResult<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let status: String = conn.query_row("SELECT evfs_raft_status()", [], |r| r.get(0))?;
        let doc: RaftStatusDoc = serde_json::from_str(&status)?;
        if doc.nodes.iter().any(|n| {
            n.node_id == node_id
                && n.raft_vfs_name == raft_vfs_name
                && n.is_leader
                && n.leader_id == Some(node_id)
        }) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err("timed out waiting for raft leader".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_voters(
    conn: &Connection,
    raft_vfs_names: &[&str],
    expected: &[u64],
    timeout: Duration,
) -> AppResult<()> {
    let deadline = std::time::Instant::now() + timeout;
    let mut expected_sorted = expected.to_vec();
    expected_sorted.sort_unstable();
    loop {
        let status: String = conn.query_row("SELECT evfs_raft_status()", [], |r| r.get(0))?;
        let doc: RaftStatusDoc = serde_json::from_str(&status)?;
        let cluster_nodes = doc
            .nodes
            .iter()
            .filter(|n| raft_vfs_names.contains(&n.raft_vfs_name.as_str()))
            .collect::<Vec<_>>();
        if cluster_nodes.len() == raft_vfs_names.len()
            && cluster_nodes.iter().all(|n| {
                let mut voters = n.voters.clone();
                voters.sort_unstable();
                voters == expected_sorted
            })
        {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err("timed out waiting for raft voter membership".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}
