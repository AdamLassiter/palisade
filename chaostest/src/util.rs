use std::{
    net::TcpListener,
    path::{Path, PathBuf},
};

use crate::{
    types::{ACCOUNTS_PER_TENANT, AppResult, NodeConfig},
    workload::{load_sqlsec_on_conn, open_evfs_control_conn},
};

pub(crate) fn evfs_keyring_path(db_path: &Path) -> PathBuf {
    db_path.with_extension("evfs-keyring")
}

pub(crate) fn evfs_raft_sidecar_path(db_path: &Path) -> PathBuf {
    db_path.with_extension("evfs-raft.json")
}

pub(crate) fn node_artifacts(node: &NodeConfig) -> Vec<PathBuf> {
    let parent = node.db_path.parent().unwrap_or_else(|| Path::new("."));
    vec![
        node.db_path.clone(),
        node.db_path.with_extension("db-wal"),
        node.db_path.with_extension("db-shm"),
        evfs_keyring_path(&node.db_path),
        evfs_raft_sidecar_path(&node.db_path),
        parent.join(format!("node{}.stdout.log", node.node_id)),
        parent.join(format!("node{}.stderr.log", node.node_id)),
    ]
}

pub(crate) fn random_account_id(rng: &mut SimpleRng, tenant_idx: usize) -> i64 {
    let offset = rng.range(ACCOUNTS_PER_TENANT as u64) as usize;
    account_id_for(tenant_idx, offset)
}

pub(crate) fn account_id_for(tenant_idx: usize, offset: usize) -> i64 {
    (tenant_idx * ACCOUNTS_PER_TENANT + offset + 1) as i64
}

pub(crate) fn tenant_name(tenant_idx: usize) -> String {
    format!("t{tenant_idx:02}")
}

pub(crate) fn ephemeral_addr() -> AppResult<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr.to_string())
}

pub(crate) fn grpc_uri(listen_addr: &str) -> String {
    format!("http://{listen_addr}")
}

pub(crate) fn is_lock_or_busy(msg: &str) -> bool {
    msg.contains("locked") || msg.contains("busy")
}

pub(crate) fn try_open_evfs_db(libs: &crate::types::LibPaths, db_path: &Path) -> AppResult<i64> {
    let conn = open_evfs_control_conn(db_path, &libs.sqlevfs)?;
    load_sqlsec_on_conn(&conn, &libs.sqlsec)?;
    Ok(conn.query_row("SELECT COUNT(*) FROM __sec_accounts", [], |r| r.get(0))?)
}

#[derive(Clone)]
pub(crate) struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    pub(crate) fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.state
    }

    pub(crate) fn range(&mut self, upper: u64) -> u64 {
        if upper == 0 { 0 } else { self.next() % upper }
    }
}
