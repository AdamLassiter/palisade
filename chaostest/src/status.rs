use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RaftStatusDoc {
    pub(crate) nodes: Vec<RaftNodeStatus>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RaftNodeStatus {
    pub(crate) node_id: u64,
    #[serde(default)]
    pub(crate) is_leader: bool,
    #[serde(default)]
    pub(crate) committed_wal_offset: u64,
    #[serde(default)]
    pub(crate) voters: Vec<u64>,
    #[serde(default)]
    pub(crate) replay: ReplayStatus,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct ReplayStatus {
    #[serde(default)]
    pub(crate) wal_sync_policy: String,
    #[serde(default)]
    pub(crate) last_applied_offset: i64,
    #[serde(default)]
    pub(crate) last_wal_synced_offset: i64,
    #[serde(default)]
    pub(crate) last_materialized_offset: i64,
}
