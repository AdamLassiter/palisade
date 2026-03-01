use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result};
use openraft::{BasicNode, Config, Raft, RaftMetrics, storage::Adaptor};
use parking_lot::RwLock;

use crate::vfs::consensus::{
    NodeId,
    RaftNode,
    TruncateCallback,
    network::ReplicaNetwork,
    wal::{WalFrameEntry, WalLogStore, WalStateMachine, WalStorageInner},
};

/// Cluster handle shared by every `EvfsFile` in the same process.
///
/// Construct via [`RaftHandle::start`] during VFS registration.
pub struct RaftHandle {
    node_id: NodeId,
    raft: RaftNode,
    /// Highest WAL byte offset durably committed by Raft.
    /// Updated by [`RaftHandle::submit_frame`] after each commit.
    committed_wal_offset: AtomicU64,
    /// Called when the local WAL must be truncated (leader step-down).
    truncate_cb: Option<TruncateCallback>,
}

impl RaftHandle {
    /// Initialise a Raft node.
    ///
    /// `apply_fn` is the callback the state machine calls for each
    /// committed WAL frame.  Typically it writes the frame bytes
    /// directly to the local WAL file via the inner OS VFS.
    ///
    /// `truncate_cb` is called when uncommitted WAL frames must be
    /// discarded (leader step-down / term change).
    pub async fn start(
        node_id: NodeId,
        peers: HashMap<NodeId, String>,
        apply_fn: impl Fn(i64, u32, &[u8]) -> Result<()> + Send + Sync + 'static,
        truncate_cb: Option<TruncateCallback>,
    ) -> Result<Arc<Self>> {
        let config = Arc::new(
            Config {
                heartbeat_interval: 250,
                election_timeout_min: 299,
                election_timeout_max: 500,
                ..Default::default()
            }
            .validate()
            .context("invalid Raft config")?,
        );

        let storage = Arc::new(RwLock::new(WalStorageInner {
            log_store: WalLogStore::default(),
            state_machine: WalStateMachine::new(apply_fn),
        }));

        let (log_store, state_machine) = Adaptor::new(storage);

        let network = ReplicaNetwork::new(peers.clone());

        let raft = Raft::new(node_id, config, network, log_store, state_machine)
            .await
            .context("failed to create Raft node")?;

        // If this is a single-node cluster, immediately become leader.
        if peers.is_empty() {
            raft.initialize(BTreeMap::from([(node_id, BasicNode::default())]))
                .await
                .ok(); // may fail if already initialised — that's fine.
        }

        Ok(Arc::new(Self {
            node_id,
            raft,
            committed_wal_offset: AtomicU64::new(0),
            truncate_cb,
        }))
    }

    /// Returns `true` if this node is currently the Raft leader.
    pub fn is_leader(&self) -> bool {
        matches!(
            self.raft.metrics().borrow().current_leader,
            Some(id) if id == self.node_id
        )
    }

    /// Submit a completed WAL frame to Raft and await majority commit.
    ///
    /// Must only be called from the **leader**.  `vfs.rs` must check
    /// [`is_leader`] before calling this; non-leaders must refuse
    /// `SQLITE_LOCK_RESERVED` in `xLock` so SQLite never writes WAL.
    ///
    /// Blocks (async) until the entry is committed on a majority.
    /// Called from within `evfs_xSync` so SQLite sees the transaction
    /// as durable only after Raft durability is confirmed.
    pub async fn submit_frame(&self, wal_offset: i64, page_no: u32, data: Vec<u8>) -> Result<()> {
        let entry = WalFrameEntry {
            wal_offset,
            page_no,
            data,
        };

        self.raft
            .client_write(entry)
            .await
            .context("Raft client_write failed")?;

        self.committed_wal_offset
            .store(wal_offset as u64, Ordering::Release);

        Ok(())
    }

    /// Request a log snapshot and compact old entries.
    ///
    /// Should be called periodically by the leader after checkpointing
    /// the SQLite WAL into the main DB file.
    pub async fn trigger_snapshot(&self) -> Result<()> {
        self.raft
            .trigger()
            .snapshot()
            .await
            .context("snapshot trigger failed")?;
        Ok(())
    }

    /// Return current Raft metrics for observability.
    pub fn metrics(&self) -> RaftMetrics<NodeId, BasicNode> {
        self.raft.metrics().borrow().clone()
    }
}
