use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use openraft::{BasicNode, Config, Raft, RaftMetrics, storage::Adaptor};
use parking_lot::RwLock;
use tokio::runtime::Handle;

use crate::vfs::consensus::{
    NodeId,
    RaftNode,
    TruncateCallback,
    network::ReplicaNetwork,
    rpc::serve_grpc,
    wal::{WalBatch, WalRecord, WalStorageInner},
};

/// Cluster handle shared by every `EvfsFile` in the same process.
///
/// Construct via [`RaftHandle::start`] during VFS registration.
pub struct RaftHandle {
    node_id: NodeId,
    raft: RaftNode,
    runtime_handle: Handle,
    /// Highest WAL byte offset durably committed by Raft.
    /// Updated by [`RaftHandle::submit_frame`] after each commit.
    committed_wal_offset: AtomicU64,
    /// Called when the local WAL must be truncated (leader step-down).
    truncate_cb: Option<TruncateCallback>,
    stats: RaftHandleStats,
}

#[derive(Default)]
struct RaftHandleStats {
    xsync_calls: AtomicU64,
    xsync_micros: AtomicU64,
    xsync_inner_micros: AtomicU64,
    xsync_drain_micros: AtomicU64,
    submit_syncs: AtomicU64,
    submit_records: AtomicU64,
    submit_frames: AtomicU64,
    submit_micros: AtomicU64,
    max_submit_micros: AtomicU64,
    last_xsync_micros: AtomicU64,
    last_xsync_inner_micros: AtomicU64,
    last_xsync_drain_micros: AtomicU64,
    last_submit_records: AtomicU64,
    last_submit_frames: AtomicU64,
    last_submit_micros: AtomicU64,
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct RaftSubmitStats {
    pub xsync_calls: u64,
    pub xsync_micros: u64,
    pub xsync_inner_micros: u64,
    pub xsync_drain_micros: u64,
    pub submit_syncs: u64,
    pub submit_records: u64,
    pub submit_frames: u64,
    pub submit_micros: u64,
    pub max_submit_micros: u64,
    pub last_xsync_micros: u64,
    pub last_xsync_inner_micros: u64,
    pub last_xsync_drain_micros: u64,
    pub last_submit_records: u64,
    pub last_submit_frames: u64,
    pub last_submit_micros: u64,
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
        apply_fn: impl Fn(WalBatch) -> Result<()> + Send + Sync + 'static,
        truncate_cb: Option<TruncateCallback>,
        grpc_listen: Option<SocketAddr>,
        storage_path: Option<PathBuf>,
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

        let storage = Arc::new(RwLock::new(
            WalStorageInner::new(apply_fn, storage_path).context("failed to open raft storage")?,
        ));
        let committed_wal_offset = storage.read().committed_wal_offset();

        let (log_store, state_machine) = Adaptor::new(storage);

        let network = ReplicaNetwork::new(peers.clone());

        let raft = Raft::new(node_id, config, network, log_store, state_machine)
            .await
            .context("failed to create Raft node")?;

        if let Some(listen_addr) = grpc_listen {
            let raft_for_server = raft.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_grpc(raft_for_server, listen_addr).await {
                    eprintln!("sqlevfs: raft gRPC server exited with error: {e}");
                }
            });
        }

        // If this is a single-node cluster, immediately become leader.
        if peers.is_empty() {
            raft.initialize(BTreeMap::from([(node_id, BasicNode::default())]))
                .await
                .ok(); // may fail if already initialised — that's fine.
        }

        let handle = Arc::new(Self {
            node_id,
            raft,
            runtime_handle: Handle::current(),
            committed_wal_offset: AtomicU64::new(committed_wal_offset),
            truncate_cb,
            stats: RaftHandleStats::default(),
        });

        Self::spawn_leader_watchdog(handle.clone());

        Ok(handle)
    }

    fn spawn_leader_watchdog(handle: Arc<Self>) {
        tokio::spawn(async move {
            let mut was_leader = false;

            loop {
                let now_leader = handle.is_leader();

                if was_leader
                    && !now_leader
                    && let Some(cb) = handle.truncate_cb.as_ref()
                {
                    let committed = handle.committed_wal_offset.load(Ordering::Acquire) as i64;
                    if let Err(e) = cb(committed) {
                        eprintln!(
                            "sqlevfs: truncate callback failed after leader step-down at offset {committed}: {e}"
                        );
                    }
                }

                was_leader = now_leader;
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        });
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
    pub async fn submit_record(&self, record: WalRecord) -> Result<()> {
        self.submit_batch(WalBatch::new(vec![record])).await
    }

    pub async fn submit_batch(&self, batch: WalBatch) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let started = std::time::Instant::now();
        let wal_offset = batch.committed_wal_offset();
        let records = batch.len() as u64;
        let frames = batch.frame_count() as u64;
        self.raft
            .client_write(batch)
            .await
            .context("Raft client_write failed")?;

        if wal_offset > 0 {
            self.committed_wal_offset
                .store(wal_offset as u64, Ordering::Release);
        }
        let micros = started.elapsed().as_micros() as u64;
        self.stats.submit_syncs.fetch_add(1, Ordering::Relaxed);
        self.stats
            .submit_records
            .fetch_add(records, Ordering::Relaxed);
        self.stats
            .submit_frames
            .fetch_add(frames, Ordering::Relaxed);
        self.stats
            .submit_micros
            .fetch_add(micros, Ordering::Relaxed);
        self.stats
            .max_submit_micros
            .fetch_max(micros, Ordering::Relaxed);
        self.stats
            .last_submit_records
            .store(records, Ordering::Relaxed);
        self.stats
            .last_submit_frames
            .store(frames, Ordering::Relaxed);
        self.stats
            .last_submit_micros
            .store(micros, Ordering::Relaxed);

        Ok(())
    }

    pub fn record_xsync_timings(&self, total_micros: u64, inner_micros: u64, drain_micros: u64) {
        self.stats.xsync_calls.fetch_add(1, Ordering::Relaxed);
        self.stats
            .xsync_micros
            .fetch_add(total_micros, Ordering::Relaxed);
        self.stats
            .xsync_inner_micros
            .fetch_add(inner_micros, Ordering::Relaxed);
        self.stats
            .xsync_drain_micros
            .fetch_add(drain_micros, Ordering::Relaxed);
        self.stats
            .last_xsync_micros
            .store(total_micros, Ordering::Relaxed);
        self.stats
            .last_xsync_inner_micros
            .store(inner_micros, Ordering::Relaxed);
        self.stats
            .last_xsync_drain_micros
            .store(drain_micros, Ordering::Relaxed);
    }

    pub async fn submit_frame(&self, wal_offset: i64, page_no: u32, data: Vec<u8>) -> Result<()> {
        self.submit_record(WalRecord::Frame {
            wal_offset,
            page_no,
            data,
        })
        .await
    }

    pub fn runtime_handle(&self) -> &Handle {
        &self.runtime_handle
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

    /// Highest WAL byte offset known committed on this node.
    pub fn committed_wal_offset(&self) -> u64 {
        self.committed_wal_offset.load(Ordering::Acquire)
    }

    pub fn submit_stats(&self) -> RaftSubmitStats {
        RaftSubmitStats {
            xsync_calls: self.stats.xsync_calls.load(Ordering::Relaxed),
            xsync_micros: self.stats.xsync_micros.load(Ordering::Relaxed),
            xsync_inner_micros: self.stats.xsync_inner_micros.load(Ordering::Relaxed),
            xsync_drain_micros: self.stats.xsync_drain_micros.load(Ordering::Relaxed),
            submit_syncs: self.stats.submit_syncs.load(Ordering::Relaxed),
            submit_records: self.stats.submit_records.load(Ordering::Relaxed),
            submit_frames: self.stats.submit_frames.load(Ordering::Relaxed),
            submit_micros: self.stats.submit_micros.load(Ordering::Relaxed),
            max_submit_micros: self.stats.max_submit_micros.load(Ordering::Relaxed),
            last_xsync_micros: self.stats.last_xsync_micros.load(Ordering::Relaxed),
            last_xsync_inner_micros: self.stats.last_xsync_inner_micros.load(Ordering::Relaxed),
            last_xsync_drain_micros: self.stats.last_xsync_drain_micros.load(Ordering::Relaxed),
            last_submit_records: self.stats.last_submit_records.load(Ordering::Relaxed),
            last_submit_frames: self.stats.last_submit_frames.load(Ordering::Relaxed),
            last_submit_micros: self.stats.last_submit_micros.load(Ordering::Relaxed),
        }
    }

    /// Explicit multi-node bootstrap for initial cluster membership.
    pub async fn initialize_cluster(&self, members: BTreeMap<NodeId, BasicNode>) -> Result<()> {
        self.raft
            .initialize(members)
            .await
            .context("failed to initialize raft cluster")?;
        Ok(())
    }

    /// Return the current voter-id set from raft metrics.
    pub fn voter_ids(&self) -> BTreeSet<NodeId> {
        self.metrics()
            .membership_config
            .membership()
            .voter_ids()
            .collect()
    }

    /// Add a learner to the local leader's cluster.
    pub async fn add_learner(
        &self,
        node_id: NodeId,
        rpc_addr: String,
        blocking: bool,
    ) -> Result<()> {
        self.raft
            .add_learner(node_id, BasicNode::new(rpc_addr), blocking)
            .await
            .context("failed to add raft learner")?;
        Ok(())
    }

    /// Change cluster membership to the provided voter set.
    pub async fn change_membership(&self, voters: BTreeSet<NodeId>, retain: bool) -> Result<()> {
        self.raft
            .change_membership(voters, retain)
            .await
            .context("failed to change raft membership")?;
        Ok(())
    }

    /// Wait until membership voters match `expected`.
    pub async fn wait_for_voter_ids(
        &self,
        expected: BTreeSet<NodeId>,
        timeout: Duration,
    ) -> Result<()> {
        self.raft
            .wait(Some(timeout))
            .voter_ids(expected, "wait for voter membership")
            .await
            .context("timed out waiting for raft voter membership")?;
        Ok(())
    }

    /// Shutdown the local raft runtime.
    pub async fn shutdown(&self) -> Result<()> {
        self.raft
            .shutdown()
            .await
            .map_err(|e| anyhow::anyhow!("failed to shutdown raft: {e:?}"))?;
        Ok(())
    }
}
