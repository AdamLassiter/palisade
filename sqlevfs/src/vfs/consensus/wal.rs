use std::{collections::BTreeMap, io::Cursor, sync::Arc};

use anyhow::Result;
use openraft::{
    BasicNode,
    Entry,
    EntryPayload,
    LogId,
    SnapshotMeta,
    StorageError,
    StoredMembership,
    Vote,
    storage::{RaftLogReader, RaftSnapshotBuilder, RaftStorage, Snapshot},
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::{
    debug,
    vfs::consensus::{NodeId, RaftConfig},
};

/// A single replicated WAL record that forms one Raft log entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalRecord {
    /// The SQLite WAL header at offset 0 for a WAL generation.
    Header { data: Vec<u8> },
    /// A WAL frame at byte offset >= 32.
    Frame {
        wal_offset: i64,
        page_no: u32,
        data: Vec<u8>,
    },
}

impl WalRecord {
    pub fn wal_offset(&self) -> i64 {
        match self {
            Self::Header { .. } => 0,
            Self::Frame { wal_offset, .. } => *wal_offset,
        }
    }
}

// -- WAL file state (per file descriptor) ----------------------------

/// Per-WAL-file-descriptor state owned by `EvfsFile`.
///
/// The VFS layer accumulates bytes written by SQLite into `pending_buf`
/// until it has a complete WAL header or frame, then queues those
/// records for submission at the next `xSync` durability barrier.
pub struct WalFileState {
    /// Parent database name (used for logging / snapshot tagging).
    pub db_name: String,
    /// Byte offset of the first buffered byte within the WAL file.
    pub pending_offset: i64,
    /// Bytes accumulated since the last record boundary.
    pub pending_buf: Vec<u8>,
    /// WAL frame size = page_size + 24-byte frame header.
    pub frame_size: usize,
    /// Complete WAL records waiting to be submitted on xSync.
    queued: Vec<WalRecord>,
}

impl WalFileState {
    pub fn new(db_name: impl Into<String>, page_size: u32) -> Self {
        Self {
            db_name: db_name.into(),
            pending_offset: 0,
            pending_buf: Vec::new(),
            // Each WAL frame = 24-byte header + one full page.
            frame_size: page_size as usize + 24,
            queued: Vec::new(),
        }
    }

    /// Feed bytes written at `wal_offset` into the accumulator.
    pub fn push(&mut self, data: &[u8], wal_offset: i64) {
        if wal_offset >= 32
            && (wal_offset - 32) % self.frame_size as i64 == 0
            && data.len() == self.frame_size
        {
            self.queue_frame(wal_offset, data.to_vec());
            self.pending_offset = wal_offset + self.frame_size as i64;
            self.pending_buf.clear();
            return;
        }

        // If the caller jumped (e.g. WAL header re-written), start a new
        // WAL generation and discard unsynced records from the old one.
        if wal_offset != self.pending_offset + self.pending_buf.len() as i64 {
            self.pending_buf.clear();
            self.queued.clear();
            self.pending_offset = wal_offset;
        }

        self.pending_buf.extend_from_slice(data);
        self.extract_complete_records();
    }

    pub fn drain_for_sync(&mut self) -> Vec<WalRecord> {
        std::mem::take(&mut self.queued)
    }

    fn extract_complete_records(&mut self) {
        loop {
            if self.pending_offset == 0 {
                if self.pending_buf.len() < 32 {
                    break;
                }
                let header: Vec<u8> = self.pending_buf.drain(..32).collect();
                self.pending_offset = 32;
                self.queued.push(WalRecord::Header { data: header });
                continue;
            }

            if self.pending_offset < 32 {
                // We only know how to materialize a WAL generation starting
                // from offset 0. Keep buffering until a reset or complete
                // header arrives.
                break;
            }

            if self.pending_buf.len() < self.frame_size {
                break;
            }

            let frame: Vec<u8> = self.pending_buf.drain(..self.frame_size).collect();
            let frame_offset = self.pending_offset;
            self.pending_offset += self.frame_size as i64;

            // WAL frame header layout (big-endian):
            //   0..4  page number
            //   4..8  "for commit" database size
            //   8..16 salt copy
            //   16..24 checksum
            let page_no = u32::from_be_bytes(frame[0..4].try_into().unwrap_or([0; 4]));

            self.queued.push(WalRecord::Frame {
                wal_offset: frame_offset,
                page_no,
                data: frame,
            });
        }
    }

    fn queue_frame(&mut self, wal_offset: i64, data: Vec<u8>) {
        let page_no = u32::from_be_bytes(data[0..4].try_into().unwrap_or([0; 4]));
        let replacement = WalRecord::Frame {
            wal_offset,
            page_no,
            data,
        };
        if let Some(existing) = self.queued.iter_mut().find(|record| {
            matches!(
                record,
                WalRecord::Frame {
                    wal_offset: existing_offset,
                    ..
                } if *existing_offset == wal_offset
            )
        }) {
            *existing = replacement;
        } else {
            self.queued.push(replacement);
        }
    }
}

// -- In-memory log storage --------------------------------------------
// NOTE: Replace with a persistent implementation (e.g. backed by a
// separate RocksDB / sled instance) before running in production.

#[derive(Default)]
pub struct WalLogStore {
    log: BTreeMap<u64, Entry<RaftConfig>>,
    /// (last_purged_log_id, vote)
    meta: RwLock<LogStoreMeta>,
}

#[derive(Default, Clone)]
struct LogStoreMeta {
    last_purged_log_id: Option<LogId<NodeId>>,
    vote: Option<Vote<NodeId>>,
}

// -- In-memory state machine ------------------------------------------

type ApplyFn = Arc<dyn Fn(WalRecord) -> Result<()> + Send + Sync>;

/// The WAL state machine: applies committed frames to the local SQLite
/// database by writing them directly to the WAL file via the OS.
///
/// In production this would hold a raw file handle to the WAL file
/// (opened under the *inner* VFS to avoid double-encryption) and
/// write frames directly.
pub struct WalStateMachine {
    /// Last log id applied.
    last_applied: Option<LogId<NodeId>>,
    /// Last membership configuration applied.
    last_membership: StoredMembership<NodeId, BasicNode>,
    /// Snapshot data (serialised DB).
    snapshot: Option<Vec<u8>>,
    /// Snapshot metadata.
    snapshot_meta: Option<SnapshotMeta<NodeId, BasicNode>>,
    /// Callback into the VFS layer: materialize a committed WAL record locally.
    apply_fn: ApplyFn,
}

impl WalStateMachine {
    pub fn new(apply_fn: impl Fn(WalRecord) -> Result<()> + Send + Sync + 'static) -> Self {
        Self {
            last_applied: None,
            last_membership: StoredMembership::default(),
            snapshot: None,
            snapshot_meta: None,
            apply_fn: Arc::new(apply_fn),
        }
    }
}

// -- openraft RaftStorage implementation -----------------------------
//
// openraft 0.9 seals `RaftLogStorage` and `RaftStateMachine` so they
// can only be implemented via the `Adaptor` wrapper around
// `RaftStorage`.  We implement the combined `RaftStorage` trait and
// let `Adaptor` split it into the two sealed halves.

impl RaftStorage<RaftConfig> for Arc<RwLock<WalStorageInner>> {
    type LogReader = Self;
    type SnapshotBuilder = Self;

    async fn get_log_state(
        &mut self,
    ) -> Result<openraft::storage::LogState<RaftConfig>, StorageError<NodeId>> {
        let s = self.read();
        let last = s.log_store.log.values().next_back().map(|e| e.log_id);
        Ok(openraft::storage::LogState {
            last_purged_log_id: s.log_store.meta.read().last_purged_log_id,
            last_log_id: last,
        })
    }

    async fn save_committed(
        &mut self,
        _committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        Ok(())
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        Ok(None)
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        self.write().log_store.meta.write().vote = Some(*vote);
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        Ok(self.read().log_store.meta.read().vote)
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn append_to_log<I>(&mut self, entries: I) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<RaftConfig>> + Send,
    {
        let mut s = self.write();
        for entry in entries {
            s.log_store.log.insert(entry.log_id.index, entry);
        }
        Ok(())
    }

    async fn delete_conflict_logs_since(
        &mut self,
        log_id: LogId<NodeId>,
    ) -> Result<(), StorageError<NodeId>> {
        self.write()
            .log_store
            .log
            .retain(|&idx, _| idx < log_id.index);
        Ok(())
    }

    async fn purge_logs_upto(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut s = self.write();
        s.log_store.log.retain(|&idx, _| idx > log_id.index);
        s.log_store.meta.write().last_purged_log_id = Some(log_id);
        Ok(())
    }

    async fn last_applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, BasicNode>), StorageError<NodeId>>
    {
        let s = self.read();
        Ok((
            s.state_machine.last_applied,
            s.state_machine.last_membership.clone(),
        ))
    }

    async fn apply_to_state_machine(
        &mut self,
        entries: &[Entry<RaftConfig>],
    ) -> Result<Vec<()>, StorageError<NodeId>> {
        let mut results = Vec::new();
        for entry in entries {
            let mut s = self.write();
            s.state_machine.last_applied = Some(entry.log_id);

            match &entry.payload {
                EntryPayload::Blank => {}
                EntryPayload::Normal(record) => {
                    let apply = s.state_machine.apply_fn.clone();
                    let record = record.clone();
                    drop(s);
                    if let Err(e) = apply(record.clone()) {
                        if debug() {
                            eprintln!(
                                "slqevfs: state machine apply error (offset={}): {e}",
                                record.wal_offset()
                            );
                        }
                        return Err(StorageError::IO {
                            source: openraft::StorageIOError::write_state_machine(
                                &std::io::Error::other(e.to_string()),
                            ),
                        });
                    }
                }
                EntryPayload::Membership(mem) => {
                    s.state_machine.last_membership =
                        StoredMembership::new(Some(entry.log_id), mem.clone());
                }
            }
            results.push(());
        }
        Ok(results)
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        let mut s = self.write();
        s.state_machine.snapshot = Some(snapshot.into_inner());
        s.state_machine.snapshot_meta = Some(meta.clone());
        s.state_machine.last_applied = meta.last_log_id;
        s.state_machine.last_membership = meta.last_membership.clone();
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<RaftConfig>>, StorageError<NodeId>> {
        let s = self.read();
        let Some(ref data) = s.state_machine.snapshot else {
            return Ok(None);
        };
        let Some(ref meta) = s.state_machine.snapshot_meta else {
            return Ok(None);
        };
        Ok(Some(Snapshot {
            meta: meta.clone(),
            snapshot: Box::new(Cursor::new(data.clone())),
        }))
    }
}

impl RaftLogReader<RaftConfig> for Arc<RwLock<WalStorageInner>> {
    async fn try_get_log_entries<
        RB: std::ops::RangeBounds<u64> + Clone + std::fmt::Debug + Send,
    >(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<RaftConfig>>, StorageError<NodeId>> {
        let s = self.read();
        let entries: Vec<_> = s
            .log_store
            .log
            .range(range)
            .map(|(_, e)| e.clone())
            .collect();
        Ok(entries)
    }
}

impl RaftSnapshotBuilder<RaftConfig> for Arc<RwLock<WalStorageInner>> {
    async fn build_snapshot(&mut self) -> Result<Snapshot<RaftConfig>, StorageError<NodeId>> {
        let s = self.read();
        let data = s.state_machine.snapshot.clone().unwrap_or_default();
        let meta = s
            .state_machine
            .snapshot_meta
            .clone()
            .unwrap_or_else(|| SnapshotMeta {
                last_log_id: s.state_machine.last_applied,
                last_membership: s.state_machine.last_membership.clone(),
                snapshot_id: format!(
                    "snap-{}",
                    s.state_machine.last_applied.map(|l| l.index).unwrap_or(0)
                ),
            });
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

/// Combined log + state-machine storage for the `Adaptor` wrapper.
pub struct WalStorageInner {
    pub(crate) log_store: WalLogStore,
    pub(crate) state_machine: WalStateMachine,
}
