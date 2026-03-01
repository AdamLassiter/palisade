//! Distributed replication via openraft + tonic gRPC.
//!
//! # Design contract with `vfs.rs`
//!
//! * `RaftHandle` is `Arc`-shared across all file descriptors that
//!   belong to the same database.
//! * `WalFileState` is per-file-descriptor state that the VFS layer
//!   stores inside `EvfsFile` for WAL file descriptors only.
//! * The VFS calls [`RaftHandle::submit_frame`] once it has a full,
//!   already-encrypted WAL frame ready to be written.
//! * The VFS exposes a [`TruncateCallback`] so the Raft layer can ask
//!   it to roll back the local WAL when the leader steps down.

pub mod handle;
pub mod network;
pub mod rpc;
pub mod wal;

use std::io::Cursor;

use anyhow::Result;
use openraft::{BasicNode, Entry, Raft, declare_raft_types};

pub mod proto {
    tonic::include_proto!("sqlevfs.raft");
}

use crate::vfs::consensus::wal::WalFrameEntry;

declare_raft_types!(
    pub RaftConfig:
        D              = WalFrameEntry,
        R              = (),
        NodeId         = u64,
        Node           = BasicNode,
        Entry          = Entry<RaftConfig>,
        SnapshotData   = Cursor<Vec<u8>>,
        AsyncRuntime   = openraft::TokioRuntime,
);

pub type NodeId = u64;
pub type RaftNode = Raft<RaftConfig>;

/// Callback the Raft layer invokes when the local WAL must be
/// truncated (e.g. a leader steps down and uncommitted frames must
/// be rolled back).
///
/// The argument is the byte offset to truncate *at* — all WAL content
/// at or beyond this offset is discarded.
pub type TruncateCallback = Box<dyn Fn(/*wal_offset_bytes:*/ i64) -> Result<()> + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::consensus::wal::WalFileState;

    #[test]
    fn wal_state_accumulates_partial_writes() {
        let page_size: u32 = 4096;
        let frame_size = page_size as usize + 24;
        let mut ws = WalFileState::new("main", page_size);

        // Write half a frame.
        let half = vec![0xAAu8; frame_size / 2];
        let frames = ws.push(&half, 32); // WAL header is 32 bytes
        assert!(frames.is_empty(), "no complete frame yet");

        // Write the other half.
        let other_half = vec![0xBBu8; frame_size / 2];
        let frames = ws.push(&other_half, 32 + (frame_size / 2) as i64);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, 32); // correct offset
        assert_eq!(frames[0].2.len(), frame_size);
    }

    #[test]
    fn wal_state_resets_on_seek() {
        let page_size: u32 = 4096;
        let mut ws = WalFileState::new("main", page_size);

        // Partial write at offset 32.
        let partial = vec![0u8; 100];
        ws.push(&partial, 32);
        assert_eq!(ws.frame_buf.len(), 100);

        // Write at a completely different offset — buffer must reset.
        let partial2 = vec![0u8; 50];
        ws.push(&partial2, 9999);
        assert_eq!(ws.frame_buf.len(), 50);
        assert_eq!(ws.pending_offset, 9999);
    }

    #[test]
    fn wal_state_multiple_frames_in_one_write() {
        let page_size: u32 = 4096;
        let frame_size = page_size as usize + 24;
        let mut ws = WalFileState::new("main", page_size);

        // Write exactly 3 frames at once.
        let data = vec![0u8; frame_size * 3];
        let frames = ws.push(&data, 32);
        assert_eq!(frames.len(), 3);
        // Offsets should be contiguous.
        assert_eq!(frames[0].0, 32);
        assert_eq!(frames[1].0, 32 + frame_size as i64);
        assert_eq!(frames[2].0, 32 + frame_size as i64 * 2);
    }
}
