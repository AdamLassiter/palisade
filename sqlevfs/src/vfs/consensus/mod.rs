//! Distributed replication via openraft + tonic gRPC.
//!
//! # Design contract with `vfs.rs`
//!
//! * `RaftHandle` is `Arc`-shared across all file descriptors that
//!   belong to the same database.
//! * `WalFileState` is per-file-descriptor state that the VFS layer
//!   stores inside `EvfsFile` for WAL file descriptors only.
//! * The VFS calls [`RaftHandle::submit_record`] at `xSync` with the
//!   complete WAL header and frame records that make a follower replica
//!   readable through SQLite's normal WAL machinery.
//! * The VFS exposes a [`TruncateCallback`] so the Raft layer can ask
//!   it to roll back the local WAL when the leader steps down.

pub mod handle;
pub mod network;
pub mod replay;
pub mod rpc;
pub mod wal;

use std::io::Cursor;

use anyhow::Result;
use openraft::{BasicNode, Entry, Raft, declare_raft_types};

pub mod proto {
    tonic::include_proto!("sqlevfs.raft");
}

use crate::vfs::consensus::wal::WalRecord;

declare_raft_types!(
    pub RaftConfig:
        D              = WalRecord,
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
    use crate::vfs::consensus::wal::{WalFileState, WalRecord};

    #[test]
    fn wal_state_accumulates_header_and_partial_frame_until_sync() {
        let page_size: u32 = 4096;
        let frame_size = page_size as usize + 24;
        let mut ws = WalFileState::new("main", page_size);
        let header = vec![0xABu8; 32];
        let mut frame = vec![0xCDu8; frame_size];
        frame[0..4].copy_from_slice(&7u32.to_be_bytes());

        ws.push(&header[..16], 0);
        assert!(
            ws.drain_for_sync().is_empty(),
            "partial header should not drain"
        );

        ws.push(&header[16..], 16);
        ws.push(&frame[..(frame_size / 2)], 32);
        assert_eq!(
            ws.drain_for_sync(),
            vec![WalRecord::Header {
                data: header.clone()
            }]
        );

        ws.push(&frame[(frame_size / 2)..], 32 + (frame_size / 2) as i64);
        assert_eq!(
            ws.drain_for_sync(),
            vec![WalRecord::Frame {
                wal_offset: 32,
                page_no: 7,
                data: frame,
            }]
        );
    }

    #[test]
    fn wal_state_resets_on_seek() {
        let page_size: u32 = 4096;
        let mut ws = WalFileState::new("main", page_size);

        // Partial write at offset 32.
        let partial = vec![0u8; 100];
        ws.push(&partial, 32);
        assert_eq!(ws.pending_buf.len(), 100);

        // Write at a completely different offset — buffer must reset.
        let partial2 = vec![0u8; 50];
        ws.push(&partial2, 9999);
        assert_eq!(ws.pending_buf.len(), 50);
        assert_eq!(ws.pending_offset, 9999);
    }

    #[test]
    fn wal_state_multiple_records_in_one_write() {
        let page_size: u32 = 4096;
        let frame_size = page_size as usize + 24;
        let mut ws = WalFileState::new("main", page_size);
        let header = vec![0x11u8; 32];
        let mut data = header.clone();
        for page_no in 1..=3u32 {
            let mut frame = vec![page_no as u8; frame_size];
            frame[0..4].copy_from_slice(&page_no.to_be_bytes());
            data.extend_from_slice(&frame);
        }

        ws.push(&data, 0);
        let records = ws.drain_for_sync();
        assert_eq!(records.len(), 4);
        assert!(matches!(&records[0], WalRecord::Header { .. }));
        assert_eq!(records[1].wal_offset(), 32);
        assert_eq!(records[2].wal_offset(), 32 + frame_size as i64);
        assert_eq!(records[3].wal_offset(), 32 + frame_size as i64 * 2);
    }
}
