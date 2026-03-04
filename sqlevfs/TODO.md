# TODO

## Critical Gaps

### 1. VFS Layer Itself

The notes describe the entire VFS interception layer but **none of it exists**. There's no:

- `sqlite3_vfs` registration
- `xWrite` / `xRead` / `xSync` / `xLock` implementations
- `EvfsFile` struct (referenced in comments but absent)
- WAL vs. main DB file discrimination logic

`WalFileState` exists but nothing calls it — it's an orphan.

- [x] Done

### 2. `xLock` / Leader Guard

The notes say non-leaders must refuse `SQLITE_LOCK_RESERVED`. That gate is never implemented. Any node can currently attempt writes.

- [x] Done

### 3. `apply_fn` Is Never Wired

`WalStateMachine` calls `apply_fn` on commit, but nothing constructs a meaningful one. The VFS layer that would provide it doesn't exist, so committed frames go nowhere on followers.

### 4. `TruncateCallback` Is Never Invoked

`RaftHandle` stores `truncate_cb` but never calls it — there's no watch on leader step-down events (e.g. polling `metrics()` for leader change).

- [x] Done

---

## Storage / Correctness Issues

### 5. In-Memory Only Storage

`WalLogStore` is a `BTreeMap` — explicitly noted as non-production. A crash loses the entire Raft log, violating durability.

### 6. `append_entries` Silently Drops Non-Normal Entries

In `network/mod.rs`, the `filter_map` skips `Membership` and `Blank` entries over the wire. This can corrupt cluster membership state on followers.

- [x] Done

### 7. `committed_wal_offset` Is Unused

It's stored after `client_write` but never read by anything.

- [x] Done

---

## Multi-Node / Protocol Gaps

### 8. Multi-Node Initialization

`RaftHandle::start` only auto-initializes single-node clusters. Multi-node clusters need explicit cluster membership bootstrapping (a join/init flow).

- [x] Done

### 9. gRPC Server Is Never Started

`serve_grpc` exists but is never called from `RaftHandle::start` or anywhere observable. Peers can't receive RPCs.

- [x] Done

### 10. No Reconnection / Backoff in `PeerNetwork`

Every RPC call does a fresh `connect()` with no retry, backoff, or connection pooling — a new TCP handshake per log entry.

- [x] Done

---

## Operational Gaps

### 11. No Checkpointing Integration

The notes describe SQLite WAL checkpointing as the trigger for `trigger_snapshot`, but nothing calls it, and there's no WAL checkpoint logic.

### 12. No Backpressure

Notes flag this explicitly. Nothing prevents SQLite from writing WAL faster than Raft can commit, which would cause unbounded buffering or silent data loss.

### 13. Proto File Missing

`tonic::include_proto!("sqlevfs.raft")` references a `.proto` file that isn't in the provided code.

- [x] Done
