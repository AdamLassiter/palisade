# TODO

## Developer Experience

### 0. Rust library usage vs. C library usage

Raft configuration expects rust crate bindings to be called.
These could be extracted into environment variables to enable configuring consensus replication when built as a dylib.

---

## Replication Correctness

### 1. Wire `apply_fn` to real WAL replay on followers

`WalStateMachine` invokes `apply_fn`, but production code still lacks a concrete follower replay path that writes committed WAL frames into follower SQLite state via inner VFS handles.

### 2. End-to-end Raft submission from SQLite WAL writes

The WAL buffering/submission path in the VFS needs a full correctness pass so committed transactions are reliably submitted at `xSync` under all partial-write/frame-boundary patterns.

### 3. True multi-node integration test coverage

Current tests validate single-node and bridged behavior, but we still need stable real multi-node leader/follower tests over Raft RPC for full transaction propagation.

---

## Durability / Operations

### 4. Persistent Raft storage

`WalLogStore` is still in-memory (`BTreeMap`). Crash/restart loses Raft log and metadata.

### 5. Checkpoint/snapshot integration

SQLite checkpoint lifecycle is not yet integrated with `trigger_snapshot` and log compaction.

### 6. Backpressure controls

No explicit limit/flow-control exists to prevent SQLite WAL production from outpacing Raft commit/apply throughput.

---

## Security Hardening

### 7. Passphrase KDF salt handling

Device passphrase mode still uses a fixed salt. Move to per-database random salt persisted alongside DB metadata.

### 8. Plaintext metadata leakage from page 1

Page 1 remains plaintext by design, exposing schema metadata. Documented, but still an open security limitation.
