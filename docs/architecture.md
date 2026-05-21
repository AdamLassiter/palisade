# Palisade Architecture

Palisade is a SQLite security and extension toolkit made from independent
crates that can be combined in one process.

## Components

- `sqlsec`: label-based row and column policy implemented with SQLite metadata,
  views, triggers, and scalar functions.
- `sqlevfs`: an encrypted SQLite VFS. It encrypts main database pages 2 and up
  with per-page AES-256-GCM and stores wrapped DEKs in an EVFS keyring sidecar.
- `sqlevfs` Raft mode: a replicated WAL path. Leaders accept writes, submit WAL
  batches to Raft, and followers replay committed records into local WAL/main DB
  materialization.
- `sqlshim`: an `LD_PRELOAD` SQL prepare-time rewriter for convenience syntax
  and policy-oriented query transformations.
- `lazytest`: a preload-friendly smoke/performance harness.
- `loadtest`: an application-shaped throughput and validation harness.
- `chaostest`: a supervised process failure and recovery harness.

## Standalone Secure Data Flow

1. The application opens SQLite through the `evfs` VFS.
2. SQLite writes main DB pages through `sqlevfs`.
3. `sqlevfs` leaves page 1 plaintext and encrypts pages 2+ before disk writes.
4. The application queries logical `sqlsec` views.
5. `sqlsec` filters rows/columns and records configured audit metadata for
   secured writes.

Plaintext can exist in process memory, SQLite page cache, page 1 schema data,
temporary SQLite files outside the main DB, and any application logs the caller
chooses to emit. EVFS protects persisted main DB pages, not SQL semantics.

## Clustered Data Flow

1. Each node opens its local DB through a node-specific Raft VFS.
2. Only the current leader is allowed to take the SQLite write lock.
3. On `xSync`, the leader submits accumulated WAL records to Raft.
4. Raft persists votes, committed metadata, membership, snapshots, log entries,
   and committed WAL offset in a node-local `*.evfs-raft-state.json` file.
5. Followers replay committed records and materialize readable local databases.

The EVFS keyring sidecar and Raft sidecar are intentionally separate. Keyring
loss/corruption fails database open; Raft sidecar loss/corruption fails cluster
state recovery for the affected node until repaired or re-seeded.

## Validation Strategy

- `sqlsec` integration tests exercise label parsing, context scoping,
  view/trigger enforcement, update constraints, and audit behavior.
- `sqlevfs` integration tests exercise crypto, keyring persistence, backup,
  restore, VFS behavior, and Raft storage/replay helpers.
- `lazytest` verifies combined extension behavior under a real SQLite process.
- `loadtest` validates logical invariants, sqlsec visibility, plaintext leakage,
  cluster convergence, follower replay/materialization, and follower write
  rejection.
- `chaostest` validates process death/restart, key loss, sidecar corruption, and
  post-recovery invariants.

Known limitations are tracked in `docs/threat-model.md` and the root capability
matrix.
