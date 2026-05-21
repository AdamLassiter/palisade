# Threat Model

## Protected Assets

- Plaintext application data
- EVFS KEKs, DEKs, wrapped DEKs, and keyring metadata
- sqlsec policies, labels, context metadata, and secured views/triggers
- Audit history and audit chain metadata
- Raft log contents, votes, membership, committed indexes, snapshots, and replay
  offsets
- Backup files and restore metadata

## Attacker Capabilities

- Steals database files from disk
- Reads or tampers with EVFS keyring, Raft state, Raft config, or backup sidecars
- Loses or replaces key material
- Issues malicious tenant SQL through the application
- Kills processes before, during, or after durability boundaries
- Partially partitions or restarts cluster nodes
- Reads application logs and process-visible temporary files

## Mitigations

- `sqlevfs` encrypts main DB pages 2+ and authenticates encrypted pages.
- EVFS keyrings store wrapped DEKs only; wrong/corrupt key material fails closed.
- `sqlsec` performs in-database row/column enforcement through views/triggers.
- `sqlshim` can rewrite convenience policy SQL before SQLite prepares it.
- Audit logging records secured write metadata without protected column values.
- Raft leader gating rejects follower writes and replicated WAL records converge
  follower materialized state.
- Persistent Raft sidecars let nodes recover votes, membership, logs, snapshots,
  and committed offsets after restart.
- `loadtest` and `chaostest` exercise visibility, encryption leakage, replay,
  materialization, key loss, sidecar corruption, and process restart behavior.

## Non-Goals And Gaps

- Page 1 schema metadata is plaintext.
- SQLite temp files, process memory, and caller logs are outside EVFS protection.
- The audit chain requires external anchoring to prove history against a full
  database rewrite by a privileged storage attacker.
- Current Raft state persistence favors debuggability over production log-store
  scale.
- Automatic SQLite checkpoint to Raft snapshot orchestration is not complete.
- Online full database DEK re-encryption is operationally handled through backup
  and restore today.
