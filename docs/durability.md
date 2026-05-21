# Durability And Recovery

## Persistent Raft Storage

Raft storage is optional at the low-level API and enabled by the existing cluster
initialization path. Passing `storage_path` to `RaftHandle::start` persists:

- log entries carrying `WalBatch` records
- current vote
- committed log id
- last purged log id
- last applied log id
- membership state
- snapshot bytes and snapshot metadata
- highest committed WAL offset

The on-disk layout is one JSON document per node:

```text
<database>.node<N>.evfs-raft-state.json
```

Writes use a temporary file plus rename. This gives crash-safe replacement on
the local filesystem for complete state documents. The format is separate from
the EVFS keyring (`*.evfs-keyring`) and Raft configuration sidecar, so encryption
metadata, Raft membership/configuration, and Raft log/state can be recovered or
diagnosed independently.

On startup, `WalStorageInner::new` loads the persisted document if present,
rebuilds in-memory Raft log/state, and re-applies persisted normal log batches
through the configured apply callback before the node joins the cluster.

## Crash Consistency Matrix

| Failure point | Expected result |
| --- | --- |
| Before WAL append | No committed logical change; recovery validates previous state. |
| After WAL append, before Raft submit | Leader truncates uncommitted bytes back to committed offset on step-down/restart. |
| During Raft submit | Entry is either absent or recoverable from persisted Raft state. |
| After Raft commit, before follower replay | Followers catch up from persisted log or leader replication. |
| During follower replay | Replay is idempotent by WAL offset/page replacement and retried after restart. |
| During materialization | Materialization resumes from replayed WAL/main DB state and validates offsets. |
| During checkpoint | Checkpoint orchestration is conservative; logical validation remains required after restart. |
| During keyring write | Missing/corrupt keyring fails closed. |
| During EVFS sidecar write | Missing/corrupt sidecar fails closed or requires operator repair/reseed. |

CI-safe coverage lives in `chaostest` short scenarios. Exhaustive failure-point
injection should run longer with fixed seeds and retained artifacts.

## Recovery Verifier / Doctor Checks

The recovery verifier and doctor model use the same status surface as
`evfs_raft_status()` plus loadtest/chaostest invariant validation:

- EVFS keyring exists, decodes, and unwraps with the configured KEK.
- Raft config sidecar exists and matches the SQLite-persisted config when both
  are present.
- Raft state sidecar exists for clustered nodes and decodes as a full state
  document.
- Leader committed WAL offset is greater than or equal to follower replay and
  materialization offsets.
- sqlsec metadata tables exist and logical views are fresh.
- audit metadata exists and audit-log non-leakage checks pass.
- application invariants hold: balance conservation, non-negative balances,
  expected order state, and transfer/order/audit row counts.

Human output should report `PASS`, `WARN`, or `FAIL`; JSON output should include
the same statuses, node ids, paths, offsets, seeds, scenario names, and failure
point metadata.

## Remaining Limitations

- Raft state documents are whole-file JSON for debuggability, not a high-volume
  production log store.
- Checkpoint-to-snapshot integration remains explicit rather than automatic.
- Full failover semantics depend on the current `openraft` membership and
  election behavior plus the surrounding supervisor/harness orchestration.
