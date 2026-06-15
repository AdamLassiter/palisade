# SQLite Security & Extension Toolkit

This repo contains a set of small, composable systems for testing and enforcing security controls around SQLite. Each component is independent, but they’re designed to work together (often via `LD_PRELOAD`) so you can mix-and-match behaviors in a single process.

## Components

### 1) `sqlsec` — Label-Based Security (in-SQL enforcement)

`sqlsec` is a SQLite extension that implements **row-level and column-level security** using:

- **Security labels**: boolean expressions over context attributes (e.g. `role=admin&team=finance`)
- **Logical views**: apps query views; views filter rows/columns based on labels
- **INSTEAD OF triggers**: safe `INSERT/UPDATE/DELETE` through secure views
- **Context attributes** with push/pop scoping
- Optional **MLS-style levels** with dominance (`clearance>=secret`)

Enforcement is performed *inside SQLite* using views + triggers (no app-side filtering).

See: the `sqlsec` README (full model, syntax, function reference, constraints).

---

### 2) `sqlevfs` — Encrypted VFS (page-at-rest encryption)

`sqlevfs` registers a custom SQLite VFS (`evfs`) that wraps the OS VFS and provides **transparent page encryption**:

- AES-256-GCM per page, DEK managed via envelope encryption (KEK from a provider)
- Wrapped DEKs persisted in a **sidecar** file next to the DB
- Supports **partial I/O** via read-modify-write for correctness
- Encrypts the **main DB file**; journaling/WAL/temp files pass through
- Uses an on-page marker (`EVFSv1`) stored in reserved bytes to detect encrypted pages
- **Page 1 is plaintext** (required for SQLite to read schema/open DB); pages 2+ encrypted

This is primarily an *at-rest* control: it protects database pages on disk, not SQL semantics.

---

### 3) `sqlshim` — `LD_PRELOAD` SQL Rewriter (prepare-time rewriting)

`sqlshim` is a tiny `LD_PRELOAD` shim that hooks SQLite prepare APIs (e.g. `sqlite3_prepare_v2`) and **parses + rewrites SQL text at runtime**.

It’s useful for “drop-in” policy transformations without changing the application binary, such as:

- injecting tenant filters
- blocking/rewriting dangerous statements
- renaming tables/columns
- normalizing queries for logging/auditing

Rewriting occurs at prepare-time by modifying SQL text before SQLite compiles it.

---

### 4) `lazytest` — Preload-Friendly Test Harness

`lazytest` is a small Rust binary that runs SQLite workloads specifically to make it easy to test combinations of shims/extensions under `LD_PRELOAD`.

It helps you:

- reproduce issues in a controlled process
- validate that multiple components work together (e.g. `sqlshim` + `sqlsec` + `sqlevfs`)
- run targeted end-to-end scenarios without modifying an application

---

### 5) `loadtest` — Application-Shaped Benchmark & Validation Harness

`loadtest` is a longer-running benchmark harness for exercising the stack under concurrent, application-shaped workloads. It can run plain SQLite, secured/encrypted SQLite, or a local 3-node Raft cluster and then validate the resulting database state.

It reports:

- total, read, and write throughput
- per-operation counts and average latencies
- lock/busy conflict counts split by operation type
- workload overrun when slow in-flight operations finish after the target duration
- validation timing and, for cluster runs, Raft replay/materialization/WAL-sync metrics

---

### 6) `chaostest` — Durability & Failure-Recovery Harness

`chaostest` is a process-supervised chaos harness for the Raft/EVFS/sqlsec stack. Unlike `loadtest`, it runs each Raft node as a child process so failure injection uses real process death and restart.

It currently exercises:

- follower process kill/restart, leader restart, and whole-process restart using persisted Raft state
- EVFS key loss and sidecar corruption fail-closed checks
- aggregate invariants, sqlsec audit non-leakage, ciphertext sanity, replay/materialization offsets, and follower write rejection where the scenario reaches validation

---

## How they fit together

Common combinations:

- **At-rest encryption + in-DB access control**: `sqlevfs` protects on-disk pages; `sqlsec` enforces row/column rules inside SQLite.
- **Query rewriting + in-DB access control**: `sqlshim` can enforce “mandatory predicates” or block statements; `sqlsec` remains the source of truth for visibility/update rules.
- **All three**: `sqlshim` shapes incoming SQL, `sqlsec` enforces label-based policy, `sqlevfs` encrypts pages on disk.
- Use **`lazytest`** as the harness to run these stacks under `LD_PRELOAD`.
- Use **`loadtest`** to compare throughput, contention behavior, validation correctness, and clustered Raft replication metrics across engines and workloads.
- Use **`chaostest`** to test durability, failure handling, and recovery gaps with real supervised Raft node processes.

## Combined usage (conceptual)

- Load `sqlsec` as a SQLite extension when you need label-based RLS/CLS.
- Register `sqlevfs` (VFS `evfs`) when you need at-rest encryption.
- Preload `sqlshim` when you need runtime SQL rewriting without changing the app.
- Use `lazytest` to exercise and validate the stack.

(Each component has its own build/run instructions in its respective README.)

## Quickstart

To run the test harness application:

```sh
./run-lazytest
```

To run all Rust tests with each crate's required SQLite feature set:

```sh
./run-workspace-tests
```

To run a distributed replicated cluster harness:

```sh
./run-loadtest
```

To run a durability/failure-recovery harness:

```sh
./run-chaostest
```

## Loadtest

The top-level `run-loadtest` script builds the workspace, creates a temporary EVFS key, sets up the `sqlshim` preload for secured engines, and runs `loadtest`.

```sh
./run-loadtest --release --engine cluster --workload transfer-heavy --duration-secs 10 --workers 8
```

Defaults are debug mode, `engine=cluster`, `workload=balanced`, `duration=60s`, `workers=8`, and a fixed seed.

### Engines

- `sqlite`: plain SQLite through `rusqlite`
- `secure`: SQLite + `sqlsec` + `sqlevfs`
- `cluster`: SQLite + `sqlsec` + `sqlevfs` Raft in a local 3-node topology
- `all`: run `sqlite`, `secure`, and `cluster`

`baseline` is accepted as a deprecated alias for `sqlite`.

### Workloads

- `balanced`: mixed reads, writes, transfers, and admin scans
- `read-heavy`: tenant point/range reads with light writes
- `write-heavy`: order creation/update pressure
- `transfer-heavy`: multi-row transfer transactions
- `scan-heavy`: admin aggregate scans
- `contention`: hot-tenant writes and transfers
- `all`: run every workload profile

Examples:

```sh
./run-loadtest --release --engine all --workload transfer-heavy --duration-secs 10 --workers 8
./run-loadtest --release --engine cluster --workload all --duration-secs 5 --workers 4
./run-loadtest --release --engine all --workload all --output workloads --duration-secs 5 --workers 4
./run-loadtest --release --engine all --workload all --output engines --duration-secs 5 --workers 4
```

When `--engine all` is used with one workload, the roll-up is grouped by engine. When `--workload all` is used with one engine, the roll-up is grouped by workload. When both are `all`, `--output workloads` groups workloads under each engine and `--output engines` groups engines under each workload; the default is `workloads`.

### Validation and Metrics

Each run seeds a database, executes the selected workload unless `--validate-only` is set, and validates:

- account-balance conservation and non-negative balances
- transfer, order, and audit row counts
- expected order terminal states
- `sqlsec` visibility for user/admin/ops contexts
- `sqlsec` audit metadata and audit-log non-leakage
- encrypted-file plaintext leakage checks for EVFS-backed modes
- cluster leader/follower convergence and follower write rejection

For cluster runs, validation waits for follower Raft replay and materialized follower DB state to catch up before comparing aggregates. The output includes leader submit timing, replay apply timing, follower WAL sync timing, materialization timing, queue depth, and replay offsets.

### Useful Flags

- `--debug` / `--release`: select build profile
- `--duration-secs N`: target workload duration
- `--workers N`: concurrent worker count
- `--seed N`: deterministic seed
- `--ramp-secs N`: worker ramp-up duration
- `--validate-only`: seed and validate without running the workload
- `--keep-artifacts`: keep the temporary workspace for inspection
- `--cluster-follower-wal-sync per-batch|coalesced`: choose follower WAL sync policy for cluster runs
- `--cluster-follower-wal-sync-batches N`: coalesced sync batch threshold, default `64`
- `--cluster-follower-wal-sync-ms N`: coalesced sync delay threshold, default `5`
- `--cluster-raft-storage memory|persistent`: choose in-memory benchmark storage
  or persistent Raft state. `loadtest` defaults to `memory`; use `persistent`
  for durability-oriented measurements.

The default cluster follower WAL sync policy is `per-batch`, which syncs follower WAL once per applied Raft batch. `coalesced` is an explicit benchmark/performance mode that writes follower WAL immediately but syncs it after the configured batch or delay threshold; this can improve write-heavy clustered benchmarks while weakening follower crash durability inside the sync window.

More detail lives in [`loadtest/README.md`](loadtest/README.md).

## Chaostest

The top-level `run-chaostest` script builds the workspace, creates an EVFS key, sets up the `sqlshim` preload, and runs `chaostest`.

```sh
./run-chaostest --scenario key-loss --duration-secs 1 --workers 1
./run-chaostest --scenario sidecar-corrupt --duration-secs 1 --workers 1
./run-chaostest --scenario follower-kill --duration-secs 1 --workers 1 --keep-artifacts
```

Defaults are debug mode, `scenario=follower-kill`, `duration=5s`, `workers=4`, and a fixed seed.

Scenarios:

- `follower-kill`: kills a follower process, continues writes, restarts it, then waits for replay/materialization convergence using node-local persisted Raft state.
- `key-loss`: replaces the EVFS key and verifies the encrypted DB fails closed.
- `sidecar-corrupt`: corrupts the EVFS keyring sidecar and verifies the DB fails closed.
- `leader-kill` and `whole-process-restart`: runnable with `--include-known-gaps` so CI defaults stay short while durability restart scenarios remain explicit.
- `all`: runs the default pass/gap matrix.

Use `--keep-artifacts` to retain per-node stdout/stderr logs and `chaostest-report.json`.

More detail lives in [`chaostest/README.md`](chaostest/README.md).

## Capability Matrix

| Capability | `sqlite` | `secure` | `cluster` |
| --- | --- | --- | --- |
| Main DB page encryption | No | Yes, via `sqlevfs` pages 2+ | Yes, per node via `sqlevfs` |
| Row/column policy enforcement | No | Yes, via `sqlsec` views/triggers | Yes, on every node using the secured schema |
| Audit metadata | No | Yes, successful secured writes | Yes, replicated with the database workload |
| Replication | No | No | Yes, Raft WAL replication |
| Follower write rejection | N/A | N/A | Yes, followers refuse leader-only write locks |
| Process restart recovery | SQLite defaults | EVFS keyring + SQLite recovery | Persisted Raft votes/log/membership/snapshot/offset state |
| Backup/restore | SQLite-native only | Encrypted EVFS backup API | Restore DB content, then validate/rebuild cluster state |
| Key rotation | External | Backup KEK rotation; full DEK replacement through restore | Same, per node/workspace |
| Known limitations | No Palisade controls | Page 1 plaintext; temp files out of scope | Checkpoint-to-snapshot orchestration is conservative |

Architecture, durability, security operations, and threat-model details live in
[`docs/architecture.md`](docs/architecture.md), [`docs/durability.md`](docs/durability.md),
[`docs/security-operations.md`](docs/security-operations.md), and
[`docs/threat-model.md`](docs/threat-model.md).
