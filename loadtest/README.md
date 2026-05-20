# loadtest

`loadtest` is a standalone Rust application that drives a longer-running, more application-shaped SQLite workload than `lazytest`.

It exercises:

- `sqlsec` secured views and context changes
- `sqlevfs` encrypted storage
- `sqlevfs` Raft replication in a local 3-node topology
- `sqlshim` custom SQL rewriting when launched under `LD_PRELOAD`

## Usage

```bash
../run-loadtest --release --engine cluster --workload transfer-heavy --duration-secs 60 --workers 8
```

From inside `loadtest/`:

```bash
EVFS_KEYFILE=/tmp/evfs-loadtest-master.key \
LD_PRELOAD=../sqlshim/target/release/libsqlshim.so \
target/release/loadtest --engine cluster --duration-secs 60 --workers 8
```

## Engines

- `sqlite`: plain SQLite through `rusqlite`, with no `sqlsec`, `sqlevfs`, or `sqlshim`
- `secure`: SQLite + `sqlsec` + `sqlevfs`
- `cluster`: SQLite + `sqlsec` + `sqlevfs` Raft, intended to run with `sqlshim`
- `all`: run every engine and print a roll-up

`baseline` is accepted as a deprecated alias for `sqlite`.

## Workloads

- `balanced`: mixed reads, writes, transfers, and admin scans
- `read-heavy`: tenant point/range reads with light writes
- `write-heavy`: order creation/update pressure
- `transfer-heavy`: multi-row transfer transactions
- `scan-heavy`: admin aggregate scans
- `contention`: hot-tenant writes and transfers
- `all`: run every workload profile and print a roll-up

When both `--engine all` and `--workload all` are used, `--output workloads`
prints workloads grouped under each engine, and `--output engines` prints engines
grouped under each workload. The default is `workloads`.

## What it validates

- account-balance conservation
- transfer/order/audit row counts
- no negative balances
- expected order terminal states
- `sqlsec` visibility behavior for user/admin/ops contexts
- `sqlsec` audit metadata initialization and audit-log non-leakage checks
- encrypted-file plaintext leakage checks for EVFS-backed modes
- leader/follower convergence and follower write rejection in cluster mode
