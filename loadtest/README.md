# loadtest

`loadtest` is a standalone Rust application that drives a longer-running, more application-shaped SQLite workload than `lazytest`.

It exercises:

- `sqlsec` secured views and context changes
- `sqlevfs` encrypted storage
- `sqlevfs` Raft replication in a local 3-node topology
- `sqlshim` custom SQL rewriting when launched under `LD_PRELOAD`

## Usage

```bash
../run-loadtest --release --engine cluster --duration-secs 60 --workers 8
```

From inside `loadtest/`:

```bash
EVFS_KEYFILE=/tmp/evfs-loadtest-master.key \
LD_PRELOAD=../sqlshim/target/release/libsqlshim.so \
target/release/loadtest --engine cluster --duration-secs 60 --workers 8
```

## Modes

- `baseline`: plain SQLite
- `secure`: SQLite + `sqlsec` + `sqlevfs`
- `cluster`: SQLite + `sqlsec` + `sqlevfs` Raft, intended to run with `sqlshim`

## What it validates

- account-balance conservation
- transfer/order/audit row counts
- no negative balances
- expected order terminal states
- `sqlsec` visibility behavior for user/admin/ops contexts
- encrypted-file plaintext leakage checks for EVFS-backed modes
- leader/follower convergence and follower write rejection in cluster mode
