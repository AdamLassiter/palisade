# chaostest

`chaostest` is a durability and failure-recovery harness for the Palisade Raft/EVFS/sqlsec stack. It is intentionally separate from `loadtest`: `loadtest` measures in-process workload behavior, while `chaostest` supervises real child processes so node death, restart, key loss, and sidecar corruption exercise process boundaries.

Run it through the top-level wrapper:

```sh
./run-chaostest --scenario key-loss --duration-secs 1 --workers 1
```

## CLI

- `--debug` / `--release`: select build profile
- `--scenario follower-kill|leader-kill|whole-process-restart|key-loss|sidecar-corrupt|all`
- `--duration-secs N`: workload duration, default `5`
- `--workers N`: workload workers, default `4`
- `--seed N`: deterministic seed
- `--keep-artifacts`: retain workspace, node logs, and report JSON
- `--include-known-gaps`: run scenarios that are expected to expose unfinished durability work
- `--cluster-follower-wal-sync per-batch|coalesced`: pass follower WAL sync policy into Raft init

## Architecture

Supervisor mode creates a workspace with `leader.db`, `node2.db`, `node3.db`, one EVFS keyfile, per-node logs, and `chaostest-report.json` when artifacts are retained or a failure occurs.

Each node is a hidden child process started with `chaostest --node ...`. The child loads `sqlevfs` and `sqlsec`, starts one `evfs_raft_init(...)` node, emits a JSON ready message, and then accepts newline-delimited JSON commands on stdin.

The child protocol currently supports status, seed, workload, local validation, follower write rejection probe, checkpoint, membership add, and shutdown commands.

## Scenario Status

- `PASS`: the scenario validated the expected safety property.
- `FAIL`: an unexpected error or invariant failure occurred.
- `KNOWN-GAP`: the scenario ran far enough to expose durability work that is not implemented yet.

Current classifications:

- `key-loss`: expected `PASS`.
- `sidecar-corrupt`: expected `PASS`.
- `follower-kill`: currently reports `KNOWN-GAP` after restart because follower replay/materialization does not recover from persisted Raft state.
- `leader-kill`: known gap until leader election/recovery is backed by persistent Raft storage.
- `whole-process-restart`: known gap until Raft state survives full process restart.

## Useful Smoke Tests

```sh
./run-chaostest --scenario key-loss --duration-secs 1 --workers 1
./run-chaostest --scenario sidecar-corrupt --duration-secs 1 --workers 1
./run-chaostest --scenario follower-kill --duration-secs 1 --workers 1 --keep-artifacts
./run-chaostest --scenario leader-kill --include-known-gaps --duration-secs 1 --workers 1
```

When `--keep-artifacts` is set, inspect the retained workspace for:

- `node*.stdout.log`: JSON protocol responses
- `node*.stderr.log`: child process diagnostics
- `chaostest-report.json`: machine-readable scenario report
