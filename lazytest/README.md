# lazytest

`lazytest` is a small Rust binary used to run ad-hoc SQLite workloads under `LD_PRELOAD`.

It exists so you can easily test and combine multiple SQLite-related shims/extensions (VFS layers, query rewriters, tracing hooks, etc.) in a realistic process without modifying an application.

## What it does

- Opens a SQLite database (file or in-memory, depending on the test)
- Executes a curated set of SQL statements and/or file operations
- Exits with success/failure based on the expected results

## Why it’s useful

- Lets `LD_PRELOAD` intercept SQLite calls reliably (you control the process)
- Makes it easy to reproduce issues and validate fixes
- Allows testing multiple extensions together (e.g. VFS + SQL rewrite + logging)

## Usage

```bash
# Build
cargo build -p lazytest

# Run default functional suites
LD_PRELOAD=/path/to/libsomething.so:/path/to/libother.so \
  target/debug/lazytest

# Run perf suite in addition to functional suites
target/debug/lazytest --perf

# Run only perf suite
target/debug/lazytest --perf-only
```

## Performance Suite

`--perf` runs performance comparisons for:

1. EVFS overhead:
- plain SQLite (default VFS)
- SQLite with `sqlevfs` (`vfs=evfs`)

2. SQLSHIM overhead:
- plain SQLite process
- same process with `LD_PRELOAD=libsqlshim.so`

It reports median timings and overhead for:

- write transaction
- point reads
- update transaction
- scan aggregate
- total workload
- prepare-heavy point lookups
- mixed query workload
- secured-view vs physical-table point reads (sqlsec)
- secured-view vs physical-table scans (sqlsec)

3. EVFS raft-like workload overhead (single-node):
- plain SQLite (default VFS)
- SQLite with `sqlevfs` (`vfs=evfs`)
- SQLite with `sqlevfs` raft path (`vfs=evfs_raft`, single-node `evfs_raft_init`)

It reports median timings for:

- seed transaction
- transfer transactions (many small commits)
- point reads
- range reads
- total raft-like workload

This provides a quick local signal for how much EVFS, EVFS Raft path, SQLSHIM, and SQLSEC add relative to unmodified SQLite.

## Notes

- `lazytest` is intentionally not a general test framework; it’s a convenient harness for manual and integration testing.
