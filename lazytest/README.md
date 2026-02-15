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

# Run with one or more preload libraries
LD_PRELOAD=/path/to/libsomething.so:/path/to/libother.so \
  target/debug/lazytest
```

## Notes

- `lazytest` is intentionally not a general test framework; it’s a convenient harness for manual and integration testing.
