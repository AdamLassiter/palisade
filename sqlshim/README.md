# sqlshim

`sqlshim` is a tiny `LD_PRELOAD` shim that intercepts SQLite calls and **parses + rewrites SQL text at runtime**.

It’s meant for “drop-in” behavior: run an existing binary unchanged, preload `sqlshim`, and it can transform queries on the fly (e.g. add/strip clauses, rename tables/columns, enforce tenant filters, block dangerous statements, etc.).

## How it works

- `LD_PRELOAD` injects a shared library into the target process.
- The shim hooks SQLite entry points (e.g. `sqlite3_prepare_v2`, `sqlite3_prepare_v3`).
- When SQL text is prepared, `sqlshim` parses it, rewrites it, and forwards the modified SQL to SQLite.

## Usage

```bash
export LD_PRELOAD=/path/to/libsqlshim.so
# optional: configure rewrite rules via env vars / config file (project-specific)
./your_sqlite_app
```

## Notes

- Rewriting SQL is best-effort: some statements, pragmas, and edge cases may be intentionally left untouched.
- This affects only SQL prepared through the hooked APIs (not raw page I/O or non-SQL access paths).
