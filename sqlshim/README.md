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
# optional: set SQLSHIM_DEBUG=true for debugging
./your_sqlite_app
```

## sqlsec convenience syntax

When the `sqlsec` extension is loaded, `sqlshim` rewrites convenience SQL into `sec_*` function calls. Audit-related forms include:

```sql
ENABLE AUDIT ON employees;
ENABLE AUDIT ON employees FOR INSERT, UPDATE, DELETE;
DISABLE AUDIT ON employees;
```

These rewrite to `sec_audit_enable`, `sec_audit_disable`, and `sec_audit_configure`. `SELECT` audit is not enabled by these forms; `sqlsec` currently audits successful secured writes.

## Notes

- Rewriting SQL is best-effort: some statements, pragmas, and edge cases may be intentionally left untouched.
- This affects only SQL prepared through the hooked APIs (not raw page I/O or non-SQL access paths).
