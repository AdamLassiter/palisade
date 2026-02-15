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

## How they fit together

Common combinations:

- **At-rest encryption + in-DB access control**: `sqlevfs` protects on-disk pages; `sqlsec` enforces row/column rules inside SQLite.
- **Query rewriting + in-DB access control**: `sqlshim` can enforce “mandatory predicates” or block statements; `sqlsec` remains the source of truth for visibility/update rules.
- **All three**: `sqlshim` shapes incoming SQL, `sqlsec` enforces label-based policy, `sqlevfs` encrypts pages on disk.
- Use **`lazytest`** as the harness to run these stacks under `LD_PRELOAD`.

## Combined usage (conceptual)

- Load `sqlsec` as a SQLite extension when you need label-based RLS/CLS.
- Register `sqlevfs` (VFS `evfs`) when you need at-rest encryption.
- Preload `sqlshim` when you need runtime SQL rewriting without changing the app.
- Use `lazytest` to exercise and validate the stack.

(Each component has its own build/run instructions in its respective README.)

## Quickstart

```sh
./test
```
