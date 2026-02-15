# sqlite-evfs

A custom SQLite VFS (“evfs”) that wraps the platform VFS and transparently encrypts database pages on read/write.

This crate is designed to make **at-rest encryption** for SQLite feel like “just a VFS”: you register `evfs`, open your database using that VFS, and pages are encrypted before hitting disk and decrypted after being read.

## Status / Caveats

This project is low-level and interacts with SQLite via FFI.

Key behaviors and constraints:

- **Page 1 is left plaintext** so SQLite can read the schema and open the database normally. Pages `2..` are encrypted.
- The encryption scheme uses **per-page AEAD (AES-256-GCM)** and stores the authentication tag (and an `EVFSv1` marker) in the **reserved bytes** at the end of each page.
- Stock SQLite (e.g. 3.45.x) does **not** support `PRAGMA reserve_size`. `evfs` therefore ensures the SQLite header’s reserved-bytes field is set when creating a new DB, so SQLite doesn’t use the reserved tail bytes for real data.
- SQLite does **partial reads/writes**; `evfs` handles this with a read-modify-write path (decrypt full page → patch → re-encrypt).

If you change page size or reserved space, you can break compatibility with existing databases.

## Features

- **Transparent page-level encryption**
  - AES-256-GCM per page
  - deterministic nonce derived from page number (safe because DEKs are random and unique per DB/scope)
  - AEAD tag stored in SQLite page reserved bytes
  - `EVFSv1` marker stored after the tag to detect encrypted pages reliably
- **Key management**
  - A **DEK** (data encryption key) encrypts pages.
  - A **KEK** (key encryption key) wraps DEKs (envelope encryption).
  - Wrapped DEKs are persisted in a **sidecar** file next to the DB.
- **KMS provider abstraction**
  - Local device-key provider (keyfile or passphrase-derived KEK)
  - Cloud provider placeholder (implementation dependent)

## How it works (high level)

- At open time, `evfs` wraps the underlying default VFS and returns its own `sqlite3_file` implementation.
- For page reads/writes on the main DB file:
  - **Writes**: decrypt existing page (if encrypted) → apply update → encrypt → write full page
  - **Reads**: read full page → decrypt (if encrypted) → copy requested bytes
- DEKs are created per scope (`Database` or per-table scope) and cached in memory. On first use, a new DEK is generated and wrapped using the KEK from the `KmsProvider`.

## Installation

Add to `Cargo.toml`:

```toml
[dependencies]
sqlevfs = { path = "." } # or git dependency

[dev-dependencies]
rusqlite = "0.32"
tempfile = "3"
```

You also need SQLite headers/libs at build time (via `libsqlite3-sys`).

## Usage

### Registering the VFS and opening a DB

```rust
use std::{path::PathBuf, sync::Arc};

use rusqlite::{Connection, OpenFlags};
use sqlevfs::{EvfsBuilder, Mode};

fn main() -> anyhow::Result<()> {
    let keyfile = PathBuf::from("db.kek");

    // 32-byte keyfile for the KEK (example only)
    // std::fs::write(&keyfile, vec![0xAA; 32])?;

    let mode = Mode::DeviceKey {
        keyfile: Some(keyfile),
        passphrase: None,
    };

    EvfsBuilder::new(mode)
        .vfs_name("evfs")
        .page_size(4096)
        .reserve_size(48) // 16 tag + 6 marker + spare
        .register()?;

    let conn = Connection::open_with_flags_and_vfs(
        "my.db",
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        "evfs",
    )?;

    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)", [])?;
    conn.execute("INSERT INTO t (v) VALUES ('hello')", [])?;

    Ok(())
}
```

### Operational modes

#### DeviceKey mode

Provides a device-local KEK:

- from a 32-byte keyfile, or
- derived from a passphrase using Argon2id (fixed salt in current code; see security notes).

```rust
let mode = Mode::DeviceKey {
    keyfile: Some(PathBuf::from("db.kek")),
    passphrase: None,
};
```

or:

```rust
let mode = Mode::DeviceKey {
    keyfile: None,
    passphrase: Some("correct horse battery staple".to_string()),
};
```

#### TenantKey mode

Intended for SaaS/multi-tenant setups where the KEK lives in a cloud KMS.

```rust
let mode = Mode::TenantKey {
    key_id: "kms-key-resource".to_string(),
    endpoint: None,
};
```

(Requires a `CloudKmsProvider` implementation in `kms/cloud.rs`.)

## Files on disk

For a database file:

- `my.db` — SQLite database; page 1 plaintext, pages 2+ encrypted
- `my.evfs-keyring` — sidecar containing wrapped DEKs (binary, not UTF-8)

The sidecar never contains plaintext DEKs.

## Security notes

- AES-GCM nonces are derived deterministically from page number. This is safe here because each page is encrypted under a random DEK, and the `(DEK, page_no)` pair is unique. Do not reuse a DEK across databases unless you understand the implications.
- In passphrase mode, a **fixed salt** is currently used. Production deployments should store a random salt alongside the database and use it for derivation (otherwise identical passphrases derive identical KEKs across databases).
- Page 1 is plaintext. This leaks schema metadata (table names, column names, etc.). If you need full-database confidentiality including schema, you need a SQLite codec integration rather than a VFS-only approach.

## Development

### Running tests

Unit tests:

```bash
cargo test
```

Integration tests (using rusqlite):

```bash
cargo test --test integration_test
```

Enable VFS logging:

```bash
RUST_LOG=sqlevfs::vfs=info cargo test --test integration_test -- test_large_data_encryption
```

### Common failure modes

- `database disk image is malformed`
  - typically indicates page 1 is encrypted (must remain plaintext), or an invalid page-1 header was written.
- `page decrypt failed: aead::Error`
  - ciphertext/tag mismatch (corruption), wrong DEK, or attempting to decrypt a plaintext page. The `EVFSv1` marker is used to avoid decrypting plaintext pages.
- large BLOB mismatch without decrypt errors
  - reserved-bytes not in effect (SQLite writing real data into tag area), or encryption incorrectly applied to journal/WAL/temp files.
