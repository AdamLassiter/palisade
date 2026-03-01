# 1 High-Level Architecture

```
        ┌───────────────────────────────┐
        │  Application (unmodified)     │
        └──────────────┬────────────────┘
                       │
                SQLite API calls
                       │
        ┌──────────────▼───────────────┐
        │  Custom VFS Layer (LazySQL)  │
        │ - WAL intercept              │
        │ - Encrypted pages            │
        │ - Replication hooks          │
        └──────────────┬───────────────┘
                       │
            Local SQLite Database
                       │
           ┌───────────▼───────────┐
           │ Raft Node / Log Layer │
           │ - Append WAL frames   │
           │ - Leader election     │
           │ - Log replication     │
           └───────────┬───────────┘
                       │
              Replicate to followers
                       │
              Followers apply WAL
```

**Key ideas:**

* **Single writer at any time**: Raft elects a leader; only leader writes WAL.
* **Followers**: apply WAL frames in order received.
* **VFS Layer**: intercepts low-level `sqlite3` I/O operations (`xWrite`, `xSync`, `xRead`) and WAL file writes.
* **Raft Layer**: manages log replication and ensures committed entries reach majority.

---

# 2 WAL Interception via Custom VFS

SQLite VFS defines functions for all low-level operations:

```c
typedef struct sqlite3_io_methods {
  int (*xClose)(sqlite3_file*);
  int (*xRead)(sqlite3_file*, void*, int iAmt, sqlite3_int64 iOfst);
  int (*xWrite)(sqlite3_file*, const void*, int iAmt, sqlite3_int64 iOfst);
  int (*xTruncate)(sqlite3_file*, sqlite3_int64 size);
  int (*xSync)(sqlite3_file*, int flags);
  ...
} sqlite3_io_methods;
```

To intercept WAL writes:

1. **Wrap the standard VFS**:

```text
- Call `sqlite3_vfs_find("unix")` (or whatever default)
- Create new VFS struct
- For each file method (xOpen), wrap underlying file
```

2. **Intercept WAL file writes**:

```rust
fn xWrite(file, buffer, amt, offset) {
    if file.is_wal_file() {
        raft_append(buffer[0..amt]); // send to Raft
    }
    underlying_xWrite(file, buffer, amt, offset)
}
```

**Important:**

* Only intercept WAL files (`dbname-wal`)
* Do not intercept the main DB for replication; WAL captures all changes
* Apply same buffer to local DB immediately (optimistic), or after Raft commit (strong consistency)

---

# 3 WAL Frame Capture

A WAL file consists of **frames**, each frame:

* 4KB page (configurable)
* Frame header
* Checksum

**Intercepting WAL frames**:

* Detect WAL file in `xWrite`
* Batch writes into full frames
* Send each frame (or group of frames) as a Raft log entry
* Include metadata:

```json
{
  "frame_index": 42,
  "db_name": "main",
  "frame_data": <4096 bytes>,
  "checkpoint_offset": 0
}
```

**Leader applies frame locally after commit**

* Followers apply committed frames in same order

---

# 4 Raft Integration

Each WAL frame (or batch of frames) becomes a **Raft log entry**:

```rust
struct RaftEntry {
    frame_index: u64,
    db_name: String,
    frame_data: Vec<u8>,
    commit_index: u64,
}
```

**Leader:**

1. Append frame(s) to Raft log
2. Wait for majority commit
3. Apply to local SQLite

**Follower:**

1. Receive committed Raft entry
2. Apply frame to local SQLite via `xWrite` or directly via WAL API
3. Optional: `xSync` after batch to flush

---

# 5 Snapshotting & Log Compaction

Without snapshots:

* Raft log grows unbounded
* Followers need full log to catch up

Solution:

* Periodically checkpoint SQLite DB
* Serialize DB file via `sqlite3_backup`
* Store snapshot as Raft snapshot
* Truncate old WAL + Raft entries

---

# 6 Handling Reads

* Followers can read local SQLite DB
* Optionally, enforce `commit_index` > frame_index for linearizable reads
* Reads never go through Raft, so low-latency

---

# 7 Advantages of WAL + Raft

| Feature    | Benefit                                                  |
| ---------- | -------------------------------------------------------- |
| WAL frames | Deterministic replication, all SQLite features supported |
| Raft       | Leader election, strong consistency, multi-node safety   |
| VFS hook   | Transparent to app, works with unmodified SQLite         |
| Snapshots  | Compact Raft log, fast replica catch-up                  |

---

# 8 Minimal Example VFS Hook (Rust-like Pseudocode)

```rust
struct WalFile {
    underlying: *mut sqlite3_file,
    db_name: String,
    raft: RaftClient,
}

impl WalFile {
    fn x_write(&self, buf: &[u8], offset: i64) -> c_int {
        if self.db_name.ends_with("-wal") {
            // append to Raft log
            self.raft.append(WalFrame {
                data: buf.to_vec(),
                offset,
            });
        }
        // pass-through write
        unsafe { self.underlying.xWrite(buf, offset) }
    }
}
```

Then register:

```rust
let default_vfs = sqlite3_vfs_find("unix");
let mut my_vfs = default_vfs.clone();
my_vfs.xOpen = |name, flags| -> WalFile { wrap_underlying(name, default_vfs) };
sqlite3_vfs_register(my_vfs, 0);
```

---

# 9 Key Considerations

1. **Single-writer per Raft cluster** → needed because WAL frames are stateful.
2. **Page alignment** → WAL frames are page-size aligned; send whole frames.
3. **Checkpointing** → followers cannot just replay WAL forever.
4. **Crash recovery** → persist Raft log + local DB; on restart, apply remaining frames.
5. **Encryption** → can encrypt WAL frames in transit or on disk.
6. **Backpressure** → don't write WAL faster than Raft can commit.

---

# Summary

* **Intercepting WAL at VFS level** is clean, transparent, and deterministic.
* **Raft handles leader election, ordering, replication**.
* **Frames not SQL** → no nondeterminism, no triggers/randomness issues.
* **Snapshots + checkpoints** → manage Raft log size and replication.

> Essentially, the distributed state machine = SQLite's page store.
