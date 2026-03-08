use std::{
    collections::HashMap,
    ffi::{CString, c_int, c_void},
    ptr,
    sync::{Arc, Mutex, OnceLock},
    time::Instant,
};

use anyhow::{Context, Result};
use libsqlite3_sys::{
    SQLITE_IOERR,
    SQLITE_OK,
    SQLITE_OPEN_CREATE,
    SQLITE_OPEN_MAIN_DB,
    SQLITE_OPEN_READWRITE,
    SQLITE_OPEN_WAL,
    sqlite3_file,
    sqlite3_vfs,
    sqlite3_vfs_find,
};
use serde::{Deserialize, Serialize};

use crate::vfs::consensus::NodeId;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ReplayTargetConfig {
    pub raft_vfs_name: String,
    /// sqlite3 VFS name used for replay I/O. Empty means default VFS.
    #[serde(default)]
    pub io_vfs_name: String,
    pub node_id: NodeId,
    pub db_path: String,
    pub wal_path: String,
    pub shm_path: String,
    pub page_size: u32,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ReplayStats {
    pub applied_frames: u64,
    pub applied_bytes: u64,
    pub truncations: u64,
    pub shm_invalidations: u64,
    pub replay_errors: u64,
    pub last_apply_micros: u64,
    pub last_applied_offset: i64,
}

#[derive(Debug)]
struct ReplayState {
    stats: ReplayStats,
    frame_size: i64,
}

struct VfsWalFile {
    vfs: *mut sqlite3_vfs,
    file: *mut sqlite3_file,
}

// SAFETY: raw pointers are only accessed behind `Mutex<VfsWalFile>`, and are
// initialized/owned by this type for the process lifetime of the sink.
unsafe impl Send for VfsWalFile {}

impl VfsWalFile {
    fn open(path: &str, vfs_name: &str) -> Result<Self> {
        let c_vfs = if vfs_name.is_empty() {
            None
        } else {
            Some(CString::new(vfs_name).context("invalid io_vfs_name")?)
        };

        // SAFETY: sqlite3_vfs_find expects a C string or null; both are stable
        // for this call.
        let vfs = unsafe { sqlite3_vfs_find(c_vfs.as_ref().map_or(ptr::null(), |v| v.as_ptr())) };
        anyhow::ensure!(!vfs.is_null(), "sqlite vfs not found: '{vfs_name}'");

        // SAFETY: szOsFile is provided by sqlite and used exactly as allocation size.
        let sz = unsafe { (*vfs).szOsFile as usize };
        anyhow::ensure!(sz > 0, "sqlite vfs has invalid szOsFile=0");

        // SAFETY: malloc allocates an opaque byte buffer for sqlite3_file impl.
        let file = unsafe { libc::malloc(sz) as *mut sqlite3_file };
        anyhow::ensure!(!file.is_null(), "failed to allocate sqlite3_file");
        // SAFETY: zero init buffer before xOpen fills it.
        unsafe { ptr::write_bytes(file as *mut u8, 0, sz) };

        let c_path = CString::new(path).context("invalid wal path")?;
        let mut out_flags: c_int = 0;
        let flags =
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_WAL | SQLITE_OPEN_MAIN_DB;

        // SAFETY: xOpen is called with a valid vfs, allocated sqlite3_file buffer, and C path.
        let rc = unsafe {
            ((*vfs).xOpen.expect("sqlite vfs missing xOpen"))(
                vfs,
                c_path.as_ptr(),
                file,
                flags,
                &mut out_flags,
            )
        };
        if rc != SQLITE_OK {
            // SAFETY: buffer was allocated via malloc and not owned by sqlite on failed xOpen.
            unsafe { libc::free(file as *mut c_void) };
            anyhow::bail!("sqlite vfs xOpen failed for '{}': rc={rc}", path);
        }

        Ok(Self { vfs, file })
    }

    fn write_at(&mut self, offset: i64, data: &[u8]) -> Result<()> {
        // SAFETY: file handle is valid after successful xOpen.
        let methods = unsafe { (*self.file).pMethods };
        anyhow::ensure!(!methods.is_null(), "sqlite file has null pMethods");

        // SAFETY: xWrite consumes immutable buffer pointer with explicit length.
        let rc = unsafe {
            ((*methods).xWrite.expect("sqlite file missing xWrite"))(
                self.file,
                data.as_ptr() as *const c_void,
                data.len() as c_int,
                offset,
            )
        };
        if rc != SQLITE_OK {
            anyhow::bail!("sqlite xWrite failed at offset {offset}: rc={rc}");
        }
        Ok(())
    }

    fn truncate(&mut self, len: i64) -> Result<()> {
        // SAFETY: file handle is valid after successful xOpen.
        let methods = unsafe { (*self.file).pMethods };
        anyhow::ensure!(!methods.is_null(), "sqlite file has null pMethods");

        // SAFETY: xTruncate operates on the opened sqlite3_file.
        let rc = unsafe {
            ((*methods).xTruncate.expect("sqlite file missing xTruncate"))(self.file, len)
        };
        if rc != SQLITE_OK {
            anyhow::bail!("sqlite xTruncate failed len={len}: rc={rc}");
        }
        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        // SAFETY: file handle is valid after successful xOpen.
        let methods = unsafe { (*self.file).pMethods };
        anyhow::ensure!(!methods.is_null(), "sqlite file has null pMethods");

        // SAFETY: xSync operates on the opened sqlite3_file.
        let rc = unsafe { ((*methods).xSync.expect("sqlite file missing xSync"))(self.file, 0) };
        if rc != SQLITE_OK {
            anyhow::bail!("sqlite xSync failed: rc={rc}");
        }
        Ok(())
    }

    fn delete(&mut self, path: &str, sync_dir: bool) -> Result<()> {
        let c_path = CString::new(path).context("invalid delete path")?;
        // SAFETY: xDelete is called with path string stable for the call.
        let rc = unsafe {
            ((*self.vfs).xDelete.expect("sqlite vfs missing xDelete"))(
                self.vfs,
                c_path.as_ptr(),
                if sync_dir { 1 } else { 0 },
            )
        };
        if rc == SQLITE_OK || rc == SQLITE_IOERR {
            // SQLITE_IOERR often maps to "not found" / fs-specific deletion errors;
            // caller handles as best-effort invalidation.
            return Ok(());
        }
        anyhow::bail!("sqlite vfs xDelete failed for '{}': rc={rc}", path)
    }
}

impl Drop for VfsWalFile {
    fn drop(&mut self) {
        // SAFETY: close/free only if allocated.
        unsafe {
            if !self.file.is_null() {
                let methods = (*self.file).pMethods;
                if !methods.is_null()
                    && let Some(x_close) = (*methods).xClose
                {
                    let _ = x_close(self.file);
                }
                libc::free(self.file as *mut c_void);
                self.file = ptr::null_mut();
            }
        }
    }
}

/// Local follower replay sink that materializes committed raft WAL
/// frames onto disk in deterministic offset order.
pub struct FollowerReplaySink {
    target: ReplayTargetConfig,
    file: Mutex<VfsWalFile>,
    state: Mutex<ReplayState>,
}

impl FollowerReplaySink {
    pub fn open(target: ReplayTargetConfig) -> Result<Arc<Self>> {
        let file = VfsWalFile::open(&target.wal_path, &target.io_vfs_name).with_context(|| {
            format!(
                "failed to open follower WAL path '{}' via sqlite vfs '{}'",
                target.wal_path, target.io_vfs_name
            )
        })?;

        let frame_size = target.page_size as i64 + 24;
        Ok(Arc::new(Self {
            target,
            file: Mutex::new(file),
            state: Mutex::new(ReplayState {
                stats: ReplayStats {
                    last_applied_offset: -1,
                    ..ReplayStats::default()
                },
                frame_size,
            }),
        }))
    }

    pub fn apply_frame(&self, wal_offset: i64, frame_data: &[u8]) -> Result<()> {
        let started = Instant::now();
        let mut st = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("replay state lock poisoned"))?;

        let expected_len = st.frame_size as usize;
        if frame_data.len() != expected_len {
            st.stats.replay_errors += 1;
            anyhow::bail!(
                "invalid WAL frame size: got={}, expected={expected_len}",
                frame_data.len()
            );
        }
        if wal_offset < 32 {
            st.stats.replay_errors += 1;
            anyhow::bail!("invalid WAL frame offset: {wal_offset}");
        }
        if (wal_offset - 32) % st.frame_size != 0 {
            st.stats.replay_errors += 1;
            anyhow::bail!(
                "unaligned WAL frame offset: {wal_offset} (frame_size={})",
                st.frame_size
            );
        }

        // Idempotent replay of already-applied offsets.
        if wal_offset <= st.stats.last_applied_offset {
            return Ok(());
        }

        let expected_next = if st.stats.last_applied_offset < 0 {
            32
        } else {
            st.stats.last_applied_offset + st.frame_size
        };
        if wal_offset != expected_next {
            st.stats.replay_errors += 1;
            anyhow::bail!(
                "out-of-order WAL replay: got offset {wal_offset}, expected {expected_next}"
            );
        }

        let mut f = self
            .file
            .lock()
            .map_err(|_| anyhow::anyhow!("replay WAL file lock poisoned"))?;
        f.write_at(wal_offset, frame_data)
            .with_context(|| format!("failed to write WAL frame at offset {wal_offset}"))?;
        f.sync()
            .context("failed to sync WAL replay file after frame apply")?;

        st.stats.last_applied_offset = wal_offset;
        st.stats.applied_frames += 1;
        st.stats.applied_bytes += frame_data.len() as u64;
        st.stats.last_apply_micros = started.elapsed().as_micros() as u64;
        drop(f);

        self.invalidate_shm_locked(&mut st);
        Ok(())
    }

    pub fn truncate_at(&self, wal_offset: i64) -> Result<()> {
        let mut st = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("replay state lock poisoned"))?;
        let f = self
            .file
            .lock()
            .map_err(|_| anyhow::anyhow!("replay WAL file lock poisoned"))?;

        let target_len = wal_offset.max(0) as u64;
        let mut file = f;
        file.truncate(target_len as i64)
            .with_context(|| format!("failed to truncate WAL file to {target_len}"))?;
        file.sync()
            .context("failed to sync WAL replay file after truncate")?;

        st.stats.truncations += 1;
        st.stats.last_applied_offset = if wal_offset <= 32 {
            -1
        } else {
            let frames = (wal_offset - 32) / st.frame_size;
            if frames <= 0 {
                -1
            } else {
                32 + (frames - 1) * st.frame_size
            }
        };
        self.invalidate_shm_locked(&mut st);
        Ok(())
    }

    pub fn sync(&self) -> Result<()> {
        let mut f = self
            .file
            .lock()
            .map_err(|_| anyhow::anyhow!("replay WAL file lock poisoned"))?;
        f.sync().context("failed to sync replay WAL file")
    }

    pub fn stats(&self) -> ReplayStats {
        self.state
            .lock()
            .map(|s| s.stats.clone())
            .unwrap_or_else(|_| ReplayStats::default())
    }

    pub fn target(&self) -> &ReplayTargetConfig {
        &self.target
    }

    fn invalidate_shm_locked(&self, st: &mut ReplayState) {
        let mut f = match self.file.lock() {
            Ok(v) => v,
            Err(_) => {
                st.stats.replay_errors += 1;
                return;
            }
        };
        match f.delete(&self.target.shm_path, false) {
            Ok(()) => st.stats.shm_invalidations += 1,
            Err(_) => st.stats.replay_errors += 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReplayKey {
    raft_vfs_name: String,
    db_path: String,
}

fn replay_key(target: &ReplayTargetConfig) -> ReplayKey {
    ReplayKey {
        raft_vfs_name: target.raft_vfs_name.clone(),
        db_path: target.db_path.clone(),
    }
}

static REPLAY_REGISTRY: OnceLock<Mutex<HashMap<ReplayKey, Arc<FollowerReplaySink>>>> =
    OnceLock::new();

fn registry() -> &'static Mutex<HashMap<ReplayKey, Arc<FollowerReplaySink>>> {
    REPLAY_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn register_sink(target: ReplayTargetConfig) -> Result<Arc<FollowerReplaySink>> {
    let sink = FollowerReplaySink::open(target.clone())?;
    let mut reg = registry()
        .lock()
        .map_err(|_| anyhow::anyhow!("replay registry lock poisoned"))?;
    reg.insert(replay_key(&target), sink.clone());
    Ok(sink)
}

pub fn get_sink(raft_vfs_name: &str, db_path: &str) -> Option<Arc<FollowerReplaySink>> {
    let key = ReplayKey {
        raft_vfs_name: raft_vfs_name.to_string(),
        db_path: db_path.to_string(),
    };
    registry().lock().ok().and_then(|m| m.get(&key).cloned())
}

pub fn remove_sink(raft_vfs_name: &str, db_path: &str) {
    let key = ReplayKey {
        raft_vfs_name: raft_vfs_name.to_string(),
        db_path: db_path.to_string(),
    };
    if let Ok(mut reg) = registry().lock() {
        reg.remove(&key);
    }
}

pub fn clear_all() {
    if let Ok(mut reg) = registry().lock() {
        reg.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use tempfile::TempDir;

    use super::*;

    fn sqlite_api_is_available() -> bool {
        std::panic::catch_unwind(|| unsafe {
            let _ = sqlite3_vfs_find(ptr::null());
        })
        .is_ok()
    }

    fn target(tmp: &TempDir) -> ReplayTargetConfig {
        let db = tmp.path().join("follower.db");
        ReplayTargetConfig {
            raft_vfs_name: "evfs_raft".to_string(),
            io_vfs_name: "".to_string(),
            node_id: 2,
            db_path: db.to_string_lossy().to_string(),
            wal_path: format!("{}-wal", db.to_string_lossy()),
            shm_path: format!("{}-shm", db.to_string_lossy()),
            page_size: 4096,
        }
    }

    #[test]
    fn replay_enforces_offset_order_and_idempotency() {
        if !sqlite_api_is_available() {
            eprintln!("skipping replay test: sqlite extension API is unavailable");
            return;
        }
        let tmp = TempDir::new().expect("tmp dir");
        let sink = FollowerReplaySink::open(target(&tmp)).expect("open sink");
        let frame = vec![0u8; 4096 + 24];

        sink.apply_frame(32, &frame).expect("apply first");
        sink.apply_frame(32, &frame).expect("idempotent duplicate");
        let err = sink
            .apply_frame(32 + 2 * (4096 + 24) as i64, &frame)
            .expect_err("out-of-order should fail");
        assert!(err.to_string().contains("out-of-order"));
    }

    #[test]
    fn replay_rejects_short_frame() {
        if !sqlite_api_is_available() {
            eprintln!("skipping replay test: sqlite extension API is unavailable");
            return;
        }
        let tmp = TempDir::new().expect("tmp dir");
        let sink = FollowerReplaySink::open(target(&tmp)).expect("open sink");
        let err = sink
            .apply_frame(32, &[0u8; 8])
            .expect_err("short frame should fail");
        assert!(err.to_string().contains("invalid WAL frame size"));
    }

    #[test]
    fn truncate_updates_state() {
        if !sqlite_api_is_available() {
            eprintln!("skipping replay test: sqlite extension API is unavailable");
            return;
        }
        let tmp = TempDir::new().expect("tmp dir");
        let sink = FollowerReplaySink::open(target(&tmp)).expect("open sink");
        let frame = vec![0u8; 4096 + 24];
        sink.apply_frame(32, &frame).expect("apply first");
        sink.apply_frame(32 + (4096 + 24) as i64, &frame)
            .expect("apply second");
        sink.truncate_at(32).expect("truncate");
        assert_eq!(sink.stats().last_applied_offset, -1);
    }
}
