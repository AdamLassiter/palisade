use std::{
    collections::HashMap,
    ffi::{CString, c_int, c_void},
    ptr,
    sync::{
        Arc,
        Condvar,
        Mutex,
        OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread,
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

use crate::vfs::consensus::{
    NodeId,
    wal::{WalBatch, WalRecord},
};

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
    #[serde(default = "default_reserve_size")]
    pub reserve_size: usize,
    #[serde(default)]
    pub follower_wal_sync: FollowerWalSyncConfig,
    #[serde(default, skip)]
    pub rebuild_on_open: bool,
}

fn default_reserve_size() -> usize {
    48
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum FollowerWalSyncMode {
    PerBatch,
    Coalesced,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FollowerWalSyncConfig {
    #[serde(default)]
    pub mode: FollowerWalSyncMode,
    #[serde(default = "default_wal_sync_max_batches")]
    pub max_batches: usize,
    #[serde(default = "default_wal_sync_max_delay_ms")]
    pub max_delay_ms: u64,
}

impl Default for FollowerWalSyncMode {
    fn default() -> Self {
        Self::PerBatch
    }
}

impl Default for FollowerWalSyncConfig {
    fn default() -> Self {
        Self {
            mode: FollowerWalSyncMode::PerBatch,
            max_batches: default_wal_sync_max_batches(),
            max_delay_ms: default_wal_sync_max_delay_ms(),
        }
    }
}

fn default_wal_sync_max_batches() -> usize {
    64
}

fn default_wal_sync_max_delay_ms() -> u64 {
    5
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ReplayStats {
    pub applied_batches: u64,
    pub applied_records: u64,
    pub applied_frames: u64,
    pub applied_bytes: u64,
    pub truncations: u64,
    pub shm_invalidations: u64,
    pub replay_errors: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_wal_sync_error: Option<String>,
    pub materialize_errors: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_materialize_error: Option<String>,
    pub last_apply_micros: u64,
    pub last_batch_records: u64,
    pub wal_syncs: u64,
    pub wal_sync_policy: String,
    pub db_syncs: u64,
    pub wal_write_micros: u64,
    pub wal_sync_micros: u64,
    pub last_wal_write_micros: u64,
    pub last_wal_sync_micros: u64,
    pub last_applied_offset: i64,
    pub last_wal_synced_offset: i64,
    pub pending_wal_sync_batches: u64,
    pub coalesced_wal_syncs: u64,
    pub wal_sync_batches: u64,
    pub last_wal_sync_batches: u64,
    pub wal_sync_delay_micros: u64,
    pub last_wal_sync_delay_micros: u64,
    pub last_materialized_offset: i64,
    pub materialize_batches: u64,
    pub materialize_frames: u64,
    pub materialize_queue_depth: u64,
    pub materialize_db_write_micros: u64,
    pub materialize_db_sync_micros: u64,
    pub materialize_shm_invalidate_micros: u64,
    pub last_materialize_db_write_micros: u64,
    pub last_materialize_db_sync_micros: u64,
    pub last_materialize_shm_invalidate_micros: u64,
}

#[derive(Debug)]
struct ReplayState {
    stats: ReplayStats,
    frame_size: i64,
    pending_pages: Vec<MaterializePage>,
}

struct VfsWalFile {
    vfs: *mut sqlite3_vfs,
    file: *mut sqlite3_file,
}

// SAFETY: raw pointers are only accessed behind `Mutex<VfsWalFile>`, and are
// initialized/owned by this type for the process lifetime of the sink.
unsafe impl Send for VfsWalFile {}

impl VfsWalFile {
    fn open_with_flags(path: &str, vfs_name: &str, flags: c_int) -> Result<Self> {
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

    fn read_at(&mut self, offset: i64, data: &mut [u8]) -> Result<()> {
        // SAFETY: file handle is valid after successful xOpen.
        let methods = unsafe { (*self.file).pMethods };
        anyhow::ensure!(!methods.is_null(), "sqlite file has null pMethods");

        // SAFETY: xRead fills the caller-provided buffer with explicit length.
        let rc = unsafe {
            ((*methods).xRead.expect("sqlite file missing xRead"))(
                self.file,
                data.as_mut_ptr() as *mut c_void,
                data.len() as c_int,
                offset,
            )
        };
        if rc != SQLITE_OK {
            anyhow::bail!("sqlite xRead failed at offset {offset}: rc={rc}");
        }
        Ok(())
    }

    fn file_size(&mut self) -> Result<i64> {
        // SAFETY: file handle is valid after successful xOpen.
        let methods = unsafe { (*self.file).pMethods };
        anyhow::ensure!(!methods.is_null(), "sqlite file has null pMethods");

        let mut size = 0_i64;
        // SAFETY: xFileSize writes an i64 size through the provided pointer.
        let rc = unsafe {
            ((*methods).xFileSize.expect("sqlite file missing xFileSize"))(self.file, &mut size)
        };
        if rc != SQLITE_OK {
            anyhow::bail!("sqlite xFileSize failed: rc={rc}");
        }
        Ok(size)
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
///
/// Important: replay writes the SQLite WAL header plus committed frames
/// into the follower WAL file and also materializes committed page images
/// into the follower main DB file so passive readers can validate replica
/// state without a separate checkpoint integration step.
pub struct FollowerReplaySink {
    target: ReplayTargetConfig,
    wal_file: Arc<Mutex<VfsWalFile>>,
    state: Arc<Mutex<ReplayState>>,
    materialize_tx: SyncSender<MaterializeBatch>,
    materialize_queue_depth: Arc<AtomicUsize>,
    wal_sync_state: Arc<WalSyncCoordinator>,
}

#[derive(Debug)]
struct MaterializePage {
    page_no: u32,
    data: Vec<u8>,
}

#[derive(Debug)]
struct MaterializeBatch {
    target_offset: i64,
    db_size_pages: Option<u32>,
    pages: Vec<MaterializePage>,
}

const MATERIALIZE_QUEUE_CAPACITY: usize = 4096;

struct WalSyncCoordinator {
    state: Mutex<WalSyncState>,
    cv: Condvar,
}

#[derive(Debug)]
struct WalSyncState {
    pending_batches: u64,
    pending_offset: i64,
    first_pending_at: Option<Instant>,
    shutdown: bool,
}

impl WalSyncCoordinator {
    fn new() -> Self {
        Self {
            state: Mutex::new(WalSyncState {
                pending_batches: 0,
                pending_offset: -1,
                first_pending_at: None,
                shutdown: false,
            }),
            cv: Condvar::new(),
        }
    }
}

fn spawn_materializer(
    target: ReplayTargetConfig,
    wal_file: Arc<Mutex<VfsWalFile>>,
    state: Arc<Mutex<ReplayState>>,
    queue_depth: Arc<AtomicUsize>,
    mut db_file: VfsWalFile,
    materialize_rx: Receiver<MaterializeBatch>,
) {
    thread::spawn(move || {
        while let Ok(batch) = materialize_rx.recv() {
            queue_depth.fetch_sub(1, Ordering::Relaxed);
            if let Err(err) = materialize_batch(
                &target,
                &wal_file,
                &state,
                &queue_depth,
                &mut db_file,
                batch,
            ) {
                if let Ok(mut st) = state.lock() {
                    st.stats.materialize_errors += 1;
                    st.stats.last_materialize_error = Some(err.to_string());
                    st.stats.materialize_queue_depth = queue_depth.load(Ordering::Relaxed) as u64;
                }
            }
        }
    });
}

fn spawn_wal_sync_worker(
    policy: FollowerWalSyncConfig,
    wal_file: Arc<Mutex<VfsWalFile>>,
    replay_state: Arc<Mutex<ReplayState>>,
    sync_state: Arc<WalSyncCoordinator>,
) {
    if policy.mode != FollowerWalSyncMode::Coalesced {
        return;
    }

    thread::spawn(move || {
        let max_batches = policy.max_batches.max(1) as u64;
        let max_delay = std::time::Duration::from_millis(policy.max_delay_ms.max(1));

        loop {
            let (batches, target_offset, delay_micros) = {
                let mut state = match sync_state.state.lock() {
                    Ok(state) => state,
                    Err(_) => return,
                };

                loop {
                    if state.shutdown {
                        return;
                    }

                    if state.pending_batches == 0 {
                        state = match sync_state.cv.wait(state) {
                            Ok(state) => state,
                            Err(_) => return,
                        };
                        continue;
                    }

                    let first_pending_at = state.first_pending_at.unwrap_or_else(Instant::now);
                    let elapsed = first_pending_at.elapsed();
                    if state.pending_batches >= max_batches || elapsed >= max_delay {
                        let batches = state.pending_batches;
                        let target_offset = state.pending_offset;
                        let delay_micros = elapsed.as_micros() as u64;
                        state.pending_batches = 0;
                        state.pending_offset = -1;
                        state.first_pending_at = None;
                        sync_state.cv.notify_all();
                        break (batches, target_offset, delay_micros);
                    }

                    let timeout = max_delay.saturating_sub(elapsed);
                    let Ok((next_state, _)) = sync_state.cv.wait_timeout(state, timeout) else {
                        return;
                    };
                    state = next_state;
                }
            };

            let sync_started = Instant::now();
            let sync_result = wal_file
                .lock()
                .map_err(|_| anyhow::anyhow!("replay WAL file lock poisoned"))
                .and_then(|mut wal| wal.sync());
            let sync_micros = sync_started.elapsed().as_micros() as u64;
            let pending_after_sync = sync_state
                .state
                .lock()
                .map(|state| state.pending_batches)
                .unwrap_or(0);

            let Ok(mut st) = replay_state.lock() else {
                return;
            };
            match sync_result {
                Ok(()) => {
                    st.stats.wal_syncs += 1;
                    st.stats.coalesced_wal_syncs += 1;
                    st.stats.wal_sync_batches += batches;
                    st.stats.last_wal_sync_batches = batches;
                    st.stats.wal_sync_micros += sync_micros;
                    st.stats.last_wal_sync_micros = sync_micros;
                    st.stats.wal_sync_delay_micros += delay_micros;
                    st.stats.last_wal_sync_delay_micros = delay_micros;
                    st.stats.last_wal_synced_offset = target_offset;
                    st.stats.pending_wal_sync_batches = pending_after_sync;
                    st.stats.last_wal_sync_error = None;
                }
                Err(err) => {
                    st.stats.replay_errors += 1;
                    st.stats.last_wal_sync_error = Some(err.to_string());
                }
            }
        }
    });
}

fn materialize_batch(
    target: &ReplayTargetConfig,
    wal_file: &Arc<Mutex<VfsWalFile>>,
    state: &Arc<Mutex<ReplayState>>,
    queue_depth: &Arc<AtomicUsize>,
    db_file: &mut VfsWalFile,
    batch: MaterializeBatch,
) -> Result<()> {
    let mut db_write_micros = 0u64;
    let mut db_sync_micros = 0u64;

    for page in &batch.pages {
        let page_offset = (page.page_no as i64 - 1) * target.page_size as i64;
        let mut page_data;
        let data = if page.page_no == 1
            && target.reserve_size <= u8::MAX as usize
            && page.data.len() >= 21
        {
            page_data = page.data.clone();
            page_data[20] = target.reserve_size as u8;
            page_data.as_slice()
        } else {
            page.data.as_slice()
        };
        let write_started = Instant::now();
        db_file.write_at(page_offset, data).with_context(|| {
            format!(
                "failed to materialize DB page {} at offset {page_offset}",
                page.page_no
            )
        })?;
        db_write_micros += write_started.elapsed().as_micros() as u64;
    }

    if !batch.pages.is_empty() {
        if let Some(db_size_pages) = batch.db_size_pages {
            let db_size = db_size_pages as i64 * target.page_size as i64;
            db_file
                .truncate(db_size)
                .with_context(|| format!("failed to truncate follower DB to {db_size} bytes"))?;
        }
        let sync_started = Instant::now();
        db_file
            .sync()
            .context("failed to sync follower DB file after materialization")?;
        db_sync_micros += sync_started.elapsed().as_micros() as u64;
    }

    let shm_started = Instant::now();
    let shm_result = {
        let mut wal = wal_file
            .lock()
            .map_err(|_| anyhow::anyhow!("replay WAL file lock poisoned"))?;
        wal.delete(&target.shm_path, false)
    };
    let shm_micros = shm_started.elapsed().as_micros() as u64;

    let mut st = state
        .lock()
        .map_err(|_| anyhow::anyhow!("replay state lock poisoned"))?;
    st.stats.materialize_batches += 1;
    st.stats.materialize_frames += batch.pages.len() as u64;
    st.stats.db_syncs += u64::from(!batch.pages.is_empty());
    match shm_result {
        Ok(()) => st.stats.shm_invalidations += 1,
        Err(_) => st.stats.replay_errors += 1,
    }
    st.stats.materialize_db_write_micros += db_write_micros;
    st.stats.materialize_db_sync_micros += db_sync_micros;
    st.stats.materialize_shm_invalidate_micros += shm_micros;
    st.stats.last_materialize_db_write_micros = db_write_micros;
    st.stats.last_materialize_db_sync_micros = db_sync_micros;
    st.stats.last_materialize_shm_invalidate_micros = shm_micros;
    st.stats.materialize_queue_depth = queue_depth.load(Ordering::Relaxed) as u64;
    st.stats.last_materialized_offset = batch.target_offset;
    st.stats.last_materialize_error = None;
    Ok(())
}

fn recover_existing_wal(
    target: &ReplayTargetConfig,
    wal_file: &Arc<Mutex<VfsWalFile>>,
    state: &Arc<Mutex<ReplayState>>,
    queue_depth: &Arc<AtomicUsize>,
    db_file: &mut VfsWalFile,
) -> Result<()> {
    let frame_size = target.page_size as i64 + 24;
    let mut wal = wal_file
        .lock()
        .map_err(|_| anyhow::anyhow!("replay WAL file lock poisoned"))?;
    let wal_size = wal.file_size().context("failed to stat follower WAL")?;
    if wal_size < 32 {
        return Ok(());
    }

    let mut header = [0u8; 32];
    wal.read_at(0, &mut header)
        .context("failed to read follower WAL header during recovery")?;

    let full_frames = ((wal_size - 32) / frame_size).max(0);
    let mut pending_pages = Vec::new();
    let mut committed_pages = Vec::with_capacity(full_frames as usize);
    let mut last_offset = 0_i64;
    let mut last_commit_offset = 0_i64;
    let mut last_db_size_pages = None;
    for idx in 0..full_frames {
        let offset = 32 + idx * frame_size;
        let mut frame = vec![0u8; frame_size as usize];
        wal.read_at(offset, &mut frame)
            .with_context(|| format!("failed to read follower WAL frame at offset {offset}"))?;
        let page_no = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        if page_no == 0 {
            break;
        }
        pending_pages.push(MaterializePage {
            page_no,
            data: frame[24..].to_vec(),
        });
        last_offset = offset;
        let db_size = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]);
        if db_size != 0 {
            committed_pages.append(&mut pending_pages);
            last_commit_offset = offset;
            last_db_size_pages = Some(db_size);
        }
    }
    drop(wal);

    {
        let mut st = state
            .lock()
            .map_err(|_| anyhow::anyhow!("replay state lock poisoned"))?;
        st.stats.last_applied_offset = last_offset;
        st.stats.last_wal_synced_offset = last_offset;
        st.pending_pages = pending_pages;
    }

    materialize_batch(
        target,
        wal_file,
        state,
        queue_depth,
        db_file,
        MaterializeBatch {
            target_offset: last_commit_offset,
            db_size_pages: last_db_size_pages,
            pages: committed_pages,
        },
    )
    .context("failed to recover follower DB from existing WAL")?;
    Ok(())
}

impl FollowerReplaySink {
    pub fn open(target: ReplayTargetConfig) -> Result<Arc<Self>> {
        let wal_file = VfsWalFile::open_with_flags(
            &target.wal_path,
            &target.io_vfs_name,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_WAL | SQLITE_OPEN_MAIN_DB,
        )
        .with_context(|| {
            format!(
                "failed to open follower WAL path '{}' via sqlite vfs '{}'",
                target.wal_path, target.io_vfs_name
            )
        })?;
        let mut db_file = VfsWalFile::open_with_flags(
            &target.db_path,
            &target.io_vfs_name,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_MAIN_DB,
        )
        .with_context(|| {
            format!(
                "failed to open follower DB path '{}' via sqlite vfs '{}'",
                target.db_path, target.io_vfs_name
            )
        })?;

        let frame_size = target.page_size as i64 + 24;
        let wal_file = Arc::new(Mutex::new(wal_file));
        if target.rebuild_on_open {
            {
                let mut wal = wal_file
                    .lock()
                    .map_err(|_| anyhow::anyhow!("replay WAL file lock poisoned"))?;
                wal.truncate(0)
                    .context("failed to truncate follower WAL before replay rebuild")?;
                wal.sync()
                    .context("failed to sync truncated follower WAL before replay rebuild")?;
            }
            db_file
                .truncate(0)
                .context("failed to truncate follower DB before replay rebuild")?;
            db_file
                .sync()
                .context("failed to sync truncated follower DB before replay rebuild")?;
        }
        let follower_wal_sync = target.follower_wal_sync.clone();
        let wal_sync_policy = match follower_wal_sync.mode {
            FollowerWalSyncMode::PerBatch => "per-batch",
            FollowerWalSyncMode::Coalesced => "coalesced",
        }
        .to_string();
        let state = Arc::new(Mutex::new(ReplayState {
            stats: ReplayStats {
                last_applied_offset: -1,
                last_wal_synced_offset: -1,
                last_materialized_offset: -1,
                wal_sync_policy,
                ..ReplayStats::default()
            },
            frame_size,
            pending_pages: Vec::new(),
        }));
        let (materialize_tx, materialize_rx) =
            mpsc::sync_channel::<MaterializeBatch>(MATERIALIZE_QUEUE_CAPACITY);
        let materialize_queue_depth = Arc::new(AtomicUsize::new(0));
        recover_existing_wal(
            &target,
            &wal_file,
            &state,
            &materialize_queue_depth,
            &mut db_file,
        )?;
        spawn_materializer(
            target.clone(),
            wal_file.clone(),
            state.clone(),
            materialize_queue_depth.clone(),
            db_file,
            materialize_rx,
        );
        let wal_sync_state = Arc::new(WalSyncCoordinator::new());
        spawn_wal_sync_worker(
            follower_wal_sync,
            wal_file.clone(),
            state.clone(),
            wal_sync_state.clone(),
        );

        Ok(Arc::new(Self {
            target,
            wal_file,
            state,
            materialize_tx,
            materialize_queue_depth,
            wal_sync_state,
        }))
    }

    pub fn apply_record(&self, record: &WalRecord) -> Result<()> {
        self.apply_batch(&WalBatch::new(vec![record.clone()]))
    }

    pub fn apply_batch(&self, batch: &WalBatch) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        let started = Instant::now();
        let mut st = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("replay state lock poisoned"))?;

        let mut wal_needs_sync = false;
        let mut batch_wal_write_micros = 0u64;
        let mut batch_wal_sync_micros = 0u64;
        let mut materialize_pages = Vec::new();
        let mut materialize_offset = st.stats.last_applied_offset;
        let mut materialize_db_size_pages = None;
        let mut sync_offset = st.stats.last_applied_offset;
        let mut materialize_needed = false;

        {
            let mut wal = self
                .wal_file
                .lock()
                .map_err(|_| anyhow::anyhow!("replay WAL file lock poisoned"))?;

            for record in &batch.records {
                match record {
                    WalRecord::Header { data } => {
                        if data.len() != 32 {
                            st.stats.replay_errors += 1;
                            anyhow::bail!(
                                "invalid WAL header size: got={}, expected=32",
                                data.len()
                            );
                        }

                        let write_started = Instant::now();
                        wal.truncate(0)
                            .context("failed to truncate WAL file for new header")?;
                        wal.write_at(0, data)
                            .context("failed to write WAL header at offset 0")?;
                        batch_wal_write_micros += write_started.elapsed().as_micros() as u64;
                        wal_needs_sync = true;

                        st.stats.applied_records += 1;
                        st.stats.applied_bytes += data.len() as u64;
                        st.stats.last_applied_offset = 0;
                        st.pending_pages.clear();
                        materialize_offset = 0;
                        sync_offset = 0;
                        materialize_needed = true;
                    }
                    WalRecord::Frame {
                        wal_offset,
                        data: frame_data,
                        page_no,
                    } => {
                        let wal_offset = *wal_offset;
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
                            continue;
                        }

                        let expected_next = if st.stats.last_applied_offset <= 0 {
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

                        let wal_write_started = Instant::now();
                        wal.write_at(wal_offset, frame_data).with_context(|| {
                            format!("failed to write WAL frame at offset {wal_offset}")
                        })?;
                        batch_wal_write_micros += wal_write_started.elapsed().as_micros() as u64;
                        wal_needs_sync = true;

                        let page_bytes = &frame_data[24..];
                        st.pending_pages.push(MaterializePage {
                            page_no: *page_no,
                            data: page_bytes.to_vec(),
                        });

                        st.stats.last_applied_offset = wal_offset;
                        sync_offset = wal_offset;
                        st.stats.applied_records += 1;
                        st.stats.applied_frames += 1;
                        st.stats.applied_bytes += frame_data.len() as u64;

                        let db_size = u32::from_be_bytes([
                            frame_data[4],
                            frame_data[5],
                            frame_data[6],
                            frame_data[7],
                        ]);
                        if db_size != 0 {
                            materialize_pages.append(&mut st.pending_pages);
                            materialize_offset = wal_offset;
                            materialize_db_size_pages = Some(db_size);
                            materialize_needed = true;
                        }
                    }
                    WalRecord::DbPage {
                        page_no,
                        db_size_pages,
                        data,
                    } => {
                        if data.len() != self.target.page_size as usize {
                            st.stats.replay_errors += 1;
                            anyhow::bail!(
                                "invalid DB page size: got={}, expected={}",
                                data.len(),
                                self.target.page_size
                            );
                        }
                        materialize_pages.push(MaterializePage {
                            page_no: *page_no,
                            data: data.clone(),
                        });
                        materialize_db_size_pages = Some(*db_size_pages);
                        materialize_needed = true;
                        st.stats.applied_records += 1;
                        st.stats.applied_bytes += data.len() as u64;
                    }
                }
            }

            if wal_needs_sync && self.target.follower_wal_sync.mode == FollowerWalSyncMode::PerBatch
            {
                let sync_started = Instant::now();
                wal.sync()
                    .context("failed to sync WAL replay file after batch apply")?;
                batch_wal_sync_micros += sync_started.elapsed().as_micros() as u64;
                st.stats.wal_syncs += 1;
                st.stats.wal_sync_batches += 1;
                st.stats.last_wal_sync_batches = 1;
                st.stats.last_wal_synced_offset = sync_offset;
            }
        }

        if wal_needs_sync && self.target.follower_wal_sync.mode == FollowerWalSyncMode::Coalesced {
            self.mark_wal_sync_pending(&mut st, sync_offset)?;
        }

        if materialize_needed {
            let materialize_batch = MaterializeBatch {
                target_offset: materialize_offset,
                db_size_pages: materialize_db_size_pages,
                pages: materialize_pages,
            };
            self.materialize_queue_depth.fetch_add(1, Ordering::Relaxed);
            st.stats.materialize_queue_depth =
                self.materialize_queue_depth.load(Ordering::Relaxed) as u64;
            if let Err(err) = self.materialize_tx.send(materialize_batch) {
                self.materialize_queue_depth.fetch_sub(1, Ordering::Relaxed);
                st.stats.materialize_queue_depth =
                    self.materialize_queue_depth.load(Ordering::Relaxed) as u64;
                st.stats.materialize_errors += 1;
                anyhow::bail!("failed to enqueue follower DB materialization batch: {err}");
            }
        }

        st.stats.applied_batches += 1;
        st.stats.last_batch_records = batch.len() as u64;
        st.stats.last_apply_micros = started.elapsed().as_micros() as u64;
        st.stats.wal_write_micros += batch_wal_write_micros;
        st.stats.wal_sync_micros += batch_wal_sync_micros;
        st.stats.last_wal_write_micros = batch_wal_write_micros;
        if batch_wal_sync_micros != 0 {
            st.stats.last_wal_sync_micros = batch_wal_sync_micros;
        }
        Ok(())
    }

    fn mark_wal_sync_pending(&self, st: &mut ReplayState, target_offset: i64) -> Result<()> {
        let max_pending = MATERIALIZE_QUEUE_CAPACITY as u64;
        let mut sync_state = self
            .wal_sync_state
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("WAL sync state lock poisoned"))?;
        while sync_state.pending_batches >= max_pending {
            sync_state = self
                .wal_sync_state
                .cv
                .wait(sync_state)
                .map_err(|_| anyhow::anyhow!("WAL sync state lock poisoned"))?;
        }
        sync_state.pending_batches += 1;
        sync_state.pending_offset = target_offset;
        if sync_state.first_pending_at.is_none() {
            sync_state.first_pending_at = Some(Instant::now());
        }
        st.stats.pending_wal_sync_batches = sync_state.pending_batches;
        self.wal_sync_state.cv.notify_one();
        Ok(())
    }

    pub fn truncate_at(&self, wal_offset: i64) -> Result<()> {
        let mut st = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("replay state lock poisoned"))?;
        let f = self
            .wal_file
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
        st.stats.last_wal_synced_offset = st.stats.last_applied_offset;
        st.stats.last_materialized_offset = st.stats.last_applied_offset;
        st.pending_pages.clear();
        if let Ok(mut sync_state) = self.wal_sync_state.state.lock() {
            sync_state.pending_batches = 0;
            sync_state.pending_offset = -1;
            sync_state.first_pending_at = None;
            st.stats.pending_wal_sync_batches = 0;
            self.wal_sync_state.cv.notify_all();
        }
        self.invalidate_shm_locked(&mut st);
        Ok(())
    }

    pub fn sync(&self) -> Result<()> {
        let mut f = self
            .wal_file
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
        let mut f = match self.wal_file.lock() {
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

impl Drop for FollowerReplaySink {
    fn drop(&mut self) {
        if let Ok(mut state) = self.wal_sync_state.state.lock() {
            state.shutdown = true;
            self.wal_sync_state.cv.notify_all();
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
    use std::{ptr, thread, time::Duration};

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
            reserve_size: 48,
            follower_wal_sync: FollowerWalSyncConfig::default(),
            rebuild_on_open: false,
        }
    }

    fn coalesced_target(
        tmp: &TempDir,
        max_batches: usize,
        max_delay_ms: u64,
    ) -> ReplayTargetConfig {
        let mut target = target(tmp);
        target.follower_wal_sync = FollowerWalSyncConfig {
            mode: FollowerWalSyncMode::Coalesced,
            max_batches,
            max_delay_ms,
        };
        target
    }

    fn commit_frame(page_no: u32) -> Vec<u8> {
        let mut frame = vec![0u8; 4096 + 24];
        frame[0..4].copy_from_slice(&page_no.to_be_bytes());
        frame[4..8].copy_from_slice(&1u32.to_be_bytes());
        frame
    }

    fn wait_for_materialized(sink: &FollowerReplaySink, offset: i64) {
        for _ in 0..100 {
            if sink.stats().last_materialized_offset >= offset {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "timed out waiting for materialized offset {offset}, stats={:?}",
            sink.stats()
        );
    }

    fn wait_for_wal_synced(sink: &FollowerReplaySink, offset: i64) {
        for _ in 0..100 {
            if sink.stats().last_wal_synced_offset >= offset {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "timed out waiting for WAL synced offset {offset}, stats={:?}",
            sink.stats()
        );
    }

    #[test]
    fn replay_enforces_offset_order_and_idempotency() {
        if !sqlite_api_is_available() {
            eprintln!("skipping replay test: sqlite extension API is unavailable");
            return;
        }
        let tmp = TempDir::new().expect("tmp dir");
        let sink = FollowerReplaySink::open(target(&tmp)).expect("open sink");
        let header = WalRecord::Header {
            data: vec![0xAA; 32],
        };
        let frame = WalRecord::Frame {
            wal_offset: 32,
            page_no: 1,
            data: commit_frame(1),
        };

        sink.apply_record(&header).expect("apply header");
        sink.apply_record(&frame).expect("apply first");
        wait_for_materialized(&sink, 32);
        sink.apply_record(&frame).expect("idempotent duplicate");
        let err = sink
            .apply_record(&WalRecord::Frame {
                wal_offset: 32 + 2 * (4096 + 24) as i64,
                page_no: 2,
                data: commit_frame(2),
            })
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
            .apply_record(&WalRecord::Frame {
                wal_offset: 32,
                page_no: 1,
                data: vec![0u8; 8],
            })
            .expect_err("short frame should fail");
        assert!(err.to_string().contains("invalid WAL frame size"));
    }

    #[test]
    fn replay_writes_header_and_frame_bytes() {
        if !sqlite_api_is_available() {
            eprintln!("skipping replay test: sqlite extension API is unavailable");
            return;
        }
        let tmp = TempDir::new().expect("tmp dir");
        let sink = FollowerReplaySink::open(target(&tmp)).expect("open sink");
        let header = WalRecord::Header {
            data: (0..32u8).collect(),
        };
        let frame = commit_frame(3);
        let frame_record = WalRecord::Frame {
            wal_offset: 32,
            page_no: 3,
            data: frame.clone(),
        };

        sink.apply_record(&header).expect("apply header");
        sink.apply_record(&frame_record).expect("apply frame");
        wait_for_materialized(&sink, 32);

        let wal = std::fs::read(tmp.path().join("follower.db-wal")).expect("read wal");
        assert_eq!(&wal[..32], &(0..32u8).collect::<Vec<_>>()[..]);
        assert_eq!(&wal[32..32 + frame.len()], &frame);
    }

    #[test]
    fn replay_reopen_recovers_materialization_from_existing_wal() {
        if !sqlite_api_is_available() {
            eprintln!("skipping replay test: sqlite extension API is unavailable");
            return;
        }
        let tmp = TempDir::new().expect("tmp dir");
        {
            let sink = FollowerReplaySink::open(target(&tmp)).expect("open sink");
            let mut frame = vec![0u8; 4096 + 24];
            frame[0..4].copy_from_slice(&3u32.to_be_bytes());
            frame[4..8].copy_from_slice(&1u32.to_be_bytes());
            frame[24..].fill(0x5A);
            sink.apply_batch(&WalBatch::new(vec![
                WalRecord::Header { data: vec![0; 32] },
                WalRecord::Frame {
                    wal_offset: 32,
                    page_no: 3,
                    data: frame,
                },
            ]))
            .expect("apply batch");
            wait_for_materialized(&sink, 32);
        }

        let reopened = FollowerReplaySink::open(target(&tmp)).expect("reopen sink");
        let stats = reopened.stats();
        assert_eq!(stats.last_applied_offset, 32);
        assert_eq!(stats.last_wal_synced_offset, 32);
        assert_eq!(stats.last_materialized_offset, 32);

        let db = std::fs::read(tmp.path().join("follower.db")).expect("read db");
        assert_eq!(&db[2 * 4096..2 * 4096 + 16], &[0x5A; 16]);
    }

    #[test]
    fn replay_batch_syncs_once_and_updates_stats() {
        if !sqlite_api_is_available() {
            eprintln!("skipping replay test: sqlite extension API is unavailable");
            return;
        }
        let tmp = TempDir::new().expect("tmp dir");
        let sink = FollowerReplaySink::open(target(&tmp)).expect("open sink");
        let header = WalRecord::Header {
            data: vec![0xAA; 32],
        };
        let mut frame1 = commit_frame(1);
        frame1[4..8].copy_from_slice(&0u32.to_be_bytes());
        let frame2 = commit_frame(2);

        sink.apply_batch(&WalBatch::new(vec![
            header,
            WalRecord::Frame {
                wal_offset: 32,
                page_no: 1,
                data: frame1,
            },
            WalRecord::Frame {
                wal_offset: 32 + (4096 + 24) as i64,
                page_no: 2,
                data: frame2,
            },
        ]))
        .expect("apply batch");

        wait_for_materialized(&sink, 32 + (4096 + 24) as i64);

        let stats = sink.stats();
        assert_eq!(stats.applied_batches, 1);
        assert_eq!(stats.applied_records, 3);
        assert_eq!(stats.applied_frames, 2);
        assert_eq!(stats.last_batch_records, 3);
        assert_eq!(stats.wal_syncs, 1);
        assert_eq!(stats.last_wal_synced_offset, 32 + (4096 + 24) as i64);
        assert_eq!(stats.db_syncs, 1);
        assert_eq!(stats.materialize_batches, 1);
        assert_eq!(stats.materialize_frames, 2);
    }

    #[test]
    fn coalesced_wal_syncs_after_batch_threshold() {
        if !sqlite_api_is_available() {
            eprintln!("skipping replay test: sqlite extension API is unavailable");
            return;
        }
        let tmp = TempDir::new().expect("tmp dir");
        let sink = FollowerReplaySink::open(coalesced_target(&tmp, 2, 10_000)).expect("open sink");
        sink.apply_record(&WalRecord::Header {
            data: vec![0u8; 32],
        })
        .expect("apply header");
        assert_eq!(sink.stats().last_applied_offset, 0);
        assert_eq!(sink.stats().last_wal_synced_offset, -1);
        let frame = commit_frame(1);
        sink.apply_record(&WalRecord::Frame {
            wal_offset: 32,
            page_no: 1,
            data: frame,
        })
        .expect("apply frame");
        wait_for_wal_synced(&sink, 32);
        let stats = sink.stats();
        assert_eq!(stats.wal_sync_policy, "coalesced");
        assert_eq!(stats.coalesced_wal_syncs, 1);
        assert_eq!(stats.last_wal_sync_batches, 2);
    }

    #[test]
    fn coalesced_wal_syncs_after_delay() {
        if !sqlite_api_is_available() {
            eprintln!("skipping replay test: sqlite extension API is unavailable");
            return;
        }
        let tmp = TempDir::new().expect("tmp dir");
        let sink = FollowerReplaySink::open(coalesced_target(&tmp, 64, 10)).expect("open sink");
        sink.apply_record(&WalRecord::Header {
            data: vec![0u8; 32],
        })
        .expect("apply header");
        assert_eq!(sink.stats().last_applied_offset, 0);
        assert_eq!(sink.stats().last_wal_synced_offset, -1);
        wait_for_wal_synced(&sink, 0);
        let stats = sink.stats();
        assert_eq!(stats.coalesced_wal_syncs, 1);
        assert_eq!(stats.last_wal_sync_batches, 1);
        assert!(stats.last_wal_sync_delay_micros > 0);
    }

    #[test]
    fn truncate_updates_state() {
        if !sqlite_api_is_available() {
            eprintln!("skipping replay test: sqlite extension API is unavailable");
            return;
        }
        let tmp = TempDir::new().expect("tmp dir");
        let sink = FollowerReplaySink::open(target(&tmp)).expect("open sink");
        sink.apply_record(&WalRecord::Header {
            data: vec![0u8; 32],
        })
        .expect("apply header");
        let frame = commit_frame(1);
        sink.apply_record(&WalRecord::Frame {
            wal_offset: 32,
            page_no: 1,
            data: frame,
        })
        .expect("apply first");
        sink.apply_record(&WalRecord::Frame {
            wal_offset: 32 + (4096 + 24) as i64,
            page_no: 2,
            data: commit_frame(2),
        })
        .expect("apply second");
        wait_for_materialized(&sink, 32 + (4096 + 24) as i64);
        sink.truncate_at(32).expect("truncate");
        assert_eq!(sink.stats().last_applied_offset, -1);
        assert_eq!(sink.stats().last_materialized_offset, -1);
    }
}
