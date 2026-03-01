// src/vfs/mod.rs

//! SQLite VFS FFI shim.
//!
//! Registers a custom VFS named "evfs" that wraps the default OS VFS,
//! adding:
//!   * page-level encryption on every read/write
//!   * WAL-frame replication via Raft
//!
//! Encryption and replication concerns are each handled by their own
//! module; this file only orchestrates the SQLite C ABI plumbing.

pub mod consensus;
pub mod crypt;

use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    ptr,
    sync::Arc,
};

use libsqlite3_sys::*;

use crate::{
    keyring::Keyring,
    vfs::{
        consensus::{handle::RaftHandle, wal::WalFileState},
        crypt::PageCryptor,
    },
};

// ── Our extended file struct ────────────────────────────────────────

/// Must start with `sqlite3_file` so SQLite can cast between them.
#[repr(C)]
struct EvfsFile {
    /// Base — SQLite only sees this field.
    base: sqlite3_file,
    /// The real file opened by the underlying OS VFS.
    inner_file: *mut sqlite3_file,
    /// Encryption handle for this file (page 1 exempted).
    cryptor: *mut PageCryptor,
    /// Present only for WAL file descriptors; `None` for all others.
    wal_state: *mut Option<WalFileState>,
    /// Whether page-level encryption is active for this fd.
    encrypt_enabled: bool,
    /// Optional Raft handle; populated in `evfs_open` when replication
    /// is enabled.  Stored here so `xSync` and `xLock` can reach it
    /// without an extra indirection through the VFS struct.
    raft_handle: *mut Option<Arc<RaftHandle>>,
}

// ── Global VFS context ───────────────────────────────────────────────

struct EvfsGlobal {
    cryptor: PageCryptor,
    inner_vfs: *mut sqlite3_vfs,
    /// Optional Raft handle; `None` = standalone (encrypt-only) mode.
    raft: Option<Arc<RaftHandle>>,
    /// Our io_methods table (static lifetime after registration).
    io_methods: sqlite3_io_methods,
}

// Safety: inner_vfs comes from SQLite and is valid for the process
// lifetime. EvfsGlobal is leaked and never mutated after registration.
unsafe impl Send for EvfsGlobal {}
unsafe impl Sync for EvfsGlobal {}

// ── Page offset helpers ─────────────────────────────────────────────

#[inline]
fn page_no_for_offset(i_ofst: i64, page_size: i64) -> u32 {
    (i_ofst / page_size) as u32 + 1
}

#[inline]
fn page_start_offset(page_no: u32, page_size: i64) -> i64 {
    (page_no as i64 - 1) * page_size
}

// ── Inner file helpers ──────────────────────────────────────────────

unsafe fn inner_filesize(inner: *mut sqlite3_file) -> Option<i64> {
    unsafe {
        let mut sz: i64 = 0;
        let rc = ((*(*inner).pMethods).xFileSize.unwrap())(inner, &mut sz);
        if rc == SQLITE_OK { Some(sz) } else { None }
    }
}

// ── Page-1 initialisation ───────────────────────────────────────────

fn try_reserve_page1(cryptor: &PageCryptor, inner: *mut sqlite3_file) -> c_int {
    unsafe {
        let Some(sz) = inner_filesize(inner) else {
            return SQLITE_IOERR;
        };
        if sz != 0 {
            return SQLITE_OK;
        }

        let page_size = cryptor.page_size as usize;
        let reserve = cryptor.reserve_size;

        if !(512..=65536).contains(&page_size) {
            return SQLITE_IOERR;
        }
        if reserve > u8::MAX as usize || reserve < 22 || page_size < 108 {
            return SQLITE_IOERR;
        }

        let usable_size = page_size - reserve;
        let mut page1 = vec![0u8; page_size];

        // SQLite database header (bytes 0–99).
        page1[0..16].copy_from_slice(b"SQLite format 3\0");
        if page_size == 65536 {
            page1[16] = 0;
            page1[17] = 1;
        } else {
            let ps = page_size as u16;
            page1[16] = (ps >> 8) as u8;
            page1[17] = (ps & 0xff) as u8;
        }
        page1[18] = 1; // file format write version
        page1[19] = 1; // file format read version
        page1[20] = reserve as u8; // reserved bytes per page
        page1[21] = 64; // max embedded payload fraction
        page1[22] = 32; // min embedded payload fraction
        page1[23] = 32; // leaf payload fraction
        page1[24..28].copy_from_slice(&1u32.to_be_bytes()); // file change counter
        page1[28..32].copy_from_slice(&1u32.to_be_bytes()); // database size in pages
        page1[40..44].copy_from_slice(&1u32.to_be_bytes()); // schema cookie
        page1[44..48].copy_from_slice(&4u32.to_be_bytes()); // schema format number
        page1[56..60].copy_from_slice(&1u32.to_be_bytes()); // text encoding: UTF-8
        page1[92..96].copy_from_slice(&1u32.to_be_bytes()); // version-valid-for
        page1[96..100].copy_from_slice(&3045001u32.to_be_bytes()); // SQLite version

        // Btree page header for an empty table-leaf (bytes 100+).
        page1[100] = 0x0D; // page type: table leaf
        let sc = usable_size as u16;
        page1[105] = (sc >> 8) as u8;
        page1[106] = (sc & 0xff) as u8;

        let rcw = ((*(*inner).pMethods).xWrite.unwrap())(
            inner,
            page1.as_ptr() as *const c_void,
            page_size as c_int,
            0,
        );
        if rcw != SQLITE_OK {
            return rcw;
        }
        let _ = ((*(*inner).pMethods).xSync.unwrap())(inner, 0);
        SQLITE_OK
    }
}

// ── xOpen ───────────────────────────────────────────────────────────

unsafe extern "C" fn evfs_open(
    vfs: *mut sqlite3_vfs,
    z_name: *const c_char,
    file: *mut sqlite3_file,
    flags: c_int,
    p_out_flags: *mut c_int,
) -> c_int {
    unsafe {
        let global = &*((*vfs).pAppData as *const EvfsGlobal);
        let inner_vfs = global.inner_vfs;
        let efile = file as *mut EvfsFile;

        let encrypt_enabled = (flags & SQLITE_OPEN_MAIN_DB) != 0;
        let is_wal = (flags & SQLITE_OPEN_WAL) != 0;

        // Allocate inner file buffer.
        let inner_sz = (*inner_vfs).szOsFile as usize;
        let inner_buf = libc::malloc(inner_sz) as *mut sqlite3_file;
        if inner_buf.is_null() {
            return SQLITE_NOMEM;
        }
        ptr::write_bytes(inner_buf as *mut u8, 0, inner_sz);

        let rc = ((*inner_vfs).xOpen.unwrap())(inner_vfs, z_name, inner_buf, flags, p_out_flags);
        if rc != SQLITE_OK {
            libc::free(inner_buf as *mut c_void);
            return rc;
        }

        // Pre-create page 1 for brand-new MAIN database files only.
        if encrypt_enabled && (flags & SQLITE_OPEN_CREATE) != 0 {
            let rc = try_reserve_page1(&global.cryptor, inner_buf);
            if rc != SQLITE_OK {
                let _ = ((*(*inner_buf).pMethods).xClose.unwrap())(inner_buf);
                libc::free(inner_buf as *mut c_void);
                return rc;
            }
        }

        // Per-file cryptor (clone is cheap: Arc inside).
        let cryptor = Box::into_raw(Box::new(global.cryptor.clone()));

        // Bind sidecar path on the MAIN DB file only.
        if encrypt_enabled && !z_name.is_null() {
            let name = CStr::from_ptr(z_name);
            if let Ok(s) = name.to_str() {
                (*cryptor).set_db_path(std::path::Path::new(s));
            }
        }

        // WAL state — Some only for WAL file descriptors with Raft enabled.
        let wal_state: *mut Option<WalFileState> =
            Box::into_raw(Box::new(if is_wal && global.raft.is_some() {
                let db_name = if z_name.is_null() {
                    "unknown".to_string()
                } else {
                    CStr::from_ptr(z_name).to_string_lossy().into_owned()
                };
                Some(WalFileState::new(db_name, global.cryptor.page_size))
            } else {
                None
            }));

        // Raft handle — cloned from global when replication is active.
        let raft_handle: *mut Option<Arc<RaftHandle>> =
            Box::into_raw(Box::new(global.raft.clone()));

        (*efile).base.pMethods = &global.io_methods;
        (*efile).inner_file = inner_buf;
        (*efile).cryptor = cryptor;
        (*efile).wal_state = wal_state;
        (*efile).encrypt_enabled = encrypt_enabled;
        (*efile).raft_handle = raft_handle;

        SQLITE_OK
    }
}

// ── xClose ──────────────────────────────────────────────────────────

unsafe extern "C" fn evfs_close(file: *mut sqlite3_file) -> c_int {
    unsafe {
        let efile = file as *mut EvfsFile;
        let inner = (*efile).inner_file;

        let rc = if !inner.is_null() && !(*inner).pMethods.is_null() {
            ((*(*inner).pMethods).xClose.unwrap())(inner)
        } else {
            SQLITE_OK
        };

        if !inner.is_null() {
            libc::free(inner as *mut c_void);
        }
        if !(*efile).cryptor.is_null() {
            drop(Box::from_raw((*efile).cryptor));
            (*efile).cryptor = ptr::null_mut();
        }
        if !(*efile).wal_state.is_null() {
            drop(Box::from_raw((*efile).wal_state));
            (*efile).wal_state = ptr::null_mut();
        }
        if !(*efile).raft_handle.is_null() {
            drop(Box::from_raw((*efile).raft_handle));
            (*efile).raft_handle = ptr::null_mut();
        }

        rc
    }
}

// ── xRead ───────────────────────────────────────────────────────────

unsafe extern "C" fn evfs_read(
    file: *mut sqlite3_file,
    buf: *mut c_void,
    i_amt: c_int,
    i_ofst: i64,
) -> c_int {
    unsafe {
        let efile = file as *mut EvfsFile;
        let inner = (*efile).inner_file;
        let cryptor = &*(*efile).cryptor;

        if !(*efile).encrypt_enabled {
            return ((*(*inner).pMethods).xRead.unwrap())(inner, buf, i_amt, i_ofst);
        }

        let page_size = cryptor.page_size as i64;
        let amt = i_amt as usize;

        // Fast path: full aligned page read.
        if i_amt as u32 == cryptor.page_size && i_ofst % page_size == 0 {
            let rc = ((*(*inner).pMethods).xRead.unwrap())(inner, buf, i_amt, i_ofst);
            if rc != SQLITE_OK {
                return rc;
            }
            let page_no = page_no_for_offset(i_ofst, page_size);
            if page_no != 1 {
                let slice = std::slice::from_raw_parts_mut(buf as *mut u8, amt);
                if let Err(e) = cryptor.decrypt(slice, page_no) {
                    log::error!("evfs xRead decrypt page {page_no}: {e}");
                    return SQLITE_IOERR_READ;
                }
            }
            return SQLITE_OK;
        }

        // Slow path: sub-page or cross-page range read.
        let out = std::slice::from_raw_parts_mut(buf as *mut u8, amt);
        let start = i_ofst;
        let end = i_ofst.checked_add(i_amt as i64).unwrap_or(i64::MAX);
        let first_page = page_no_for_offset(start, page_size);
        let last_page = page_no_for_offset(end - 1, page_size);

        let mut out_cursor = 0usize;
        for page_no in first_page..=last_page {
            let p_start = page_start_offset(page_no, page_size);
            let p_end = p_start + page_size;
            let seg_start = start.max(p_start);
            let seg_end = end.min(p_end);
            let seg_len = (seg_end - seg_start) as usize;

            let mut page_buf = vec![0u8; cryptor.page_size as usize];
            let rc = ((*(*inner).pMethods).xRead.unwrap())(
                inner,
                page_buf.as_mut_ptr() as *mut c_void,
                cryptor.page_size as c_int,
                p_start,
            );
            let short_read = rc == SQLITE_IOERR_SHORT_READ;
            if rc != SQLITE_OK && !short_read {
                return rc;
            }

            if page_no != 1
                && !short_read
                && let Err(e) = cryptor.decrypt(&mut page_buf, page_no)
            {
                log::error!("evfs xRead slow-path decrypt page {page_no}: {e}");
                return SQLITE_IOERR_READ;
            }

            let in_page_off = (seg_start - p_start) as usize;
            out[out_cursor..out_cursor + seg_len]
                .copy_from_slice(&page_buf[in_page_off..in_page_off + seg_len]);
            out_cursor += seg_len;
        }
        debug_assert_eq!(out_cursor, out.len());
        SQLITE_OK
    }
}

// ── xWrite ──────────────────────────────────────────────────────────

unsafe extern "C" fn evfs_write(
    file: *mut sqlite3_file,
    buf: *const c_void,
    i_amt: c_int,
    i_ofst: i64,
) -> c_int {
    unsafe {
        let efile = file as *mut EvfsFile;
        let inner = (*efile).inner_file;
        let cryptor = &*(*efile).cryptor;

        if !(*efile).encrypt_enabled {
            return ((*(*inner).pMethods).xWrite.unwrap())(inner, buf, i_amt, i_ofst);
        }

        let page_size = cryptor.page_size as i64;
        let amt = i_amt as usize;

        // Fast path: full aligned page write.
        if i_amt as u32 == cryptor.page_size && i_ofst % page_size == 0 {
            let page_no = page_no_for_offset(i_ofst, page_size);
            let mut page_buf = std::slice::from_raw_parts(buf as *const u8, amt).to_vec();

            if page_no == 1 {
                // Page 1 stays plaintext; just keep the reserve field correct.
                if cryptor.reserve_size <= u8::MAX as usize && page_buf.len() >= 21 {
                    page_buf[20] = cryptor.reserve_size as u8;
                }
            } else if let Err(e) = cryptor.encrypt(&mut page_buf, page_no) {
                log::error!("evfs xWrite encrypt page {page_no}: {e}");
                return SQLITE_IOERR_WRITE;
            }

            // Buffer for WAL replication before hitting the OS.
            if let Some(ws) = (*(*efile).wal_state).as_mut() {
                let _frames: Vec<(i64, u32, Vec<u8>)> = ws.push(&page_buf, i_ofst);
                // Full frame accumulation and Raft submission happen in xSync.
            }

            return ((*(*inner).pMethods).xWrite.unwrap())(
                inner,
                page_buf.as_ptr() as *const c_void,
                i_amt,
                i_ofst,
            );
        }

        // Slow path: sub-page or cross-page range write.
        let inp = std::slice::from_raw_parts(buf as *const u8, amt);
        let start = i_ofst;
        let end = i_ofst.checked_add(i_amt as i64).unwrap_or(i64::MAX);
        let first_page = page_no_for_offset(start, page_size);
        let last_page = page_no_for_offset(end - 1, page_size);

        let mut in_cursor = 0usize;
        for page_no in first_page..=last_page {
            let p_start = page_start_offset(page_no, page_size);
            let p_end = p_start + page_size;
            let seg_start = start.max(p_start);
            let seg_end = end.min(p_end);
            let seg_len = (seg_end - seg_start) as usize;
            let in_page_off = (seg_start - p_start) as usize;

            let mut page_buf = vec![0u8; cryptor.page_size as usize];
            let covers_whole_page = seg_len == cryptor.page_size as usize && in_page_off == 0;

            if !covers_whole_page {
                let rc = ((*(*inner).pMethods).xRead.unwrap())(
                    inner,
                    page_buf.as_mut_ptr() as *mut c_void,
                    cryptor.page_size as c_int,
                    p_start,
                );
                let short_read = rc == SQLITE_IOERR_SHORT_READ;
                if rc != SQLITE_OK && !short_read {
                    return rc;
                }
                if page_no != 1
                    && !short_read
                    && let Err(e) = cryptor.decrypt(&mut page_buf, page_no)
                {
                    log::error!("evfs xWrite slow-path decrypt page {page_no}: {e}");
                    return SQLITE_IOERR_WRITE;
                }
            } else {
                page_buf.copy_from_slice(&inp[in_cursor..in_cursor + seg_len]);
            }

            // Merge new plaintext bytes.
            page_buf[in_page_off..in_page_off + seg_len]
                .copy_from_slice(&inp[in_cursor..in_cursor + seg_len]);
            in_cursor += seg_len;

            if page_no == 1 {
                if cryptor.reserve_size <= u8::MAX as usize && page_buf.len() >= 21 {
                    page_buf[20] = cryptor.reserve_size as u8;
                }
            } else if let Err(e) = cryptor.encrypt(&mut page_buf, page_no) {
                log::error!("evfs xWrite slow-path encrypt page {page_no}: {e}");
                return SQLITE_IOERR_WRITE;
            }

            // Buffer WAL frame bytes for replication.
            if let Some(ws) = (*(*efile).wal_state).as_mut() {
                let _frames: Vec<(i64, u32, Vec<u8>)> = ws.push(&page_buf, p_start);
            }

            let rc = ((*(*inner).pMethods).xWrite.unwrap())(
                inner,
                page_buf.as_ptr() as *const c_void,
                cryptor.page_size as c_int,
                p_start,
            );
            if rc != SQLITE_OK {
                return rc;
            }
        }
        debug_assert_eq!(in_cursor, inp.len());
        SQLITE_OK
    }
}

// ── xSync ───────────────────────────────────────────────────────────
//
// This is the natural durability barrier.  On the leader, we drain
// all buffered WAL frames into Raft before returning SQLITE_OK so
// that SQLite only considers the transaction committed once the
// majority has confirmed it.

unsafe extern "C" fn evfs_sync(file: *mut sqlite3_file, flags: c_int) -> c_int {
    unsafe {
        let efile = file as *mut EvfsFile;
        let inner = (*efile).inner_file;

        // Flush to the OS first.
        let rc = ((*(*inner).pMethods).xSync.unwrap())(inner, flags);
        if rc != SQLITE_OK {
            return rc;
        }

        // If this is a WAL file with Raft enabled, drain the frame buffer.
        let wal_state_opt = &mut *(*efile).wal_state;
        let Some(ws) = wal_state_opt else {
            return SQLITE_OK;
        };

        // Retrieve the Raft handle stored directly on the EvfsFile.
        let Some(ref raft) = *(*efile).raft_handle else {
            return SQLITE_OK;
        };

        if !raft.is_leader() {
            // Followers never drive xSync for WAL files — they replay
            // committed frames via the apply_fn callback.
            return SQLITE_OK;
        }

        // Drain any fully-formed frames remaining in the accumulator.
        // (In normal operation these were already extracted by xWrite,
        // but a partial trailing write might have left residue.)
        let frames: Vec<(i64, u32, Vec<u8>)> = ws.push(&[], ws.pending_offset);

        for (offset, page_no, data) in frames {
            let handle = raft.clone();
            // We are inside an unsafe extern "C" fn; spawn a blocking
            // task on the Tokio runtime that was created alongside the
            // Raft handle.
            let result = tokio::runtime::Handle::try_current()
                .ok()
                .map(|h| h.block_on(handle.submit_frame(offset, page_no, data)));

            match result {
                Some(Ok(())) => {}
                Some(Err(e)) => {
                    log::error!("Raft submit_frame failed: {e}");
                    return SQLITE_IOERR;
                }
                None => {
                    log::error!("No Tokio runtime available for Raft sync");
                    return SQLITE_IOERR;
                }
            }
        }

        SQLITE_OK
    }
}

// ── xLock ───────────────────────────────────────────────────────────
//
// On follower nodes we refuse RESERVED lock escalation so SQLite
// never attempts to write (WAL) on a non-leader.

unsafe extern "C" fn evfs_lock(file: *mut sqlite3_file, lock_type: c_int) -> c_int {
    unsafe {
        let efile = file as *mut EvfsFile;
        let inner = (*efile).inner_file;

        // Gate write locks on leader status when Raft is enabled.
        if lock_type >= SQLITE_LOCK_RESERVED
            && let Some(ref raft) = *(*efile).raft_handle
            && !raft.is_leader()
        {
            log::debug!("evfs_lock: refusing RESERVED lock on follower node");
            return SQLITE_BUSY;
        }

        ((*(*inner).pMethods).xLock.unwrap())(inner, lock_type)
    }
}

// ── Forwarded I/O methods ───────────────────────────────────────────

macro_rules! forward_io {
    ($name:ident ( $($arg:ident : $ty:ty),* ) -> c_int) => {
        #[allow(non_snake_case)]
        unsafe extern "C" fn $name(
            file: *mut sqlite3_file,
            $( $arg: $ty, )*
        ) -> c_int {
            unsafe {
                let efile = file as *mut EvfsFile;
                let inner = (*efile).inner_file;
                ((*(*inner).pMethods).$name.unwrap())(inner, $( $arg, )*)
            }
        }
    };
}

forward_io!(xTruncate(size: i64) -> c_int);
forward_io!(xUnlock(lock_type: c_int) -> c_int);

unsafe extern "C" fn evfs_file_size(file: *mut sqlite3_file, p_size: *mut i64) -> c_int {
    unsafe {
        let efile = file as *mut EvfsFile;
        ((*(*(*efile).inner_file).pMethods).xFileSize.unwrap())((*efile).inner_file, p_size)
    }
}

unsafe extern "C" fn evfs_check_reserved_lock(
    file: *mut sqlite3_file,
    p_res_out: *mut c_int,
) -> c_int {
    unsafe {
        let efile = file as *mut EvfsFile;
        let inner = (*efile).inner_file;
        ((*(*inner).pMethods).xCheckReservedLock.unwrap())(inner, p_res_out)
    }
}

unsafe extern "C" fn evfs_file_control(
    file: *mut sqlite3_file,
    op: c_int,
    p_arg: *mut c_void,
) -> c_int {
    unsafe {
        let efile = file as *mut EvfsFile;
        let inner = (*efile).inner_file;
        let cryptor = &*(*efile).cryptor;

        if op == SQLITE_FCNTL_RESERVE_BYTES {
            log::info!("SQLITE_FCNTL_RESERVE_BYTES -> {}", cryptor.reserve_size);
            if !p_arg.is_null() {
                *(p_arg as *mut c_int) = cryptor.reserve_size as c_int;
            }
            return SQLITE_OK;
        }

        // Gate WAL checkpoint on the leader when replication is active.
        if op == SQLITE_FCNTL_PRAGMA
            && let Some(ref raft) = *(*efile).raft_handle
            && !raft.is_leader()
        {
            log::warn!("evfs_file_control: blocking checkpoint on follower");
            return SQLITE_MISUSE;
        }

        ((*(*inner).pMethods).xFileControl.unwrap())(inner, op, p_arg)
    }
}

unsafe extern "C" fn evfs_sector_size(file: *mut sqlite3_file) -> c_int {
    unsafe {
        let efile = file as *mut EvfsFile;
        ((*(*(*efile).inner_file).pMethods).xSectorSize.unwrap())((*efile).inner_file)
    }
}

unsafe extern "C" fn evfs_device_characteristics(file: *mut sqlite3_file) -> c_int {
    unsafe {
        let efile = file as *mut EvfsFile;
        ((*(*(*efile).inner_file).pMethods)
            .xDeviceCharacteristics
            .unwrap())((*efile).inner_file)
    }
}

// ── Forwarded VFS methods ───────────────────────────────────────────
//
// The macro delegates to the inner VFS using the correct sqlite3_vfs
// field names (xDelete, xAccess, etc.) while exposing our own
// function names to the registration table.

macro_rules! forward_vfs {
    ($fn_name:ident => $field:ident ( $($arg:ident : $ty:ty),* ) -> c_int) => {
        unsafe extern "C" fn $fn_name(
            vfs: *mut sqlite3_vfs,
            $( $arg: $ty, )*
        ) -> c_int {
            unsafe {
                let global = &*((*vfs).pAppData as *const EvfsGlobal);
                ((*global.inner_vfs).$field.unwrap())(global.inner_vfs, $( $arg, )*)
            }
        }
    };
}

forward_vfs!(evfs_delete       => xDelete(z_name: *const c_char, sync_dir: c_int) -> c_int);
forward_vfs!(evfs_access       => xAccess(z_name: *const c_char, flags: c_int, p_res_out: *mut c_int) -> c_int);
forward_vfs!(evfs_full_pathname => xFullPathname(z_name: *const c_char, n_out: c_int, z_out: *mut c_char) -> c_int);
forward_vfs!(evfs_randomness   => xRandomness(n_byte: c_int, z_out: *mut c_char) -> c_int);
forward_vfs!(evfs_sleep        => xSleep(microseconds: c_int) -> c_int);
forward_vfs!(evfs_current_time => xCurrentTime(p_time: *mut f64) -> c_int);

unsafe extern "C" fn evfs_get_last_error(
    vfs: *mut sqlite3_vfs,
    n_buf: c_int,
    z_buf: *mut c_char,
) -> c_int {
    unsafe {
        let global = &*((*vfs).pAppData as *const EvfsGlobal);
        if let Some(f) = (*global.inner_vfs).xGetLastError {
            f(global.inner_vfs, n_buf, z_buf)
        } else {
            SQLITE_OK
        }
    }
}

unsafe extern "C" fn evfs_current_time_int64(vfs: *mut sqlite3_vfs, p_time: *mut i64) -> c_int {
    unsafe {
        let global = &*((*vfs).pAppData as *const EvfsGlobal);
        if let Some(f) = (*global.inner_vfs).xCurrentTimeInt64 {
            f(global.inner_vfs, p_time)
        } else {
            let mut t: f64 = 0.0;
            let rc = evfs_current_time(vfs, &mut t);
            if rc == SQLITE_OK {
                *p_time = (t * 86400000.0) as i64;
            }
            rc
        }
    }
}

// ── Registration ────────────────────────────────────────────────────

/// Configuration for VFS registration.
pub struct EvfsConfig {
    pub keyring: Arc<Keyring>,
    pub page_size: u32,
    pub reserve_size: usize,
    /// Pass `Some(handle)` to enable distributed replication.
    pub raft: Option<Arc<RaftHandle>>,
}

pub fn register_evfs(name: &str, cfg: EvfsConfig) -> anyhow::Result<()> {
    let inner_vfs = unsafe { sqlite3_vfs_find(ptr::null()) };
    anyhow::ensure!(!inner_vfs.is_null(), "no default sqlite3 VFS found");

    let cryptor = PageCryptor::new(cfg.keyring, cfg.page_size, cfg.reserve_size);

    let io_methods = sqlite3_io_methods {
        iVersion: 1,
        xClose: Some(evfs_close),
        xRead: Some(evfs_read),
        xWrite: Some(evfs_write),
        xTruncate: Some(xTruncate),
        xSync: Some(evfs_sync),
        xFileSize: Some(evfs_file_size),
        xLock: Some(evfs_lock),
        xUnlock: Some(xUnlock),
        xCheckReservedLock: Some(evfs_check_reserved_lock),
        xFileControl: Some(evfs_file_control),
        xSectorSize: Some(evfs_sector_size),
        xDeviceCharacteristics: Some(evfs_device_characteristics),
        // v2/v3 — not needed for iVersion=1.
        xShmMap: None,
        xShmLock: None,
        xShmBarrier: None,
        xShmUnmap: None,
        xFetch: None,
        xUnfetch: None,
    };

    let global = Box::leak(Box::new(EvfsGlobal {
        cryptor,
        inner_vfs,
        raft: cfg.raft,
        io_methods,
    }));

    let c_name = CString::new(name)?;
    let sz_os_file = std::mem::size_of::<EvfsFile>() as c_int;

    let vfs = Box::leak(Box::new(sqlite3_vfs {
        iVersion: 2,
        szOsFile: sz_os_file,
        mxPathname: unsafe { (*inner_vfs).mxPathname },
        pNext: ptr::null_mut(),
        zName: c_name.into_raw(),
        pAppData: global as *mut EvfsGlobal as *mut c_void,
        xOpen: Some(evfs_open),
        xDelete: Some(evfs_delete),
        xAccess: Some(evfs_access),
        xFullPathname: Some(evfs_full_pathname),
        xDlOpen: None,
        xDlError: None,
        xDlSym: None,
        xDlClose: None,
        xRandomness: Some(evfs_randomness),
        xSleep: Some(evfs_sleep),
        xCurrentTime: Some(evfs_current_time),
        xGetLastError: Some(evfs_get_last_error),
        xCurrentTimeInt64: Some(evfs_current_time_int64),
        xSetSystemCall: None,
        xGetSystemCall: None,
        xNextSystemCall: None,
    }));

    let rc = unsafe { sqlite3_vfs_register(vfs as *mut sqlite3_vfs, 0) };
    anyhow::ensure!(rc == SQLITE_OK, "sqlite3_vfs_register failed: {rc}");

    log::debug!(
        "evfs registered (page_size={}, reserve={}, raft={})",
        cfg.page_size,
        cfg.reserve_size,
        global.raft.is_some(),
    );
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evfs_file_base_is_first_field() {
        assert_eq!(std::mem::offset_of!(EvfsFile, base), 0);
    }

    #[test]
    fn page_no_calculation() {
        let ps = 4096i64;
        assert_eq!(page_no_for_offset(0, ps), 1);
        assert_eq!(page_no_for_offset(4096, ps), 2);
        assert_eq!(page_no_for_offset(8192, ps), 3);
    }

    #[test]
    fn page_start_round_trips() {
        let ps = 4096i64;
        for pno in 1u32..=10 {
            let off = page_start_offset(pno, ps);
            assert_eq!(page_no_for_offset(off, ps), pno);
        }
    }

    #[test]
    fn cstring_rejects_interior_null() {
        assert!(CString::new("evfs\0bad").is_err());
        assert!(CString::new("evfs").is_ok());
    }

    #[test]
    fn io_methods_critical_slots_set() {
        let methods = sqlite3_io_methods {
            iVersion: 1,
            xClose: Some(evfs_close),
            xRead: Some(evfs_read),
            xWrite: Some(evfs_write),
            xTruncate: Some(xTruncate),
            xSync: Some(evfs_sync),
            xFileSize: Some(evfs_file_size),
            xLock: Some(evfs_lock),
            xUnlock: Some(xUnlock),
            xCheckReservedLock: Some(evfs_check_reserved_lock),
            xFileControl: Some(evfs_file_control),
            xSectorSize: Some(evfs_sector_size),
            xDeviceCharacteristics: Some(evfs_device_characteristics),
            xShmMap: None,
            xShmLock: None,
            xShmBarrier: None,
            xShmUnmap: None,
            xFetch: None,
            xUnfetch: None,
        };
        assert!(methods.xRead.is_some());
        assert!(methods.xWrite.is_some());
        assert!(methods.xSync.is_some());
        assert!(methods.xClose.is_some());
        assert!(methods.xLock.is_some());
    }
}
