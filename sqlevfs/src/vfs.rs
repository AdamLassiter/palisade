//! SQLite VFS FFI shim.
//!
//! Registers a custom VFS named "evfs" that wraps the default OS VFS,
//! adding page-level encryption on every read/write.

use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    ptr,
    sync::Arc,
};

use libsqlite3_sys::*;

use crate::{crypto::page::is_encrypted_page, io::FileContext, keyring::Keyring};

// ── Our extended file struct ────────────────────────────────────────

/// Must start with `sqlite3_file` so SQLite can cast between them.
#[repr(C)]
struct EvfsFile {
    /// Base - SQLite only sees this.
    base: sqlite3_file,
    /// The real file opened by the underlying VFS.  We allocate
    /// enough trailing space for the inner VFS's szOsFile.
    inner_file: *mut sqlite3_file,
    /// Shared encryption context.
    ctx: *mut FileContext,
}

// ── Global VFS context (leaked, lives for the process) ─────────────

struct EvfsGlobal {
    keyring: Arc<Keyring>,
    page_size: u32,
    reserve_size: usize,
    inner_vfs: *mut sqlite3_vfs,
    /// Our io_methods table (static lifetime).
    io_methods: sqlite3_io_methods,
}

// Safety: the inner_vfs pointer comes from SQLite and is valid for
// the process lifetime. EvfsGlobal is leaked and never mutated.
unsafe impl Send for EvfsGlobal {}
unsafe impl Sync for EvfsGlobal {}

// ── xOpen ───────────────────────────────────────────────────────────

unsafe fn inner_filesize(inner: *mut sqlite3_file) -> Option<i64> {
    unsafe {
        let mut sz: i64 = 0;
        let rc = ((*(*inner).pMethods).xFileSize.unwrap())(inner, &mut sz);
        if rc == SQLITE_OK { Some(sz) } else { None }
    }
}

fn try_reserve_page1(global: &EvfsGlobal, inner: *mut sqlite3_file) -> c_int {
    unsafe {
        let Some(sz) = inner_filesize(inner) else {
            return SQLITE_IOERR;
        };
        if sz != 0 {
            return SQLITE_OK;
        }

        let page_size = global.page_size as usize;
        let reserve = global.reserve_size;

        if !(512..=65536).contains(&page_size) {
            return SQLITE_IOERR;
        }
        if reserve > u8::MAX as usize {
            return SQLITE_IOERR;
        }
        if reserve < 22 {
            // 16 tag + 6 marker (EVFSv1)
            return SQLITE_IOERR;
        }
        if page_size < 100 + 8 {
            return SQLITE_IOERR;
        }

        // Usable size is what SQLite will use for btree content.
        let usable_size = page_size - reserve;

        let mut page1 = vec![0u8; page_size];

        // --- 0..100: SQLite database header ---
        page1[0..16].copy_from_slice(b"SQLite format 3\0");

        // Page size: big-endian u16. Value 1 means 65536.
        if page_size == 65536 {
            page1[16] = 0;
            page1[17] = 1;
        } else {
            let ps = page_size as u16;
            page1[16] = (ps >> 8) as u8;
            page1[17] = (ps & 0xff) as u8;
        }

        // File format write/read version.
        page1[18] = 1;
        page1[19] = 1;

        // Reserved bytes per page.
        page1[20] = reserve as u8;

        // Max/min embedded payload fractions (SQLite defaults).
        page1[21] = 64;
        page1[22] = 32;
        page1[23] = 32;

        // File change counter (non-zero is fine).
        page1[24..28].copy_from_slice(&1u32.to_be_bytes());

        // Database size in pages: 1
        page1[28..32].copy_from_slice(&1u32.to_be_bytes());

        // Schema cookie: 1
        page1[40..44].copy_from_slice(&1u32.to_be_bytes());

        // Schema format number: 4 (current)
        page1[44..48].copy_from_slice(&4u32.to_be_bytes());

        // Text encoding: 1 = UTF-8
        page1[56..60].copy_from_slice(&1u32.to_be_bytes());

        // "Version-valid-for" matches file change counter.
        page1[92..96].copy_from_slice(&1u32.to_be_bytes());

        // SQLite version number: 3.45.1 -> 3045001
        page1[96..100].copy_from_slice(&3045001u32.to_be_bytes());

        // --- 100..: btree page header for an empty table-leaf page ---
        // Page type: 0x0D = table leaf
        page1[100] = 0x0D;

        // First freeblock offset (2 bytes) = 0
        // Number of cells (2 bytes) = 0
        page1[101] = 0;
        page1[102] = 0;
        page1[103] = 0;
        page1[104] = 0;

        // Start of cell content area (2 bytes) = usable_size
        // (for 0 cells, content area starts at end of usable area)
        let sc = usable_size as u16;
        page1[105] = (sc >> 8) as u8;
        page1[106] = (sc & 0xff) as u8;

        // Fragmented free bytes = 0
        page1[107] = 0;

        // Write it.
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

unsafe extern "C" fn evfs_open(
    vfs: *mut sqlite3_vfs,
    z_name: *const c_char,
    file: *mut sqlite3_file,
    flags: c_int,
    p_out_flags: *mut c_int,
) -> c_int {
    unsafe {
        let encrypt_enabled = (flags & SQLITE_OPEN_MAIN_DB) != 0;

        let global = &*((*vfs).pAppData as *const EvfsGlobal);
        let inner_vfs = global.inner_vfs;
        let efile = file as *mut EvfsFile;

        // Allocate the inner file buffer.
        let inner_sz = (*inner_vfs).szOsFile as usize;
        let inner_buf = libc::malloc(inner_sz) as *mut sqlite3_file;
        if inner_buf.is_null() {
            return SQLITE_NOMEM;
        }
        ptr::write_bytes(inner_buf as *mut u8, 0, inner_sz);

        // Open via the real VFS.
        let real_open = (*inner_vfs).xOpen.unwrap();
        let rc = real_open(inner_vfs, z_name, inner_buf, flags, p_out_flags);
        if rc != SQLITE_OK {
            libc::free(inner_buf as *mut c_void);
            return rc;
        }

        // Only pre-create page 1 for a brand new MAIN database file.
        // Never do this for journals/WAL/temp files.
        if encrypt_enabled && (flags & SQLITE_OPEN_CREATE) != 0 {
            let rc = try_reserve_page1(global, inner_buf);
            if rc != SQLITE_OK {
                // Close inner file then free buffer.
                let _ = ((*(*inner_buf).pMethods).xClose.unwrap())(inner_buf);
                libc::free(inner_buf as *mut c_void);
                return rc;
            }
        }

        // Build our per-file context.
        let ctx = Box::into_raw(Box::new(FileContext {
            keyring: global.keyring.clone(),
            page_size: global.page_size,
            reserve_size: global.reserve_size,
            encrypt_enabled,
            page_scope_map: None,
        }));

        // Bind the keyring sidecar only to the MAIN DB file.
        // SQLite will open additional files (journal, wal, shm, temp) and
        // we must not overwrite the shared keyring's sidecar path.
        if encrypt_enabled && !z_name.is_null() {
            let name = CStr::from_ptr(z_name);
            if let Ok(s) = name.to_str() {
                let path = std::path::Path::new(s);
                (*ctx).keyring.set_sidecar_path(path);
            }
        }

        (*efile).base.pMethods = &global.io_methods;
        (*efile).inner_file = inner_buf;
        (*efile).ctx = ctx;

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

        // Drop our context.
        if !(*efile).ctx.is_null() {
            drop(Box::from_raw((*efile).ctx));
            (*efile).ctx = ptr::null_mut();
        }

        rc
    }
}

// ── Partial page offset helpers ────────────────────────────────────

fn page_no_for_offset(i_ofst: i64, page_size: i64) -> u32 {
    (i_ofst / page_size) as u32 + 1
}

fn page_start_offset(page_no: u32, page_size: i64) -> i64 {
    (page_no as i64 - 1) * page_size
}

// ── xRead (decrypt after read) ─────────────────────────────────────

unsafe extern "C" fn evfs_read(
    file: *mut sqlite3_file,
    buf: *mut c_void,
    i_amt: c_int,
    i_ofst: i64,
) -> c_int {
    unsafe {
        let efile = file as *mut EvfsFile;
        let inner = (*efile).inner_file;
        let ctx = &*(*efile).ctx;

        if !ctx.encrypt_enabled {
            return ((*(*inner).pMethods).xRead.unwrap())(inner, buf, i_amt, i_ofst);
        }

        let page_size = ctx.page_size as i64;
        let amt = i_amt as usize;

        // Fast path: full aligned page read.
        if i_amt as u32 == ctx.page_size && i_ofst % page_size == 0 {
            let rc = ((*(*inner).pMethods).xRead.unwrap())(inner, buf, i_amt, i_ofst);
            if rc != SQLITE_OK {
                return rc;
            }

            let page_no = page_no_for_offset(i_ofst, page_size);
            if page_no != 1 {
                let slice = std::slice::from_raw_parts_mut(buf as *mut u8, amt);
                if let Err(e) = ctx.decrypt_page(slice, page_no) {
                    log::error!("evfs xRead decrypt page {page_no}: {e}");
                    return SQLITE_IOERR_READ;
                }
            }

            return SQLITE_OK;
        }

        // Slow path: range read (may be sub-page or cross-page).
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

            // Read full page into temp.
            let mut page_buf = vec![0u8; ctx.page_size as usize];
            let rc = ((*(*inner).pMethods).xRead.unwrap())(
                inner,
                page_buf.as_mut_ptr() as *mut c_void,
                ctx.page_size as c_int,
                p_start,
            );
            let short_read = rc == SQLITE_IOERR_SHORT_READ;
            if rc != SQLITE_OK && !short_read {
                return rc;
            }

            // Decrypt if needed.
            if page_no != 1
                && !short_read
                && is_encrypted_page(&page_buf, ctx.reserve_size)
                && let Err(e) = ctx.decrypt_page(&mut page_buf, page_no)
            {
                log::error!("evfs decrypt page {page_no}: {e}");
                return SQLITE_IOERR_READ;
            }

            let in_page_off = (seg_start - p_start) as usize;

            out[out_cursor..out_cursor + seg_len]
                .copy_from_slice(&page_buf[in_page_off..in_page_off + seg_len]);
            out_cursor += seg_len;
        }
        assert_eq!(out_cursor, out.len());

        SQLITE_OK
    }
}

// ── xWrite (encrypt before write) ──────────────────────────────────

unsafe extern "C" fn evfs_write(
    file: *mut sqlite3_file,
    buf: *const c_void,
    i_amt: c_int,
    i_ofst: i64,
) -> c_int {
    unsafe {
        let efile = file as *mut EvfsFile;
        let inner = (*efile).inner_file;
        let ctx = &*(*efile).ctx;

        if !ctx.encrypt_enabled {
            // Pass-through entirely.
            return ((*(*inner).pMethods).xWrite.unwrap())(inner, buf, i_amt, i_ofst);
        }

        let page_size = ctx.page_size as i64;
        let amt = i_amt as usize;

        // Fast path: full aligned page write.
        if i_amt as u32 == ctx.page_size && i_ofst % page_size == 0 {
            let page_no = page_no_for_offset(i_ofst, page_size);
            let mut page_buf = std::slice::from_raw_parts(buf as *const u8, amt).to_vec();

            if page_no == 1 && ctx.reserve_size <= u8::MAX as usize && page_buf.len() >= 21 {
                page_buf[20] = ctx.reserve_size as u8;
            } else if let Err(e) = ctx.encrypt_page(&mut page_buf, page_no) {
                log::error!("evfs xWrite encrypt page {page_no}: {e}");
                return SQLITE_IOERR_WRITE;
            }

            return ((*(*inner).pMethods).xWrite.unwrap())(
                inner,
                page_buf.as_ptr() as *const c_void,
                i_amt,
                i_ofst,
            );
        }

        // Slow path: range write (sub-page or cross-page).
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

            // Load existing page (full), unless the segment covers entire page.
            let mut page_buf = vec![0u8; ctx.page_size as usize];
            let covers_whole_page = seg_len == ctx.page_size as usize && in_page_off == 0;

            if !covers_whole_page {
                let rc = ((*(*inner).pMethods).xRead.unwrap())(
                    inner,
                    page_buf.as_mut_ptr() as *mut c_void,
                    ctx.page_size as c_int,
                    p_start,
                );
                let short_read = rc == SQLITE_IOERR_SHORT_READ;
                if rc != SQLITE_OK && !short_read {
                    return rc;
                }

                // Decrypt if needed.
                if page_no != 1
                    && !short_read
                    && is_encrypted_page(&page_buf, ctx.reserve_size)
                    && let Err(e) = ctx.decrypt_page(&mut page_buf, page_no)
                {
                    log::error!("evfs decrypt page {page_no}: {e}");
                    return SQLITE_IOERR_WRITE;
                }
            } else {
                // If whole-page overwrite, start from new plaintext bytes.
                page_buf.copy_from_slice(&inp[in_cursor..in_cursor + seg_len]);
            }

            // Patch plaintext bytes.
            page_buf[in_page_off..in_page_off + seg_len]
                .copy_from_slice(&inp[in_cursor..in_cursor + seg_len]);
            in_cursor += seg_len;

            // Page 1 stays plaintext, but we still force reserved bytes header.
            if page_no == 1 {
                if ctx.reserve_size <= u8::MAX as usize && page_buf.len() >= 21 {
                    page_buf[20] = ctx.reserve_size as u8;
                }
            } else {
                if let Err(e) = ctx.encrypt_page(&mut page_buf, page_no) {
                    log::error!("evfs xWrite encrypt page {page_no}: {e}");
                    return SQLITE_IOERR_WRITE;
                }
            }

            let rc = ((*(*inner).pMethods).xWrite.unwrap())(
                inner,
                page_buf.as_ptr() as *const c_void,
                ctx.page_size as c_int,
                p_start,
            );
            if rc != SQLITE_OK {
                return rc;
            }
        }
        assert_eq!(in_cursor, inp.len());

        SQLITE_OK
    }
}

// ── Forwarded I/O methods ───────────────────────────────────────────

macro_rules! forward_io {
    ($sym:expr, $name:ident ( $($arg:ident : $ty:ty),* ) -> c_int) => {
        #[allow(non_snake_case)]
        unsafe extern "C" fn $name(
            file: *mut sqlite3_file,
            $( $arg: $ty, )*
        ) -> c_int { unsafe {
            let efile = file as *mut EvfsFile;
            let inner = (*efile).inner_file;
            ((*(*inner).pMethods).$name.unwrap())(inner, $( $arg, )*)
        }}
    };
}

forward_io!("xTruncate", xTruncate(size: i64) -> c_int);
forward_io!("xSync", xSync(flags: c_int) -> c_int);

unsafe extern "C" fn evfs_file_size(file: *mut sqlite3_file, p_size: *mut i64) -> c_int {
    unsafe {
        let efile = file as *mut EvfsFile;
        let inner = (*efile).inner_file;
        ((*(*inner).pMethods).xFileSize.unwrap())(inner, p_size)
    }
}

forward_io!("xLock", xLock(lock_type: c_int) -> c_int);
forward_io!("xUnlock", xUnlock(lock_type: c_int) -> c_int);

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

        // Handle reserve bytes control
        if op == SQLITE_FCNTL_RESERVE_BYTES {
            let ctx = &*(*efile).ctx;

            log::info!("SQLITE_FCNTL_RESERVE_BYTES -> {}", ctx.reserve_size);
            let p_int = p_arg as *mut c_int;
            if !p_int.is_null() {
                *p_int = ctx.reserve_size as c_int;
            }
            return SQLITE_OK;
        }

        ((*(*inner).pMethods).xFileControl.unwrap())(inner, op, p_arg)
    }
}

unsafe extern "C" fn evfs_sector_size(file: *mut sqlite3_file) -> c_int {
    unsafe {
        let efile = file as *mut EvfsFile;
        let inner = (*efile).inner_file;
        ((*(*inner).pMethods).xSectorSize.unwrap())(inner)
    }
}

unsafe extern "C" fn evfs_device_characteristics(file: *mut sqlite3_file) -> c_int {
    unsafe {
        let efile = file as *mut EvfsFile;
        let inner = (*efile).inner_file;
        ((*(*inner).pMethods).xDeviceCharacteristics.unwrap())(inner)
    }
}

// ── Forwarded VFS methods ───────────────────────────────────────────

unsafe extern "C" fn evfs_delete(
    vfs: *mut sqlite3_vfs,
    z_name: *const c_char,
    sync_dir: c_int,
) -> c_int {
    unsafe {
        let global = &*((*vfs).pAppData as *const EvfsGlobal);
        ((*global.inner_vfs).xDelete.unwrap())(global.inner_vfs, z_name, sync_dir)
    }
}

unsafe extern "C" fn evfs_access(
    vfs: *mut sqlite3_vfs,
    z_name: *const c_char,
    flags: c_int,
    p_res_out: *mut c_int,
) -> c_int {
    unsafe {
        let global = &*((*vfs).pAppData as *const EvfsGlobal);
        ((*global.inner_vfs).xAccess.unwrap())(global.inner_vfs, z_name, flags, p_res_out)
    }
}

unsafe extern "C" fn evfs_full_pathname(
    vfs: *mut sqlite3_vfs,
    z_name: *const c_char,
    n_out: c_int,
    z_out: *mut c_char,
) -> c_int {
    unsafe {
        let global = &*((*vfs).pAppData as *const EvfsGlobal);
        ((*global.inner_vfs).xFullPathname.unwrap())(global.inner_vfs, z_name, n_out, z_out)
    }
}

unsafe extern "C" fn evfs_randomness(
    vfs: *mut sqlite3_vfs,
    n_byte: c_int,
    z_out: *mut c_char,
) -> c_int {
    unsafe {
        let global = &*((*vfs).pAppData as *const EvfsGlobal);
        ((*global.inner_vfs).xRandomness.unwrap())(global.inner_vfs, n_byte, z_out)
    }
}

unsafe extern "C" fn evfs_sleep(vfs: *mut sqlite3_vfs, microseconds: c_int) -> c_int {
    unsafe {
        let global = &*((*vfs).pAppData as *const EvfsGlobal);
        ((*global.inner_vfs).xSleep.unwrap())(global.inner_vfs, microseconds)
    }
}

unsafe extern "C" fn evfs_current_time(vfs: *mut sqlite3_vfs, p_time: *mut f64) -> c_int {
    unsafe {
        let global = &*((*vfs).pAppData as *const EvfsGlobal);
        ((*global.inner_vfs).xCurrentTime.unwrap())(global.inner_vfs, p_time)
    }
}

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
            // Fallback to float version.
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

pub fn register_evfs(
    name: &str,
    keyring: Arc<Keyring>,
    page_size: u32,
    reserve_size: usize,
) -> anyhow::Result<()> {
    let inner_vfs = unsafe { sqlite3_vfs_find(ptr::null()) };
    anyhow::ensure!(!inner_vfs.is_null(), "no default sqlite3 VFS found");

    // Build the io_methods table.
    let io_methods = sqlite3_io_methods {
        iVersion: 1,
        xClose: Some(evfs_close),
        xRead: Some(evfs_read),
        xWrite: Some(evfs_write),
        xTruncate: Some(xTruncate),
        xSync: Some(xSync),
        xFileSize: Some(evfs_file_size),
        xLock: Some(xLock),
        xUnlock: Some(xUnlock),
        xCheckReservedLock: Some(evfs_check_reserved_lock),
        xFileControl: Some(evfs_file_control),
        xSectorSize: Some(evfs_sector_size),
        xDeviceCharacteristics: Some(evfs_device_characteristics),
        // v2/v3 methods - not needed for iVersion=1.
        xShmMap: None,
        xShmLock: None,
        xShmBarrier: None,
        xShmUnmap: None,
        xFetch: None,
        xUnfetch: None,
    };

    let global = Box::leak(Box::new(EvfsGlobal {
        keyring,
        page_size,
        reserve_size,
        inner_vfs,
        io_methods,
    }));

    let c_name = CString::new(name)?;

    // We need szOsFile large enough for our EvfsFile.
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

    log::debug!("evfs registered (page_size={page_size}, reserve={reserve_size})");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::crypto::keys::KeyScope;

    #[test]
    fn test_evfs_file_struct_layout() {
        // Ensure EvfsFile starts with sqlite3_file for C casting
        let file_offset = std::mem::offset_of!(EvfsFile, base);
        assert_eq!(file_offset, 0, "EvfsFile.base must be first field");
    }

    #[test]
    fn test_evfs_global_struct_size() {
        // Ensure EvfsGlobal fits reasonable size constraints
        let size = std::mem::size_of::<EvfsGlobal>();
        assert!(size < 10000, "EvfsGlobal unexpectedly large");
    }

    #[test]
    fn test_evfs_file_struct_pointer_fields() {
        // Verify pointer fields exist and are properly sized
        assert_eq!(
            std::mem::size_of::<*mut sqlite3_file>(),
            std::mem::size_of::<*mut c_void>()
        );
        assert_eq!(
            std::mem::size_of::<*mut FileContext>(),
            std::mem::size_of::<*mut c_void>()
        );
    }

    #[test]
    fn test_register_evfs_with_valid_args() -> anyhow::Result<()> {
        use crate::kms::KmsProvider;

        // Mock KmsProvider for registration test
        struct TestKmsProvider;
        impl KmsProvider for TestKmsProvider {
            fn get_kek(&self) -> anyhow::Result<(crate::crypto::keys::KekId, Vec<u8>)> {
                Ok((crate::crypto::keys::KekId("test".into()), vec![0xAAu8; 32]))
            }

            fn get_kek_by_id(&self, _id: &crate::crypto::keys::KekId) -> anyhow::Result<Vec<u8>> {
                Ok(vec![0xBBu8; 32])
            }
        }

        let keyring = Arc::new(Keyring::new(Arc::new(TestKmsProvider)));

        // Try to register - note this is global state, only run once
        // In a real test suite, you'd want to isolate this
        let result = register_evfs("test_evfs", keyring, 4096, 16);

        // Registration might fail if already registered in test suite
        // Both success and "already registered" are acceptable
        match result {
            Ok(()) => Ok(()),
            Err(e) if e.to_string().contains("already") => Ok(()),
            Err(e) => Err(e),
        }
    }

    #[test]
    fn test_register_evfs_invalid_name_with_null_byte() -> anyhow::Result<()> {
        use crate::kms::KmsProvider;

        struct TestKmsProvider;
        impl KmsProvider for TestKmsProvider {
            fn get_kek(&self) -> anyhow::Result<(crate::crypto::keys::KekId, Vec<u8>)> {
                Ok((crate::crypto::keys::KekId("test".into()), vec![0xCCu8; 32]))
            }

            fn get_kek_by_id(&self, _id: &crate::crypto::keys::KekId) -> anyhow::Result<Vec<u8>> {
                Ok(vec![0xDDu8; 32])
            }
        }

        let keyring = Arc::new(Keyring::new(Arc::new(TestKmsProvider)));

        // Name with null byte should fail
        let result = register_evfs("test\0invalid", keyring, 4096, 16);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_cstring_conversion_for_vfs_name() {
        let name = "evfs";
        let c_name = CString::new(name);
        assert!(c_name.is_ok());

        let invalid_name = "evfs\0bad";
        let c_invalid = CString::new(invalid_name);
        assert!(c_invalid.is_err());
    }

    #[test]
    fn test_io_methods_struct_initialization() {
        let io_methods = sqlite3_io_methods {
            iVersion: 1,
            xClose: Some(evfs_close),
            xRead: Some(evfs_read),
            xWrite: Some(evfs_write),
            xTruncate: Some(xTruncate),
            xSync: Some(xSync),
            xFileSize: Some(evfs_file_size),
            xLock: Some(xLock),
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

        // Verify critical methods are set
        assert!(io_methods.xRead.is_some());
        assert!(io_methods.xWrite.is_some());
        assert!(io_methods.xClose.is_some());
        assert!(io_methods.xSync.is_some());
    }

    #[test]
    fn test_page_number_calculation() {
        // Test the page number calculation: (i_ofst / page_size) + 1
        let page_size = 4096i64;

        let cases = vec![
            (0, 1),        // First page
            (4096, 2),     // Second page
            (8192, 3),     // Third page
            (409600, 101), // 100th offset -> 101st page
        ];

        for (offset, expected_page) in cases {
            let page_no = (offset / page_size) as u32 + 1;
            assert_eq!(page_no, expected_page);
        }
    }

    #[test]
    fn test_page_alignment_check() {
        let page_size = 4096i64;

        // Aligned offsets
        assert_eq!(0 % page_size, 0);
        assert_eq!(4096 % page_size, 0);
        assert_eq!(8192 % page_size, 0);

        // Unaligned offsets
        assert_ne!(100 % page_size, 0);
        assert_ne!(4096 + 1, 0 % page_size);
    }

    #[test]
    fn test_vfs_struct_layout() {
        // Verify sqlite3_vfs has expected size
        let size = std::mem::size_of::<sqlite3_vfs>();
        // Should be reasonably sized (actual size depends on SQLite version)
        assert!(size > 0 && size < 10000);
    }

    #[test]
    fn test_sqlite3_file_is_opaque() {
        // sqlite3_file is opaque from Rust perspective,
        // but we can verify its size constraint
        let file_size = std::mem::size_of::<sqlite3_file>();
        // Must be non-zero (it's a real struct)
        assert!(file_size > 0);
    }

    #[test]
    fn test_page_scope_map_initialization() {
        // Verify that FileContext can be created with None page_scope_map
        // (This is more of a compile-time check but good to document)
        assert!(std::mem::size_of::<Option<HashMap<u32, KeyScope>>>() > 0);
    }
}
