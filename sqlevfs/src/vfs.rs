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

use crate::{io::FileContext, keyring::Keyring};

// ── Our extended file struct ────────────────────────────────────────

/// Must start with `sqlite3_file` so SQLite can cast between them.
#[repr(C)]
struct EvfsFile {
    /// Base — SQLite only sees this.
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

        // Build our per-file context.
        let ctx = Box::into_raw(Box::new(FileContext {
            keyring: global.keyring.clone(),
            page_size: global.page_size,
            reserve_size: global.reserve_size,
            page_scope_map: None,
        }));

        // Set sidecar path if we have a filename.
        if !z_name.is_null() {
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

        let rc = ((*(*inner).pMethods).xRead.unwrap())(inner, buf, i_amt, i_ofst);
        if rc != SQLITE_OK {
            return rc;
        }

        let ctx = &*(*efile).ctx;
        let page_size = ctx.page_size as i64;

        // Only decrypt page-aligned, full-page reads.
        if i_amt as u32 == ctx.page_size && i_ofst % page_size == 0 {
            let page_no = (i_ofst / page_size) as u32 + 1; // 1-indexed
            let slice = std::slice::from_raw_parts_mut(buf as *mut u8, i_amt as usize);

            // Page 1 special case: first 100 bytes are the SQLite header
            // and must remain readable in plaintext for SQLite to
            // identify the file. We encrypt bytes 100.. only.
            if page_no == 1 && is_plaintext_header(slice) {
                // Database is new / unencrypted — nothing to decrypt.
                return SQLITE_OK;
            }

            if let Err(e) = ctx.decrypt_page(slice, page_no) {
                log::error!("evfs xRead decrypt page {page_no}: {e}");
                return SQLITE_IOERR_READ;
            }
        }

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
        let page_size = ctx.page_size as i64;

        if i_amt as u32 == ctx.page_size && i_ofst % page_size == 0 {
            let page_no = (i_ofst / page_size) as u32 + 1;
            let mut page_buf =
                std::slice::from_raw_parts(buf as *const u8, i_amt as usize).to_vec();

            if let Err(e) = ctx.encrypt_page(&mut page_buf, page_no) {
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

        // Non-page-aligned writes (e.g. journal header) — pass through.
        ((*(*inner).pMethods).xWrite.unwrap())(inner, buf, i_amt, i_ofst)
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

// ── Helpers ─────────────────────────────────────────────────────────

/// Detect whether a page-1 buffer is a plaintext SQLite header.
fn is_plaintext_header(page: &[u8]) -> bool {
    page.len() >= 16 && &page[0..16] == b"SQLite format 3\0"
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
        // v2/v3 methods — not needed for iVersion=1.
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

    log::info!("evfs registered (page_size={page_size}, reserve={reserve_size})");
    Ok(())
}
