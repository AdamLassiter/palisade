use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub enum Enforce {
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct StoragePolicy {
    pub journal_mode: JournalModePolicy,
    pub temp_store: TempStorePolicy,
    pub enforce: Enforce,
}

impl Default for StoragePolicy {
    fn default() -> Self {
        Self {
            journal_mode: JournalModePolicy::Memory,
            temp_store: TempStorePolicy::Memory,
            enforce: Enforce::Warn,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum JournalModePolicy {
    /// Always force `journal_mode=MEMORY` (no on-disk rollback journal).
    Memory,
    /// Always force `journal_mode=OFF` (unsafe; no rollback journal).
    Off,
    /// Use `journal_mode=DELETE` only if the DB directory is on ramdisk;
    /// otherwise warn/error (and optionally fall back).
    DeleteOnlyIfRamdisk { fallback: JournalModeFallback },
}

#[derive(Debug, Clone, Copy)]
pub enum JournalModeFallback {
    /// If not on ramdisk, fall back to `MEMORY`.
    Memory,
    /// If not on ramdisk, fall back to `OFF`.
    Off,
    /// If not on ramdisk, do not fall back; just warn/error and leave as-is.
    None,
}

#[derive(Debug, Clone, Copy)]
pub enum TempStorePolicy {
    /// Always force `temp_store=MEMORY`.
    Memory,
    /// Allow `temp_store=FILE` only if the temp directory is on ramdisk.
    FileOnlyIfRamdisk { fallback: TempStoreFallback },
}

#[derive(Debug, Clone, Copy)]
pub enum TempStoreFallback {
    /// If not on ramdisk, fall back to `MEMORY`.
    Memory,
    /// If not on ramdisk, do not fall back; just warn/error and leave as-is.
    None,
}

#[derive(Debug, Clone)]
pub struct PolicyReport {
    pub db_dir: PathBuf,
    pub db_dir_fstype: Option<String>,
    pub temp_dir: PathBuf,
    pub temp_dir_fstype: Option<String>,
    pub applied_journal_mode: Option<String>,
    pub applied_temp_store: Option<String>,
    pub notes: Vec<String>,
}

impl PolicyReport {
    fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }
}

fn is_ramdisk_fstype(fstype: &str) -> bool {
    matches!(fstype, "tmpfs" | "ramfs")
}

fn canonical_or_original(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}

#[cfg(target_os = "linux")]
mod linux_mounts {
    use anyhow::Context;

    use super::*;

    #[derive(Debug, Clone)]
    struct MountInfo {
        mount_point: PathBuf,
        fstype: String,
    }

    fn parse_mountinfo() -> anyhow::Result<Vec<MountInfo>> {
        let s =
            std::fs::read_to_string("/proc/self/mountinfo").context("read /proc/self/mountinfo")?;

        let mut out = Vec::new();
        for line in s.lines() {
            let Some((pre, post)) = line.split_once(" - ") else {
                continue;
            };

            let pre_fields: Vec<&str> = pre.split_whitespace().collect();
            if pre_fields.len() < 5 {
                continue;
            }
            let mount_point = PathBuf::from(pre_fields[4]);

            let post_fields: Vec<&str> = post.split_whitespace().collect();
            if post_fields.is_empty() {
                continue;
            }
            let fstype = post_fields[0].to_string();

            out.push(MountInfo {
                mount_point,
                fstype,
            });
        }

        Ok(out)
    }

    pub(super) fn fstype_for_path(path: &Path) -> anyhow::Result<Option<String>> {
        let path = canonical_or_original(path);
        let mounts = parse_mountinfo()?;

        let mut best: Option<(usize, String)> = None;

        for m in mounts {
            if path.starts_with(&m.mount_point) {
                let score = m.mount_point.as_os_str().len();
                let better = best.as_ref().map(|(s, _)| score > *s).unwrap_or(true);
                if better {
                    best = Some((score, m.fstype));
                }
            }
        }

        Ok(best.map(|(_, f)| f))
    }
}

fn fstype_for_path_best_effort(path: &Path) -> anyhow::Result<Option<String>> {
    #[cfg(target_os = "linux")]
    {
        linux_mounts::fstype_for_path(path)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Ok(None)
    }
}

fn enforce_or_fallback(enforce: Enforce, msg: &str) -> anyhow::Result<()> {
    match enforce {
        Enforce::Warn => {
            log::warn!("{msg}");
            Ok(())
        }
        Enforce::Error => anyhow::bail!("{msg}"),
    }
}

#[cfg(feature = "rusqlite")]
pub fn apply_storage_policy(
    conn: &rusqlite::Connection,
    db_path: &Path,
    policy: &StoragePolicy,
) -> anyhow::Result<PolicyReport> {
    use anyhow::Context;

    let db_dir = db_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let db_dir = canonical_or_original(&db_dir);

    let temp_dir = canonical_or_original(&std::env::temp_dir());

    let db_dir_fstype = fstype_for_path_best_effort(&db_dir)
        .context("determine filesystem type for db directory")?;
    let temp_dir_fstype = fstype_for_path_best_effort(&temp_dir)
        .context("determine filesystem type for temp directory")?;

    let mut report = PolicyReport {
        db_dir,
        db_dir_fstype: db_dir_fstype.clone(),
        temp_dir,
        temp_dir_fstype: temp_dir_fstype.clone(),
        applied_journal_mode: None,
        applied_temp_store: None,
        notes: vec![],
    };

    // --- Journal mode ---
    match policy.journal_mode {
        JournalModePolicy::Memory => {
            conn.execute_batch("PRAGMA journal_mode=MEMORY;")
                .context("set PRAGMA journal_mode=MEMORY")?;
            report.applied_journal_mode = Some("MEMORY".into());
        }
        JournalModePolicy::Off => {
            conn.execute_batch("PRAGMA journal_mode=OFF;")
                .context("set PRAGMA journal_mode=OFF")?;
            report.applied_journal_mode = Some("OFF".into());
        }
        JournalModePolicy::DeleteOnlyIfRamdisk { fallback } => {
            let ok = db_dir_fstype
                .as_deref()
                .map(is_ramdisk_fstype)
                .unwrap_or(false);

            if ok {
                conn.execute_batch("PRAGMA journal_mode=DELETE;")
                    .context("set PRAGMA journal_mode=DELETE")?;
                report.applied_journal_mode = Some("DELETE".into());
            } else {
                let fstype = db_dir_fstype.clone().unwrap_or_else(|| "unknown".into());
                let msg = format!(
                    "storage policy: refusing journal_mode=DELETE because db dir is not on ramdisk (db_dir={}, fstype={fstype}); risk of plaintext journal on disk",
                    report.db_dir.display(),
                );
                enforce_or_fallback(policy.enforce, &msg)?;

                match fallback {
                    JournalModeFallback::Memory => {
                        conn.execute_batch("PRAGMA journal_mode=MEMORY;")
                            .context("fallback PRAGMA journal_mode=MEMORY")?;
                        report.applied_journal_mode = Some("MEMORY".into());
                        report.note("journal_mode=DELETE denied; fell back to MEMORY");
                    }
                    JournalModeFallback::Off => {
                        conn.execute_batch("PRAGMA journal_mode=OFF;")
                            .context("fallback PRAGMA journal_mode=OFF")?;
                        report.applied_journal_mode = Some("OFF".into());
                        report.note("journal_mode=DELETE denied; fell back to OFF");
                    }
                    JournalModeFallback::None => {
                        report.note("journal_mode=DELETE denied; no fallback applied");
                    }
                }
            }
        }
    }

    // --- Temp store ---
    match policy.temp_store {
        TempStorePolicy::Memory => {
            conn.execute_batch("PRAGMA temp_store=MEMORY;")
                .context("set PRAGMA temp_store=MEMORY")?;
            report.applied_temp_store = Some("MEMORY".into());
        }
        TempStorePolicy::FileOnlyIfRamdisk { fallback } => {
            let ok = temp_dir_fstype
                .as_deref()
                .map(is_ramdisk_fstype)
                .unwrap_or(false);

            if ok {
                conn.execute_batch("PRAGMA temp_store=FILE;")
                    .context("set PRAGMA temp_store=FILE")?;
                report.applied_temp_store = Some("FILE".into());
            } else {
                let fstype = temp_dir_fstype.clone().unwrap_or_else(|| "unknown".into());
                let msg = format!(
                    "storage policy: refusing temp_store=FILE because temp dir is not on ramdisk (temp_dir={}, fstype={fstype}); risk of plaintext temp files on disk",
                    report.temp_dir.display(),
                );
                enforce_or_fallback(policy.enforce, &msg)?;

                match fallback {
                    TempStoreFallback::Memory => {
                        conn.execute_batch("PRAGMA temp_store=MEMORY;")
                            .context("fallback PRAGMA temp_store=MEMORY")?;
                        report.applied_temp_store = Some("MEMORY".into());
                        report.note("temp_store=FILE denied; fell back to MEMORY");
                    }
                    TempStoreFallback::None => {
                        report.note("temp_store=FILE denied; no fallback applied");
                    }
                }
            }
        }
    }

    // Optional: Verify what SQLite reports back (best-effort).
    // journal_mode returns a string; temp_store returns an integer.
    if let Ok(jm) = conn.query_row("PRAGMA journal_mode;", [], |r| r.get::<_, String>(0)) {
        report.note(format!("sqlite reports journal_mode={jm}"));
    }
    if let Ok(ts) = conn.query_row("PRAGMA temp_store;", [], |r| r.get::<_, i64>(0)) {
        report.note(format!(
            "sqlite reports temp_store={ts} (0 default,1 file,2 memory)"
        ));
    }

    Ok(report)
}

#[cfg(not(feature = "rusqlite"))]
pub fn apply_storage_policy(
    _conn: &(),
    _db_path: &Path,
    _policy: &StoragePolicy,
) -> anyhow::Result<PolicyReport> {
    anyhow::bail!("apply_storage_policy requires crate feature `rusqlite`")
}
