use std::{
    collections::HashMap,
    ffi::{CStr, CString, c_char, c_int, c_void},
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    ptr,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use anyhow::{Context, Result};
use libsqlite3_sys::{
    SQLITE_NULL,
    SQLITE_OK,
    SQLITE_ROW,
    SQLITE_TRANSIENT,
    SQLITE_UTF8,
    sqlite3,
    sqlite3_column_text,
    sqlite3_context,
    sqlite3_context_db_handle,
    sqlite3_create_function_v2,
    sqlite3_db_filename,
    sqlite3_exec,
    sqlite3_finalize,
    sqlite3_prepare_v2,
    sqlite3_result_error,
    sqlite3_result_text,
    sqlite3_step,
    sqlite3_stmt,
    sqlite3_value,
    sqlite3_value_int64,
    sqlite3_value_text,
    sqlite3_value_type,
    sqlite3_vfs_find,
};
use serde::{Deserialize, Serialize};
use tokio::runtime::{Builder, Runtime};
use tonic::transport::Endpoint;

use crate::{
    EvfsBuilder,
    Mode,
    keyring::Keyring,
    vfs::{
        EvfsConfig,
        consensus::{
            NodeId,
            handle::RaftHandle,
            replay::{self, ReplayStats, ReplayTargetConfig},
        },
        register_evfs,
    },
};

const DEFAULT_VFS_NAME: &str = "evfs";
const DEFAULT_RAFT_VFS_NAME: &str = "evfs_raft";
const SIDECAR_EXT: &str = "evfs-raft.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RaftSqlConfig {
    node_id: NodeId,
    listen_addr: String,
    peers: HashMap<NodeId, String>,
    vfs_name: String,
    raft_vfs_name: String,
    page_size: u32,
    reserve_size: usize,
    replay_target: ReplayTargetConfig,
}

struct ManagedRaft {
    config: RaftSqlConfig,
    raft: Arc<RaftHandle>,
}

struct RaftManager {
    rt: Runtime,
    nodes: HashMap<String, ManagedRaft>,
}

impl RaftManager {
    fn new() -> Result<Self> {
        let rt = Builder::new_multi_thread()
            .enable_all()
            .thread_name("sqlevfs-raft-sql")
            .build()
            .context("failed to create tokio runtime for raft sql control plane")?;
        Ok(Self {
            rt,
            nodes: HashMap::new(),
        })
    }

    fn start_node(&mut self, cfg: RaftSqlConfig) -> Result<()> {
        if let Some(existing) = self.nodes.get(&cfg.raft_vfs_name) {
            if existing.config.matches_start_request(&cfg) {
                return Ok(());
            }
            anyhow::bail!(
                "raft VFS '{}' is already active with a different configuration",
                cfg.raft_vfs_name
            );
        }

        let mode = mode_from_env()?;
        let builder = EvfsBuilder::new(mode);
        let keyring = Arc::new(Keyring::new(builder.provider));
        let listen_addr: SocketAddr = cfg
            .listen_addr
            .parse()
            .with_context(|| format!("invalid listen addr '{}'", cfg.listen_addr))?;

        let sink = replay::register_sink(cfg.replay_target.clone())
            .context("failed to create/register follower replay sink")?;
        let peers = cfg.peers.clone();
        let sink_for_apply = sink.clone();
        let sink_for_truncate = sink.clone();
        let skip_local_replay = cfg.peers.is_empty();
        let raft_result = self.rt.block_on(async {
            RaftHandle::start(
                cfg.node_id,
                peers,
                move |record| {
                    if skip_local_replay {
                        return Ok(());
                    }
                    sink_for_apply
                        .apply_record(&record)
                        .context("follower replay apply_record failed")
                },
                Some(Box::new(move |offset| {
                    sink_for_truncate
                        .truncate_at(offset)
                        .context("follower replay truncate failed")
                })),
                Some(listen_addr),
            )
            .await
        });
        let raft = match raft_result {
            Ok(r) => r,
            Err(e) => {
                replay::remove_sink(&cfg.replay_target.raft_vfs_name, &cfg.replay_target.db_path);
                return Err(e);
            }
        };

        let vfs_exists = {
            let c_name = CString::new(cfg.raft_vfs_name.as_str())?;
            unsafe { !sqlite3_vfs_find(c_name.as_ptr()).is_null() }
        };
        if !vfs_exists
            && let Err(e) = register_evfs(
                &cfg.raft_vfs_name,
                EvfsConfig {
                    keyring,
                    page_size: cfg.page_size,
                    reserve_size: cfg.reserve_size,
                    raft: Some(raft.clone()),
                },
            )
        {
            let _ = self.rt.block_on(async { raft.shutdown().await });
            replay::remove_sink(&cfg.replay_target.raft_vfs_name, &cfg.replay_target.db_path);
            return Err(e);
        }

        self.nodes
            .insert(cfg.raft_vfs_name.clone(), ManagedRaft { config: cfg, raft });

        Ok(())
    }

    fn add_node(&mut self, node_id: NodeId, rpc_addr: String, wait_secs: u64) -> Result<()> {
        let Some((_name, leader)) = self.nodes.iter().find(|(_k, v)| v.raft.is_leader()) else {
            anyhow::bail!("no local raft leader is active in this process");
        };

        let leader = leader.raft.clone();
        let mut voters = leader.voter_ids();
        voters.insert(node_id);
        let expected_voters = voters.clone();

        self.rt.block_on(async move {
            leader.add_learner(node_id, rpc_addr, true).await?;
            leader.change_membership(voters, true).await?;
            leader
                .wait_for_voter_ids(expected_voters, Duration::from_secs(wait_secs))
                .await?;
            Ok::<(), anyhow::Error>(())
        })?;

        Ok(())
    }

    fn status_json(&self) -> Result<String> {
        #[derive(Serialize)]
        struct NodeStatus {
            node_id: NodeId,
            raft_vfs_name: String,
            vfs_name: String,
            listen_addr: String,
            leader_id: Option<NodeId>,
            is_leader: bool,
            voters: Vec<NodeId>,
            peers: HashMap<NodeId, String>,
            replay: ReplayStats,
        }

        #[derive(Serialize)]
        struct StatusDoc {
            nodes: Vec<NodeStatus>,
        }

        let mut nodes = Vec::new();
        for (name, managed) in &self.nodes {
            let metrics = managed.raft.metrics();
            let mut voters: Vec<NodeId> =
                metrics.membership_config.membership().voter_ids().collect();
            voters.sort_unstable();
            nodes.push(NodeStatus {
                node_id: managed.config.node_id,
                raft_vfs_name: name.clone(),
                vfs_name: managed.config.vfs_name.clone(),
                listen_addr: managed.config.listen_addr.clone(),
                leader_id: metrics.current_leader,
                is_leader: managed.raft.is_leader(),
                voters,
                peers: managed.config.peers.clone(),
                replay: replay::get_sink(
                    &managed.config.replay_target.raft_vfs_name,
                    &managed.config.replay_target.db_path,
                )
                .map(|s| s.stats())
                .unwrap_or_default(),
            });
        }

        serde_json::to_string(&StatusDoc { nodes }).context("failed to serialize raft status")
    }

    fn stop_all(&mut self) -> Result<()> {
        let names: Vec<String> = self.nodes.keys().cloned().collect();
        for name in names {
            if let Some(managed) = self.nodes.remove(&name) {
                self.rt.block_on(async { managed.raft.shutdown().await })?;
                replay::remove_sink(
                    &managed.config.replay_target.raft_vfs_name,
                    &managed.config.replay_target.db_path,
                );
            }
        }
        Ok(())
    }
}

impl RaftSqlConfig {
    fn matches_start_request(&self, other: &Self) -> bool {
        self.node_id == other.node_id
            && self.listen_addr == other.listen_addr
            && self.peers == other.peers
            && self.vfs_name == other.vfs_name
            && self.raft_vfs_name == other.raft_vfs_name
            && self.page_size == other.page_size
            && self.reserve_size == other.reserve_size
            && self.replay_target.raft_vfs_name == other.replay_target.raft_vfs_name
            && self.replay_target.db_path == other.replay_target.db_path
            && self.replay_target.wal_path == other.replay_target.wal_path
            && self.replay_target.shm_path == other.replay_target.shm_path
            && self.replay_target.page_size == other.replay_target.page_size
    }
}

static RAFT_MANAGER: OnceLock<Mutex<RaftManager>> = OnceLock::new();

fn manager() -> Result<&'static Mutex<RaftManager>> {
    if let Some(m) = RAFT_MANAGER.get() {
        return Ok(m);
    }
    let mgr = RaftManager::new()?;
    Ok(RAFT_MANAGER.get_or_init(|| Mutex::new(mgr)))
}

fn mode_from_env() -> Result<Mode> {
    if let Ok(path) = std::env::var("EVFS_KEYFILE") {
        Ok(Mode::DeviceKey {
            keyfile: Some(PathBuf::from(path)),
            passphrase: None,
        })
    } else if let Ok(pw) = std::env::var("EVFS_PASSPHRASE") {
        Ok(Mode::DeviceKey {
            keyfile: None,
            passphrase: Some(pw),
        })
    } else if let Ok(key_id) = std::env::var("EVFS_KMS_KEY_ID") {
        Ok(Mode::TenantKey {
            key_id,
            endpoint: std::env::var("EVFS_KMS_ENDPOINT").ok(),
        })
    } else {
        anyhow::bail!(
            "no key source configured (set EVFS_KEYFILE, EVFS_PASSPHRASE, or EVFS_KMS_KEY_ID)"
        );
    }
}

fn parse_peers_json(peers_json: &str) -> Result<HashMap<NodeId, String>> {
    let peers: HashMap<NodeId, String> =
        serde_json::from_str(peers_json).context("failed to parse peers_json as object map")?;
    for (id, addr) in &peers {
        validate_rpc_addr(addr).with_context(|| format!("peer {id} has invalid rpc address"))?;
    }
    Ok(peers)
}

fn validate_rpc_addr(addr: &str) -> Result<()> {
    if addr.is_empty() {
        anyhow::bail!("rpc_addr must not be empty");
    }
    let has_http_scheme = addr.starts_with("http://") || addr.starts_with("https://");
    if !has_http_scheme {
        anyhow::bail!("rpc_addr must be a valid gRPC URI such as http://127.0.0.1:5002");
    }
    Endpoint::from_shared(addr.to_string()).map_err(|e| {
        anyhow::anyhow!("rpc_addr must be a valid gRPC URI such as http://127.0.0.1:5002: {e}")
    })?;
    Ok(())
}

fn sidecar_path_for_db(db_path: &Path) -> Option<PathBuf> {
    if db_path.as_os_str().is_empty() {
        return None;
    }
    let s = db_path.to_string_lossy();
    if s == ":memory:" || s.starts_with("file::memory:") {
        return None;
    }
    Some(db_path.with_extension(SIDECAR_EXT))
}

fn derive_replay_target(
    raft_vfs_name: &str,
    node_id: NodeId,
    db_path: &Path,
    page_size: u32,
) -> Result<ReplayTargetConfig> {
    if db_path.as_os_str().is_empty() {
        anyhow::bail!("cannot derive replay target for empty db path");
    }
    let db = db_path.to_string_lossy().to_string();
    Ok(ReplayTargetConfig {
        raft_vfs_name: raft_vfs_name.to_string(),
        io_vfs_name: String::new(),
        node_id,
        wal_path: format!("{db}-wal"),
        shm_path: format!("{db}-shm"),
        db_path: db,
        page_size,
    })
}

fn main_db_path(db: *mut sqlite3) -> Option<PathBuf> {
    unsafe {
        let p = sqlite3_db_filename(db, c"main".as_ptr());
        if p.is_null() {
            return None;
        }
        let s = CStr::from_ptr(p).to_string_lossy().to_string();
        if s.is_empty() {
            return None;
        }
        Some(PathBuf::from(s))
    }
}

fn exec_sql(db: *mut sqlite3, sql: &str) -> Result<()> {
    let c_sql = CString::new(sql)?;
    let mut err_msg: *mut c_char = ptr::null_mut();
    let rc = unsafe { sqlite3_exec(db, c_sql.as_ptr(), None, ptr::null_mut(), &mut err_msg) };
    if rc == SQLITE_OK {
        return Ok(());
    }

    let msg = if err_msg.is_null() {
        format!("sqlite error {rc}")
    } else {
        unsafe {
            let s = CStr::from_ptr(err_msg).to_string_lossy().to_string();
            libsqlite3_sys::sqlite3_free(err_msg as *mut c_void);
            s
        }
    };
    anyhow::bail!("{msg}");
}

fn read_persisted_config_from_db(db: *mut sqlite3) -> Result<Option<RaftSqlConfig>> {
    let sql = CString::new("SELECT config_json FROM evfs_raft_config WHERE id = 1")?;
    let mut stmt: *mut sqlite3_stmt = ptr::null_mut();
    let rc = unsafe { sqlite3_prepare_v2(db, sql.as_ptr(), -1, &mut stmt, ptr::null_mut()) };
    if rc != SQLITE_OK {
        return Ok(None);
    }
    if stmt.is_null() {
        return Ok(None);
    }

    let step_rc = unsafe { sqlite3_step(stmt) };
    let out = if step_rc == SQLITE_ROW {
        let text_ptr = unsafe { sqlite3_column_text(stmt, 0) };
        if text_ptr.is_null() {
            None
        } else {
            let json = unsafe { CStr::from_ptr(text_ptr as *const c_char) }
                .to_string_lossy()
                .to_string();
            Some(
                serde_json::from_str::<RaftSqlConfig>(&json)
                    .context("failed to parse persisted evfs_raft_config json")?,
            )
        }
    } else {
        None
    };
    unsafe {
        sqlite3_finalize(stmt);
    }
    Ok(out)
}

fn persist_config_in_db(db: *mut sqlite3, cfg: &RaftSqlConfig) -> Result<()> {
    exec_sql(
        db,
        "CREATE TABLE IF NOT EXISTS evfs_raft_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            config_json TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
    )?;
    let json = serde_json::to_string(cfg)?;
    let escaped = json.replace('\'', "''");
    exec_sql(
        db,
        &format!(
            "INSERT INTO evfs_raft_config(id, config_json, updated_at)
             VALUES (1, '{}', CURRENT_TIMESTAMP)
             ON CONFLICT(id) DO UPDATE
             SET config_json=excluded.config_json, updated_at=CURRENT_TIMESTAMP",
            escaped
        ),
    )
}

fn clear_config_in_db(db: *mut sqlite3) {
    let _ = exec_sql(db, "DELETE FROM evfs_raft_config WHERE id = 1");
}

fn persist_sidecar(path: &Path, cfg: &RaftSqlConfig) -> Result<()> {
    let data = serde_json::to_vec_pretty(cfg)?;
    fs::write(path, data).with_context(|| format!("failed to write sidecar '{}'", path.display()))
}

fn load_sidecar(path: &Path) -> Result<RaftSqlConfig> {
    let data =
        fs::read(path).with_context(|| format!("failed to read sidecar '{}'", path.display()))?;
    serde_json::from_slice(&data).context("failed to decode sidecar json")
}

fn remove_sidecar(path: &Path) {
    let _ = fs::remove_file(path);
}

fn start_with_config(cfg: RaftSqlConfig) -> Result<()> {
    let mgr = manager()?;
    let mut guard = mgr
        .lock()
        .map_err(|_| anyhow::anyhow!("raft manager lock poisoned"))?;
    guard.start_node(cfg)
}

fn sqlite_error(ctx: *mut sqlite3_context, prefix: &str, e: impl std::fmt::Display) {
    let msg =
        CString::new(format!("{prefix}: {e}")).unwrap_or_else(|_| CString::new(prefix).unwrap());
    unsafe {
        sqlite3_result_error(ctx, msg.as_ptr(), -1);
    }
}

fn sqlite_text(ctx: *mut sqlite3_context, value: &str) {
    let msg = CString::new(value).unwrap_or_else(|_| CString::new("").unwrap());
    unsafe {
        sqlite3_result_text(ctx, msg.as_ptr(), -1, SQLITE_TRANSIENT());
    }
}

unsafe fn get_required_text(
    argv: *mut *mut sqlite3_value,
    idx: usize,
    name: &str,
) -> Result<String> {
    let p = unsafe { sqlite3_value_text(*argv.add(idx)) };
    if p.is_null() {
        anyhow::bail!("NULL argument {name}");
    }
    Ok(unsafe { CStr::from_ptr(p as *const c_char) }
        .to_string_lossy()
        .to_string())
}

unsafe fn get_optional_text(
    argv: *mut *mut sqlite3_value,
    idx: usize,
    default: &str,
) -> Result<String> {
    if unsafe { sqlite3_value_type(*argv.add(idx)) } == SQLITE_NULL {
        return Ok(default.to_string());
    }
    let p = unsafe { sqlite3_value_text(*argv.add(idx)) };
    if p.is_null() {
        return Ok(default.to_string());
    }
    Ok(unsafe { CStr::from_ptr(p as *const c_char) }
        .to_string_lossy()
        .to_string())
}

pub(crate) fn register_raft_sql_functions(db: *mut sqlite3) {
    unsafe {
        sqlite3_create_function_v2(
            db,
            c"evfs_raft_init".as_ptr(),
            -1,
            SQLITE_UTF8,
            ptr::null_mut(),
            Some(ffi_evfs_raft_init),
            None,
            None,
            None,
        );
        sqlite3_create_function_v2(
            db,
            c"evfs_raft_add_node".as_ptr(),
            -1,
            SQLITE_UTF8,
            ptr::null_mut(),
            Some(ffi_evfs_raft_add_node),
            None,
            None,
            None,
        );
        sqlite3_create_function_v2(
            db,
            c"evfs_raft_status".as_ptr(),
            0,
            SQLITE_UTF8,
            ptr::null_mut(),
            Some(ffi_evfs_raft_status),
            None,
            None,
            None,
        );
        sqlite3_create_function_v2(
            db,
            c"evfs_raft_stop".as_ptr(),
            0,
            SQLITE_UTF8,
            ptr::null_mut(),
            Some(ffi_evfs_raft_stop),
            None,
            None,
            None,
        );
    }
}

pub(crate) fn try_autostart(db: *mut sqlite3) {
    if db.is_null() {
        return;
    }

    let db_path = match main_db_path(db) {
        Some(p) => p,
        None => return,
    };
    let sidecar = match sidecar_path_for_db(&db_path) {
        Some(p) => p,
        None => return,
    };

    let cfg = if sidecar.exists() {
        match load_sidecar(&sidecar) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("sqlevfs: failed to autostart raft from sidecar: {e}");
                None
            }
        }
    } else {
        match read_persisted_config_from_db(db) {
            Ok(Some(c)) => {
                if let Err(e) = persist_sidecar(&sidecar, &c) {
                    eprintln!("sqlevfs: failed to create raft sidecar during autostart: {e}");
                }
                Some(c)
            }
            Ok(None) => None,
            Err(e) => {
                eprintln!("sqlevfs: failed to read persisted raft config: {e}");
                None
            }
        }
    };

    if let Some(cfg) = cfg
        && let Err(e) = start_with_config(cfg)
    {
        eprintln!("sqlevfs: raft autostart failed: {e}");
    }
}

pub(crate) extern "C" fn ffi_evfs_raft_init(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if !(3..=5).contains(&argc) {
            sqlite_error(
                ctx,
                "evfs_raft_init",
                "expected 3-5 arguments: node_id, listen_addr, peers_json[, vfs_name[, raft_vfs_name]]",
            );
            return;
        }

        if sqlite3_value_type(*argv) == SQLITE_NULL {
            sqlite_error(ctx, "evfs_raft_init", "NULL node_id");
            return;
        }
        let node_id = sqlite3_value_int64(*argv) as u64;
        if node_id == 0 {
            sqlite_error(ctx, "evfs_raft_init", "node_id must be > 0");
            return;
        }

        let result = (|| -> Result<String> {
            // listen_addr is the raw socket address used by the local gRPC server bind.
            let listen_addr = get_required_text(argv, 1, "listen_addr")?;
            let _parsed: SocketAddr = listen_addr
                .parse()
                .with_context(|| format!("invalid listen_addr '{listen_addr}'"))?;
            // peers_json values are URI-form endpoints used by outbound gRPC clients.
            let peers_json = get_required_text(argv, 2, "peers_json")?;
            let peers = parse_peers_json(&peers_json)?;

            let vfs_name = if argc >= 4 {
                get_optional_text(argv, 3, DEFAULT_VFS_NAME)?
            } else {
                DEFAULT_VFS_NAME.to_string()
            };
            let raft_vfs_name = if argc >= 5 {
                get_optional_text(argv, 4, DEFAULT_RAFT_VFS_NAME)?
            } else {
                DEFAULT_RAFT_VFS_NAME.to_string()
            };

            let replay_target = {
                let db = sqlite3_context_db_handle(ctx);
                let db_path = main_db_path(db).ok_or_else(|| {
                    anyhow::anyhow!(
                        "unable to derive main database path for replay target; open a file-backed DB first"
                    )
                })?;
                derive_replay_target(&raft_vfs_name, node_id, &db_path, 4096)?
            };

            let cfg = RaftSqlConfig {
                node_id,
                listen_addr,
                peers,
                vfs_name,
                raft_vfs_name,
                page_size: 4096,
                reserve_size: 48,
                replay_target,
            };

            start_with_config(cfg.clone())?;

            let db = sqlite3_context_db_handle(ctx);
            if !db.is_null() {
                persist_config_in_db(db, &cfg)?;
                if let Some(path) = main_db_path(db).and_then(|p| sidecar_path_for_db(&p)) {
                    persist_sidecar(&path, &cfg)?;
                }
            }

            Ok(format!(
                "raft started; reopen DB with vfs={} for replication path",
                cfg.raft_vfs_name
            ))
        })();

        match result {
            Ok(msg) => sqlite_text(ctx, &msg),
            Err(e) => sqlite_error(ctx, "evfs_raft_init", e),
        }
    }
}

pub(crate) extern "C" fn ffi_evfs_raft_add_node(
    ctx: *mut sqlite3_context,
    argc: c_int,
    argv: *mut *mut sqlite3_value,
) {
    unsafe {
        if !(2..=3).contains(&argc) {
            sqlite_error(
                ctx,
                "evfs_raft_add_node",
                "expected 2-3 arguments: node_id, rpc_addr[, wait_seconds]",
            );
            return;
        }
        let node_id = sqlite3_value_int64(*argv) as u64;
        if node_id == 0 {
            sqlite_error(ctx, "evfs_raft_add_node", "node_id must be > 0");
            return;
        }
        let rpc_addr = match get_required_text(argv, 1, "rpc_addr") {
            Ok(v) => v,
            Err(e) => {
                sqlite_error(ctx, "evfs_raft_add_node", e);
                return;
            }
        };
        if let Err(e) = validate_rpc_addr(&rpc_addr) {
            sqlite_error(ctx, "evfs_raft_add_node", e);
            return;
        }
        let wait_seconds = if argc == 3 {
            sqlite3_value_int64(*argv.add(2)) as u64
        } else {
            30
        };

        let res = (|| -> Result<()> {
            let mgr = manager()?;
            let mut guard = mgr
                .lock()
                .map_err(|_| anyhow::anyhow!("raft manager lock poisoned"))?;
            guard.add_node(node_id, rpc_addr, wait_seconds)
        })();

        match res {
            Ok(()) => sqlite_text(ctx, "node added as learner and promoted to voter"),
            Err(e) => sqlite_error(ctx, "evfs_raft_add_node", e),
        }
    }
}

pub(crate) extern "C" fn ffi_evfs_raft_status(
    ctx: *mut sqlite3_context,
    _argc: c_int,
    _argv: *mut *mut sqlite3_value,
) {
    let res = (|| -> Result<String> {
        let mgr = manager()?;
        let guard = mgr
            .lock()
            .map_err(|_| anyhow::anyhow!("raft manager lock poisoned"))?;
        guard.status_json()
    })();
    match res {
        Ok(json) => sqlite_text(ctx, &json),
        Err(e) => sqlite_error(ctx, "evfs_raft_status", e),
    }
}

pub(crate) extern "C" fn ffi_evfs_raft_stop(
    ctx: *mut sqlite3_context,
    _argc: c_int,
    _argv: *mut *mut sqlite3_value,
) {
    let db = unsafe { sqlite3_context_db_handle(ctx) };
    let sidecar = main_db_path(db).and_then(|p| sidecar_path_for_db(&p));
    let res = (|| -> Result<()> {
        let mgr = manager()?;
        let mut guard = mgr
            .lock()
            .map_err(|_| anyhow::anyhow!("raft manager lock poisoned"))?;
        guard.stop_all()?;
        if !db.is_null() {
            clear_config_in_db(db);
        }
        if let Some(path) = sidecar {
            remove_sidecar(&path);
        }
        Ok(())
    })();
    match res {
        Ok(()) => sqlite_text(ctx, "raft stopped"),
        Err(e) => sqlite_error(ctx, "evfs_raft_stop", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_peers_json_accepts_object_map() {
        let peers =
            parse_peers_json(r#"{"2":"http://127.0.0.1:5002","3":"http://127.0.0.1:5003"}"#)
                .expect("peers_json should parse");
        assert_eq!(
            peers.get(&2).map(String::as_str),
            Some("http://127.0.0.1:5002")
        );
        assert_eq!(
            peers.get(&3).map(String::as_str),
            Some("http://127.0.0.1:5003")
        );
    }

    #[test]
    fn parse_peers_json_rejects_empty_address() {
        let err = parse_peers_json(r#"{"2":""}"#).expect_err("empty address should fail");
        assert!(err.to_string().contains("invalid rpc address"));
    }

    #[test]
    fn parse_peers_json_rejects_bare_socket_address() {
        let err =
            parse_peers_json(r#"{"2":"127.0.0.1:5002"}"#).expect_err("bare host:port should fail");
        assert!(err.to_string().contains("invalid rpc address"));
    }

    #[test]
    fn validate_rpc_addr_rejects_malformed_uri() {
        let err = validate_rpc_addr("http://").expect_err("malformed uri should fail");
        assert!(err.to_string().contains("valid gRPC URI"));
    }

    #[test]
    fn sidecar_path_skips_memory_db() {
        let p = sidecar_path_for_db(Path::new(":memory:"));
        assert!(p.is_none());
    }
}
