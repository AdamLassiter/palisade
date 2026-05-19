use std::{
    fs,
    path::Path,
    sync::{Mutex, OnceLock},
    thread,
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, params};

use crate::{
    types::{
        AppResult,
        Config,
        Engine,
        Labels,
        LibPaths,
        NodeInfo,
        ReadSurface,
        Role,
        Runtime,
        TENANTS,
    },
    util::{persist, table_name, tenant_name, transient},
};

static SQLSEC_LOAD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) fn create_schema(
    cfg: &Config,
    runtime: &Runtime,
    conn: &Connection,
) -> AppResult<Labels> {
    if cfg.engine.uses_security() {
        transient("loading sqlsec extension");
        load_sqlsec_on_conn(conn, &runtime.libs.sqlsec)?;
        transient("setting admin sqlsec context");
        set_admin_context(conn, runtime.use_shim_syntax)?;
    }

    transient("creating physical tables");
    let physical_accounts = table_name(cfg.engine, "accounts", ReadSurface::Physical);
    let physical_orders = table_name(cfg.engine, "orders", ReadSurface::Physical);
    let physical_transfers = table_name(cfg.engine, "transfers", ReadSurface::Physical);
    let physical_audit = table_name(cfg.engine, "audit_log", ReadSurface::Physical);

    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {physical_accounts} (
            id INTEGER PRIMARY KEY,
            tenant TEXT NOT NULL,
            balance INTEGER NOT NULL,
            status TEXT NOT NULL,
            secret_note TEXT NOT NULL,
            row_label_id INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_{physical_accounts}_tenant ON {physical_accounts}(tenant);

        CREATE TABLE IF NOT EXISTS {physical_orders} (
            id INTEGER PRIMARY KEY,
            tenant TEXT NOT NULL,
            account_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            status TEXT NOT NULL,
            row_label_id INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_{physical_orders}_tenant ON {physical_orders}(tenant);

        CREATE TABLE IF NOT EXISTS {physical_transfers} (
            id INTEGER PRIMARY KEY,
            tenant TEXT NOT NULL,
            from_account_id INTEGER NOT NULL,
            to_account_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            row_label_id INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_{physical_transfers}_tenant_ts ON {physical_transfers}(tenant, ts);

        CREATE TABLE IF NOT EXISTS {physical_audit} (
            id INTEGER PRIMARY KEY,
            tenant TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            action TEXT NOT NULL,
            ref_id INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            detail TEXT NOT NULL,
            row_label_id INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_{physical_audit}_tenant_ts ON {physical_audit}(tenant, ts);"
    ))?;

    if !cfg.engine.uses_security() {
        persist("security disabled for sqlite engine");
        return Ok(Labels {
            tenant_labels: (0..TENANTS).map(|i| i as i64 + 1).collect(),
        });
    }

    transient("bootstrapping secured metadata");
    bootstrap_security_views(conn, runtime.use_shim_syntax)
}

pub(crate) fn configure_setup_conn(conn: &Connection) -> AppResult<()> {
    conn.busy_timeout(Duration::from_millis(750))?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA temp_store = MEMORY;
         PRAGMA cache_size = -8192;
         PRAGMA page_size = 4096;",
    )?;
    Ok(())
}

pub(crate) fn open_configured_worker_conn(
    cfg: &Config,
    leader_db_path: &Path,
    raft_vfs: Option<&str>,
    libs: &LibPaths,
) -> AppResult<Connection> {
    const MAX_ATTEMPTS: usize = 8;
    let mut last_err = None;

    for attempt in 1..=MAX_ATTEMPTS {
        match (|| -> AppResult<Connection> {
            let conn = open_worker_conn(cfg, leader_db_path, raft_vfs)?;
            conn.busy_timeout(Duration::from_secs(5))?;

            if cfg.engine.uses_security() {
                let _guard = SQLSEC_LOAD_LOCK
                    .get_or_init(|| Mutex::new(()))
                    .lock()
                    .map_err(|_| "sqlsec load lock poisoned")?;
                load_sqlsec_on_conn(&conn, &libs.sqlsec)?;
            }

            Ok(conn)
        })() {
            Ok(conn) => return Ok(conn),
            Err(err) if is_lock_or_busy(&err.to_string()) && attempt < MAX_ATTEMPTS => {
                last_err = Some(err);
                thread::sleep(Duration::from_millis(25 * attempt as u64));
            }
            Err(err) => {
                return Err(format!(
                    "failed to open/configure worker connection after attempt {attempt}/{MAX_ATTEMPTS}: {err}"
                )
                .into());
            }
        }
    }

    Err(format!(
        "failed to open/configure worker connection after {MAX_ATTEMPTS} attempts: {}",
        last_err
            .map(|err| err.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    )
    .into())
}

pub(crate) fn is_lock_or_busy(msg: &str) -> bool {
    msg.contains("locked") || msg.contains("busy")
}

pub(crate) fn load_sqlsec_on_conn(conn: &Connection, sqlsec_path: &Path) -> AppResult<()> {
    unsafe {
        conn.load_extension_enable()?;
        let load_result = conn.load_extension(sqlsec_path, None::<&str>);
        let disable_result = conn.load_extension_disable();
        load_result?;
        disable_result?;
    }
    Ok(())
}

pub(crate) fn load_sqlevfs_on_conn(conn: &Connection, sqlevfs_path: &Path) -> AppResult<()> {
    unsafe {
        conn.load_extension_enable()?;
        conn.load_extension(sqlevfs_path, None::<&str>)?;
        conn.load_extension_disable()?;
    }
    Ok(())
}

pub(crate) fn open_writer_conn(cfg: &Config, runtime: &Runtime) -> AppResult<Connection> {
    match cfg.engine {
        Engine::Sqlite => Ok(Connection::open(&runtime.leader_db_path)?),
        Engine::Secure => Ok(Connection::open_with_flags_and_vfs(
            &runtime.leader_db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            "evfs",
        )?),
        Engine::Cluster => Ok(Connection::open_with_flags_and_vfs(
            &runtime.leader_db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            runtime
                .leader_raft_vfs_name
                .as_deref()
                .ok_or("missing leader raft vfs for cluster writer")?,
        )?),
        Engine::All => Err("cannot open writer connection for engine=all".into()),
    }
}

pub(crate) fn open_worker_conn(
    cfg: &Config,
    leader_db_path: &Path,
    raft_vfs: Option<&str>,
) -> AppResult<Connection> {
    Ok(match cfg.engine {
        Engine::Sqlite => Connection::open(leader_db_path)?,
        Engine::Secure => Connection::open_with_flags_and_vfs(
            leader_db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            "evfs",
        )?,
        Engine::Cluster => Connection::open_with_flags_and_vfs(
            leader_db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            raft_vfs.ok_or("missing raft vfs for cluster writer")?,
        )?,
        Engine::All => return Err("cannot open worker connection for engine=all".into()),
    })
}

pub(crate) fn open_validation_conn(
    cfg: &Config,
    runtime: &Runtime,
    read_only: bool,
) -> AppResult<Connection> {
    let flags = if matches!(cfg.engine, Engine::Cluster) {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    } else if read_only {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    };
    let conn = match cfg.engine {
        Engine::Sqlite => Connection::open_with_flags(&runtime.leader_db_path, flags)?,
        Engine::Secure => {
            Connection::open_with_flags_and_vfs(&runtime.leader_db_path, flags, "evfs")?
        }
        Engine::Cluster => {
            Connection::open_with_flags_and_vfs(&runtime.leader_db_path, flags, "evfs")?
        }
        Engine::All => return Err("cannot open validation connection for engine=all".into()),
    };
    conn.busy_timeout(Duration::from_millis(750))?;
    Ok(conn)
}

pub(crate) fn open_cluster_replica_conn(follower: &NodeInfo) -> AppResult<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;
    let conn = Connection::open_with_flags_and_vfs(&follower.db_path, flags, "evfs")?;
    conn.busy_timeout(Duration::from_millis(750))?;
    Ok(conn)
}

pub(crate) fn open_cluster_replica_raft_conn(follower: &NodeInfo) -> AppResult<Connection> {
    let conn = Connection::open_with_flags_and_vfs(
        &follower.db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        follower.raft_vfs_name.as_str(),
    )?;
    conn.busy_timeout(Duration::from_millis(750))?;
    Ok(conn)
}

pub(crate) fn open_evfs_control_conn(db_path: &Path, libs: &LibPaths) -> AppResult<Connection> {
    transient(format!("opening EVFS control {}", db_path.display()));
    let conn = Connection::open_with_flags_and_vfs(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        "evfs",
    )?;
    load_sqlevfs_on_conn(&conn, &libs.sqlevfs)?;
    Ok(conn)
}

pub(crate) fn checkpoint_best_effort(cfg: &Config, runtime: &Runtime) {
    let Ok(conn) = open_writer_conn(cfg, runtime) else {
        return;
    };
    let _ = conn.busy_timeout(Duration::from_millis(750));
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
}

fn register_secure_table(
    conn: &Connection,
    use_shim: bool,
    logical: &str,
    physical: &str,
    table_label: Option<&str>,
) -> AppResult<()> {
    if use_shim {
        let sql = if let Some(label) = table_label {
            format!(
                "REGISTER SECURE TABLE {logical} ON {physical} WITH ROW LABEL row_label_id TABLE LABEL '{label}';"
            )
        } else {
            format!("REGISTER SECURE TABLE {logical} ON {physical} WITH ROW LABEL row_label_id;")
        };
        conn.execute_batch(&sql)?;
    } else {
        let table_label_id = if let Some(label) = table_label {
            Some(conn.query_row("SELECT sec_define_label(?1)", [label], |r| {
                r.get::<_, i64>(0)
            })?)
        } else {
            None
        };
        conn.query_row::<i64, _, _>(
            "SELECT sec_register_table(?1, ?2, 'row_label_id', ?3, NULL)",
            params![logical, physical, table_label_id],
            |r| r.get(0),
        )?;
    }
    Ok(())
}

fn bootstrap_security_views(conn: &Connection, use_shim: bool) -> AppResult<Labels> {
    transient("applying admin context for secured views");
    set_admin_context(conn, use_shim)?;

    let mut tenant_labels = Vec::with_capacity(TENANTS);
    for tenant_idx in 0..TENANTS {
        let expr = format!("(tenant={}|role=admin|role=ops)", tenant_name(tenant_idx));
        let label_id: i64 = conn.query_row("SELECT sec_define_label(?1)", [expr], |r| r.get(0))?;
        tenant_labels.push(label_id);
    }
    persist(format!("defined {} tenant labels", tenant_labels.len()));
    let _ops_admin: i64 = conn.query_row(
        "SELECT sec_define_label('(role=admin|role=ops)')",
        [],
        |r| r.get(0),
    )?;

    transient("registering secured tables");
    maybe_register_secure_table(conn, use_shim, "accounts", "__sec_accounts", None)?;
    maybe_register_secure_table(conn, use_shim, "orders", "__sec_orders", None)?;
    maybe_register_secure_table(conn, use_shim, "transfers", "__sec_transfers", None)?;
    transient("applying column security");
    set_column_security(conn, use_shim, "accounts", "secret_note", "role=admin")?;
    transient("refreshing secured views");
    refresh_views(conn, use_shim)?;

    Ok(Labels { tenant_labels })
}

fn maybe_register_secure_table(
    conn: &Connection,
    use_shim: bool,
    logical: &str,
    physical: &str,
    table_label: Option<&str>,
) -> AppResult<()> {
    let existing = conn
        .query_row(
            "SELECT COUNT(*) FROM sec_tables WHERE logical_table = ?1",
            [logical],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0);
    if existing == 0 {
        register_secure_table(conn, use_shim, logical, physical, table_label)?;
    }
    Ok(())
}

fn set_column_security(
    conn: &Connection,
    use_shim: bool,
    table: &str,
    column: &str,
    read_expr: &str,
) -> AppResult<()> {
    if use_shim {
        conn.execute_batch(&format!(
            "SET COLUMN SECURITY {table}.{column} READ '{read_expr}';"
        ))?;
    } else {
        conn.execute(
            "UPDATE sec_columns
             SET read_label_id = sec_define_label(?1)
             WHERE logical_table = ?2 AND column_name = ?3",
            params![read_expr, table, column],
        )?;
    }
    Ok(())
}

pub(crate) fn refresh_views(conn: &Connection, use_shim: bool) -> AppResult<()> {
    if use_shim {
        conn.execute_batch("REFRESH SECURE VIEWS;")?;
    } else {
        conn.query_row::<i64, _, _>("SELECT sec_refresh_views()", [], |r| r.get(0))?;
    }
    Ok(())
}

pub(crate) fn set_admin_context(conn: &Connection, use_shim: bool) -> AppResult<()> {
    apply_context(conn, use_shim, Role::Admin, None)
}

pub(crate) fn apply_context(
    conn: &Connection,
    use_shim: bool,
    role: Role,
    tenant: Option<usize>,
) -> AppResult<()> {
    if use_shim {
        conn.execute_batch("CLEAR CONTEXT;")?;
        conn.execute_batch(&format!("SET CONTEXT role = '{}';", role.as_str()))?;
        if let Some(tenant_idx) = tenant {
            conn.execute_batch(&format!(
                "SET CONTEXT tenant = '{}';",
                tenant_name(tenant_idx)
            ))?;
        }
    } else {
        conn.query_row::<i64, _, _>("SELECT sec_clear_context()", [], |r| r.get(0))?;
        conn.query_row::<i64, _, _>(
            "SELECT sec_set_attr(?1, ?2)",
            params!["role", role.as_str()],
            |r| r.get(0),
        )?;
        if let Some(tenant_idx) = tenant {
            conn.query_row::<i64, _, _>(
                "SELECT sec_set_attr(?1, ?2)",
                params!["tenant", tenant_name(tenant_idx)],
                |r| r.get(0),
            )?;
        }
        conn.query_row::<i64, _, _>("SELECT sec_refresh_views()", [], |r| r.get(0))?;
    }
    Ok(())
}

pub(crate) fn validate_ciphertext(db_path: &Path) -> AppResult<()> {
    let raw = fs::read(db_path)?;
    if raw.len() < 16 || &raw[..16] != b"SQLite format 3\0" {
        return Err("sqlite header missing from raw file".into());
    }
    let raw_str = String::from_utf8_lossy(&raw);
    for needle in ["secret-note-", "created order", "transitioned order"] {
        if raw_str.contains(needle) {
            return Err(format!("plaintext marker '{needle}' found in raw encrypted file").into());
        }
    }
    Ok(())
}
