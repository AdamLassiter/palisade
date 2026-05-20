use std::{
    fs,
    path::Path,
    sync::{Mutex, OnceLock},
    thread,
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::{
    status::RaftStatusDoc,
    types::{AppResult, TENANTS},
    util::{SimpleRng, random_account_id, tenant_name},
};

static SQLSEC_LOAD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) fn open_evfs_control_conn(db_path: &Path, sqlevfs: &Path) -> AppResult<Connection> {
    let loader = Connection::open(":memory:")?;
    load_sqlevfs_on_conn(&loader, sqlevfs)?;
    let conn = Connection::open_with_flags_and_vfs(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        "evfs",
    )?;
    load_sqlevfs_on_conn(&conn, sqlevfs)?;
    Ok(conn)
}

pub(crate) fn load_sqlevfs_on_conn(conn: &Connection, sqlevfs: &Path) -> AppResult<()> {
    unsafe {
        conn.load_extension_enable()?;
        conn.load_extension(sqlevfs, None::<&str>)?;
        conn.load_extension_disable()?;
    }
    Ok(())
}

pub(crate) fn load_sqlsec_on_conn(conn: &Connection, sqlsec: &Path) -> AppResult<()> {
    const MAX_ATTEMPTS: usize = 8;
    let _guard = SQLSEC_LOAD_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| "sqlsec load lock poisoned")?;
    let mut last_err = None;
    for attempt in 1..=MAX_ATTEMPTS {
        let result = unsafe {
            conn.load_extension_enable()?;
            let load_result = conn.load_extension(sqlsec, None::<&str>);
            let disable_result = conn.load_extension_disable();
            load_result?;
            disable_result?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        };
        match result {
            Ok(()) => return Ok(()),
            Err(err)
                if (err.to_string().contains("locked") || err.to_string().contains("busy"))
                    && attempt < MAX_ATTEMPTS =>
            {
                last_err = Some(err);
                thread::sleep(Duration::from_millis(25 * attempt as u64));
            }
            Err(err) => {
                return Err(format!(
                    "sqlsec initialization failed after attempt {attempt}/{MAX_ATTEMPTS}: {err}"
                )
                .into());
            }
        }
    }
    Err(format!(
        "sqlsec initialization failed after {MAX_ATTEMPTS} attempts: {}",
        last_err
            .map(|err| err.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    )
    .into())
}

pub(crate) fn configure_conn(conn: &Connection) -> AppResult<()> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA temp_store = MEMORY;
         PRAGMA cache_size = -8192;
         PRAGMA page_size = 4096;",
    )?;
    Ok(())
}

pub(crate) fn create_schema(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS __sec_accounts (
            id INTEGER PRIMARY KEY,
            tenant TEXT NOT NULL,
            balance INTEGER NOT NULL,
            status TEXT NOT NULL,
            secret_note TEXT NOT NULL,
            row_label_id INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx___sec_accounts_tenant ON __sec_accounts(tenant);

        CREATE TABLE IF NOT EXISTS __sec_orders (
            id INTEGER PRIMARY KEY,
            tenant TEXT NOT NULL,
            account_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            status TEXT NOT NULL,
            row_label_id INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx___sec_orders_tenant ON __sec_orders(tenant);

        CREATE TABLE IF NOT EXISTS __sec_transfers (
            id INTEGER PRIMARY KEY,
            tenant TEXT NOT NULL,
            from_account_id INTEGER NOT NULL,
            to_account_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            row_label_id INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx___sec_transfers_tenant_ts ON __sec_transfers(tenant, ts);

        CREATE TABLE IF NOT EXISTS __sec_audit_log (
            id INTEGER PRIMARY KEY,
            tenant TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            action TEXT NOT NULL,
            ref_id INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            detail TEXT NOT NULL,
            row_label_id INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx___sec_audit_log_tenant_ts ON __sec_audit_log(tenant, ts);",
    )?;
    Ok(())
}

pub(crate) fn bootstrap_sqlsec(conn: &Connection) -> AppResult<()> {
    conn.query_row::<i64, _, _>("SELECT sec_clear_context()", [], |r| r.get(0))?;
    conn.query_row::<i64, _, _>("SELECT sec_set_attr('role', 'admin')", [], |r| r.get(0))?;
    for tenant_idx in 0..TENANTS {
        let expr = format!("(tenant={}|role=admin|role=ops)", tenant_name(tenant_idx));
        conn.query_row::<i64, _, _>("SELECT sec_define_label(?1)", [expr], |r| r.get(0))?;
    }
    for (logical, physical) in [
        ("accounts", "__sec_accounts"),
        ("orders", "__sec_orders"),
        ("transfers", "__sec_transfers"),
    ] {
        let exists = conn
            .query_row(
                "SELECT COUNT(*) FROM sec_tables WHERE logical_name = ?1",
                [logical],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0);
        if exists == 0 {
            conn.query_row::<i64, _, _>(
                "SELECT sec_register_table(?1, ?2, 'row_label_id', NULL, NULL)",
                params![logical, physical],
                |r| r.get(0),
            )?;
        }
    }
    conn.execute(
        "UPDATE sec_columns
         SET read_label_id = sec_define_label('role=admin')
         WHERE logical_table = 'accounts' AND column_name = 'secret_note'",
        [],
    )?;
    conn.query_row::<i64, _, _>("SELECT sec_refresh_views()", [], |r| r.get(0))?;
    Ok(())
}

pub(crate) fn tenant_label_id(conn: &Connection, tenant_idx: usize) -> AppResult<i64> {
    let expr = format!("(tenant={}|role=admin|role=ops)", tenant_name(tenant_idx));
    Ok(
        conn.query_row("SELECT id FROM sec_labels WHERE expr = ?1", [expr], |r| {
            r.get(0)
        })?,
    )
}

pub(crate) fn transfer_once(
    conn: &Connection,
    rng: &mut SimpleRng,
    metrics: &mut WorkloadMetrics,
) -> AppResult<()> {
    let tenant_idx = rng.range(TENANTS as u64) as usize;
    let from_id = random_account_id(rng, tenant_idx);
    let mut to_id = random_account_id(rng, tenant_idx);
    if from_id == to_id {
        to_id = random_account_id(rng, (tenant_idx + 1) % TENANTS);
    }
    let amount = (rng.range(90) + 10) as i64;
    let transfer_id = (rng.next() & 0x3fff_ffff) as i64;
    let audit_id = transfer_id + 10_000_000;
    let tenant = tenant_name(tenant_idx);
    let label_id = tenant_label_id(conn, tenant_idx)?;

    let tx = conn.unchecked_transaction()?;
    let balance: Option<i64> = tx
        .query_row(
            "SELECT balance FROM __sec_accounts WHERE id = ?1",
            [from_id],
            |r| r.get(0),
        )
        .optional()?;
    if balance.unwrap_or(0) >= amount {
        tx.execute(
            "UPDATE __sec_accounts SET balance = balance - ?1 WHERE id = ?2",
            params![amount, from_id],
        )?;
        tx.execute(
            "UPDATE __sec_accounts SET balance = balance + ?1 WHERE id = ?2",
            params![amount, to_id],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO __sec_transfers
             (id, tenant, from_account_id, to_account_id, amount, ts, row_label_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?1, ?6)",
            params![transfer_id, tenant, from_id, to_id, amount, label_id],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO __sec_audit_log
             (id, tenant, actor_role, action, ref_id, ts, detail, row_label_id)
             VALUES (?1, ?2, 'ops', 'transfer', ?3, ?3, ?4, ?5)",
            params![
                audit_id,
                tenant,
                transfer_id,
                format!("transfer {amount} from {from_id} to {to_id}"),
                label_id
            ],
        )?;
        tx.commit()?;
        metrics.transfers += 1;
    } else {
        tx.rollback()?;
        metrics.skipped += 1;
    }
    Ok(())
}

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct WorkloadMetrics {
    pub(crate) transfers: u64,
    pub(crate) skipped: u64,
    pub(crate) lock_conflicts: u64,
}

impl WorkloadMetrics {
    pub(crate) fn merge(&mut self, other: &Self) {
        self.transfers += other.transfers;
        self.skipped += other.skipped;
        self.lock_conflicts += other.lock_conflicts;
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Aggregate {
    pub(crate) account_count: i64,
    pub(crate) total_balance: i64,
    pub(crate) transfer_count: i64,
    pub(crate) audit_count: i64,
}

pub(crate) fn aggregate(conn: &Connection) -> AppResult<Aggregate> {
    Ok(Aggregate {
        account_count: conn.query_row("SELECT COUNT(*) FROM __sec_accounts", [], |r| r.get(0))?,
        total_balance: conn
            .query_row("SELECT SUM(balance) FROM __sec_accounts", [], |r| r.get(0))?,
        transfer_count: conn.query_row("SELECT COUNT(*) FROM __sec_transfers", [], |r| r.get(0))?,
        audit_count: conn.query_row("SELECT COUNT(*) FROM __sec_audit_log", [], |r| r.get(0))?,
    })
}

pub(crate) fn validate_ciphertext(db_path: &Path) -> AppResult<()> {
    let raw = fs::read(db_path)?;
    if raw.len() < 16 || &raw[..16] != b"SQLite format 3\0" {
        return Err("sqlite header missing from raw file".into());
    }
    let raw_str = String::from_utf8_lossy(&raw);
    for needle in ["secret-note-", "transfer "] {
        if raw_str.contains(needle) {
            return Err(format!("plaintext marker '{needle}' found in encrypted file").into());
        }
    }
    Ok(())
}

pub(crate) fn raft_status_has_node(conn: &Connection, node_id: u64) -> AppResult<bool> {
    let status: String = conn.query_row("SELECT evfs_raft_status()", [], |r| r.get(0))?;
    let doc: RaftStatusDoc = serde_json::from_str(&status)?;
    Ok(doc.nodes.iter().any(|node| node.node_id == node_id))
}
