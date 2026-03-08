use std::{
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use rusqlite::{Connection, OpenFlags, Result, params};

use crate::helpers::{TestDir, TestRunner};

const WARMUP_RUNS: usize = 1;
const MEASURED_RUNS: usize = 3;

#[derive(Copy, Clone)]
struct RaftPerfConfig {
    accounts: i64,
    transfer_txns: i64,
    point_reads: i64,
    range_reads: i64,
}

#[derive(Copy, Clone, Default)]
struct RaftPerfSample {
    seed_txn: Duration,
    transfer_txns: Duration,
    point_reads: Duration,
    range_reads: Duration,
    total: Duration,
}

#[derive(Copy, Clone)]
enum Engine {
    Plain,
    Evfs,
    EvfsRaft,
}

pub(crate) fn run_evfs_raft_perf_tests(t: &mut TestRunner, mode: &str) -> Result<()> {
    t.section("Performance: evfs Raft Workload vs EVFS/SQLite");

    let ext_path = format!("../sqlevfs/target/{mode}/libsqlevfs.so");
    if !Path::new(&ext_path).exists() {
        t.fail(
            "evfs raft perf prerequisites",
            &format!("missing sqlevfs extension: {ext_path}"),
        );
        return Ok(());
    }

    let cfg = RaftPerfConfig {
        accounts: 3_000,
        transfer_txns: 900,
        point_reads: 10_000,
        range_reads: 700,
    };

    let tmp = TestDir::new("lazytest-raft-perf-");
    let keyfile = tmp.write_keyfile("raft-perf.key", [0x6D; 32]);
    unsafe {
        std::env::set_var("EVFS_KEYFILE", &keyfile);
    }

    load_evfs_extension(mode)?;
    t.ok("loaded sqlevfs extension for raft perf runs");

    let plain = benchmark_engine(Engine::Plain, &tmp.path("raft-plain.db"), mode, cfg)?;
    let evfs = benchmark_engine(Engine::Evfs, &tmp.path("raft-evfs.db"), mode, cfg)?;
    let raft = benchmark_engine(Engine::EvfsRaft, &tmp.path("raft-evfs-raft.db"), mode, cfg)?;

    report_overhead(
        t,
        "seed transaction",
        plain.seed_txn,
        raft.seed_txn,
        "sqlite",
        "evfs_raft",
    );
    report_overhead(
        t,
        "seed transaction",
        evfs.seed_txn,
        raft.seed_txn,
        "evfs",
        "evfs_raft",
    );

    report_overhead(
        t,
        "transfer transactions (many commits)",
        plain.transfer_txns,
        raft.transfer_txns,
        "sqlite",
        "evfs_raft",
    );
    report_overhead(
        t,
        "transfer transactions (many commits)",
        evfs.transfer_txns,
        raft.transfer_txns,
        "evfs",
        "evfs_raft",
    );

    report_overhead(
        t,
        "point reads",
        plain.point_reads,
        raft.point_reads,
        "sqlite",
        "evfs_raft",
    );
    report_overhead(
        t,
        "point reads",
        evfs.point_reads,
        raft.point_reads,
        "evfs",
        "evfs_raft",
    );

    report_overhead(
        t,
        "range reads",
        plain.range_reads,
        raft.range_reads,
        "sqlite",
        "evfs_raft",
    );
    report_overhead(
        t,
        "range reads",
        evfs.range_reads,
        raft.range_reads,
        "evfs",
        "evfs_raft",
    );

    report_overhead(
        t,
        "total raft-like workload",
        plain.total,
        raft.total,
        "sqlite",
        "evfs_raft",
    );
    report_overhead(
        t,
        "total raft-like workload",
        evfs.total,
        raft.total,
        "evfs",
        "evfs_raft",
    );

    Ok(())
}

fn load_evfs_extension(mode: &str) -> Result<()> {
    let loader = Connection::open(":memory:")?;
    unsafe {
        loader.load_extension_enable()?;
        loader.load_extension(format!("../sqlevfs/target/{mode}/libsqlevfs"), None::<&str>)?;
        loader.load_extension_disable()?;
    }
    Ok(())
}

fn benchmark_engine(
    engine: Engine,
    db_path: &Path,
    mode: &str,
    cfg: RaftPerfConfig,
) -> Result<RaftPerfSample> {
    cleanup_db_artifacts(db_path);

    for _ in 0..WARMUP_RUNS {
        let _ = run_single_workload(engine, db_path, mode, cfg)?;
        cleanup_db_artifacts(db_path);
    }

    let mut samples = Vec::with_capacity(MEASURED_RUNS);
    for _ in 0..MEASURED_RUNS {
        let sample = run_single_workload(engine, db_path, mode, cfg)?;
        samples.push(sample);
        cleanup_db_artifacts(db_path);
    }

    Ok(RaftPerfSample {
        seed_txn: median_duration(samples.iter().map(|s| s.seed_txn).collect()),
        transfer_txns: median_duration(samples.iter().map(|s| s.transfer_txns).collect()),
        point_reads: median_duration(samples.iter().map(|s| s.point_reads).collect()),
        range_reads: median_duration(samples.iter().map(|s| s.range_reads).collect()),
        total: median_duration(samples.iter().map(|s| s.total).collect()),
    })
}

fn run_single_workload(
    engine: Engine,
    db_path: &Path,
    mode: &str,
    cfg: RaftPerfConfig,
) -> Result<RaftPerfSample> {
    let start_total = Instant::now();

    if matches!(engine, Engine::EvfsRaft) {
        stop_raft_best_effort(db_path, mode);
        setup_single_node_raft(db_path, mode)?;
    }

    let conn = open_conn(engine, db_path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS account (
            id         INTEGER PRIMARY KEY,
            tenant     INTEGER NOT NULL,
            balance    INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            note       TEXT NOT NULL
         )",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_account_tenant ON account(tenant)",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ledger (
            id         INTEGER PRIMARY KEY,
            from_id    INTEGER NOT NULL,
            to_id      INTEGER NOT NULL,
            amount     INTEGER NOT NULL,
            ts         INTEGER NOT NULL
         )",
        [],
    )?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_ts ON ledger(ts)", [])?;

    let start_seed = Instant::now();
    conn.execute_batch("BEGIN IMMEDIATE;")?;
    {
        let mut ins = conn.prepare(
            "INSERT INTO account (id, tenant, balance, updated_at, note)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for id in 1..=cfg.accounts {
            ins.execute(params![
                id,
                id % 40,
                10_000_i64,
                id,
                format!("acct-{id:05}")
            ])?;
        }
    }
    conn.execute_batch("COMMIT;")?;
    let seed_txn = start_seed.elapsed();

    let start_transfers = Instant::now();
    for i in 0..cfg.transfer_txns {
        let from_id = ((i * 7_919) % cfg.accounts) + 1;
        let mut to_id = ((i * 10_729) % cfg.accounts) + 1;
        if to_id == from_id {
            to_id = (to_id % cfg.accounts) + 1;
        }
        let amount = (i % 97) + 1;

        conn.execute_batch("BEGIN IMMEDIATE;")?;
        conn.execute(
            "UPDATE account SET balance = balance - ?1, updated_at = ?2 WHERE id = ?3",
            params![amount, i + 1, from_id],
        )?;
        conn.execute(
            "UPDATE account SET balance = balance + ?1, updated_at = ?2 WHERE id = ?3",
            params![amount, i + 1, to_id],
        )?;
        conn.execute(
            "INSERT INTO ledger (from_id, to_id, amount, ts) VALUES (?1, ?2, ?3, ?4)",
            params![from_id, to_id, amount, i + 1],
        )?;
        conn.execute_batch("COMMIT;")?;
    }
    let transfer_txns = start_transfers.elapsed();

    let start_point_reads = Instant::now();
    {
        let mut stmt = conn.prepare("SELECT balance FROM account WHERE id = ?1")?;
        for i in 0..cfg.point_reads {
            let id = ((i * 17_321) % cfg.accounts) + 1;
            let _bal: i64 = stmt.query_row([id], |row| row.get(0))?;
        }
    }
    let point_reads = start_point_reads.elapsed();

    let start_range_reads = Instant::now();
    {
        let mut stmt =
            conn.prepare("SELECT COALESCE(SUM(amount), 0) FROM ledger WHERE ts BETWEEN ?1 AND ?2")?;
        for i in 0..cfg.range_reads {
            let lo = ((i * 37) % cfg.transfer_txns).max(1);
            let hi = (lo + 180).min(cfg.transfer_txns);
            let _sum: i64 = stmt.query_row(params![lo, hi], |row| row.get(0))?;
        }
    }
    let range_reads = start_range_reads.elapsed();

    let account_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM account", [], |row| row.get(0))?;
    let ledger_count: i64 = conn.query_row("SELECT COUNT(*) FROM ledger", [], |row| row.get(0))?;
    if account_count != cfg.accounts || ledger_count != cfg.transfer_txns {
        return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
            std::io::Error::other(format!(
                "unexpected row counts: account={account_count} ledger={ledger_count}"
            )),
        )));
    }

    drop(conn);

    if matches!(engine, Engine::EvfsRaft) {
        stop_raft_best_effort(db_path, mode);
    }

    Ok(RaftPerfSample {
        seed_txn,
        transfer_txns,
        point_reads,
        range_reads,
        total: start_total.elapsed(),
    })
}

fn open_conn(engine: Engine, db_path: &Path) -> Result<Connection> {
    match engine {
        Engine::Plain => Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        ),
        Engine::Evfs => Connection::open_with_flags_and_vfs(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            "evfs",
        ),
        Engine::EvfsRaft => Connection::open_with_flags_and_vfs(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            "evfs_raft",
        ),
    }
}

fn setup_single_node_raft(db_path: &Path, mode: &str) -> Result<()> {
    let conn = Connection::open_with_flags_and_vfs(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        "evfs",
    )?;

    load_evfs_sql_functions(&conn, mode)?;

    conn.query_row::<String, _, _>(
        "SELECT evfs_raft_init(?1, ?2, ?3)",
        params![1_i64, "127.0.0.1:0", "{}"],
        |r| r.get(0),
    )?;

    let ready = wait_until(Duration::from_secs(5), || {
        let status: Result<String> = conn.query_row("SELECT evfs_raft_status()", [], |r| r.get(0));
        match status {
            Ok(s) => s.contains("\"node_id\":1") && s.contains("\"is_leader\":true"),
            Err(_) => false,
        }
    });

    if !ready {
        return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
            std::io::Error::other("timed out waiting for evfs_raft leader"),
        )));
    }

    Ok(())
}

fn stop_raft_best_effort(db_path: &Path, mode: &str) {
    let Ok(conn) = Connection::open_with_flags_and_vfs(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        "evfs",
    ) else {
        return;
    };

    if load_evfs_sql_functions(&conn, mode).is_err() {
        return;
    }

    let _: Result<String> = conn.query_row("SELECT evfs_raft_stop()", [], |r| r.get(0));
}

fn load_evfs_sql_functions(conn: &Connection, mode: &str) -> Result<()> {
    unsafe {
        conn.load_extension_enable()?;
        conn.load_extension(format!("../sqlevfs/target/{mode}/libsqlevfs"), None::<&str>)?;
        conn.load_extension_disable()?;
    }
    Ok(())
}

fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if pred() {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

fn cleanup_db_artifacts(db_path: &Path) {
    let mut paths = vec![db_path.to_path_buf()];
    paths.push(PathBuf::from(format!("{}-wal", db_path.display())));
    paths.push(PathBuf::from(format!("{}-shm", db_path.display())));
    paths.push(db_path.with_extension("evfs-raft.json"));

    for path in paths {
        let _ = std::fs::remove_file(path);
    }
}

fn report_overhead(
    t: &mut TestRunner,
    label: &str,
    baseline: Duration,
    candidate: Duration,
    baseline_name: &str,
    candidate_name: &str,
) {
    let b = ms(baseline);
    let c = ms(candidate);
    if b <= f64::EPSILON {
        t.fail(label, &"baseline timing was zero");
        return;
    }

    let overhead_pct = ((c / b) - 1.0) * 100.0;
    t.ok(&format!(
        "{label}: {baseline_name}={b:.2}ms {candidate_name}={c:.2}ms overhead={overhead_pct:+.2}%"
    ));
}

fn median_duration(mut durs: Vec<Duration>) -> Duration {
    durs.sort_unstable();
    durs[durs.len() / 2]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}
