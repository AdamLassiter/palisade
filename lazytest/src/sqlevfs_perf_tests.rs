use std::{
    path::Path,
    time::{Duration, Instant},
};

use rusqlite::{Connection, OpenFlags, Result, params};

use crate::helpers::{TestDir, TestRunner};

const WARMUP_RUNS: usize = 1;
const MEASURED_RUNS: usize = 5;

#[derive(Copy, Clone)]
struct PerfConfig {
    rows: i64,
    point_reads: i64,
    updates: i64,
}

#[derive(Copy, Clone, Default)]
struct PerfSample {
    write_txn: Duration,
    point_reads: Duration,
    update_txn: Duration,
    scan_sum: Duration,
    total: Duration,
}

#[derive(Copy, Clone)]
enum Engine {
    Plain,
    Evfs,
}

pub(crate) fn run_evfs_perf_tests(t: &mut TestRunner, mode: &str) -> Result<()> {
    t.section("Performance: EVFS Overhead vs Plain SQLite");

    let evfs_path = format!("../sqlevfs/target/{mode}/libsqlevfs.so");
    if !Path::new(&evfs_path).exists() {
        t.fail(
            "perf suite prerequisites",
            &format!("missing sqlevfs extension: {evfs_path}"),
        );
        return Ok(());
    }

    let cfg = PerfConfig {
        rows: 20_000,
        point_reads: 30_000,
        updates: 10_000,
    };

    let tmp = TestDir::new("lazytest-perf-");
    let keyfile = tmp.write_keyfile("perf.key", [0x4C; 32]);
    unsafe {
        std::env::set_var("EVFS_KEYFILE", &keyfile);
    }

    load_evfs_extension(mode)?;
    t.ok("loaded sqlevfs extension for perf runs");

    let sqlite_stats = benchmark_engine(Engine::Plain, &tmp.path("plain.db"), cfg)?;
    let evfs_stats = benchmark_engine(Engine::Evfs, &tmp.path("evfs.db"), cfg)?;

    report_overhead(
        t,
        "write transaction",
        sqlite_stats.write_txn,
        evfs_stats.write_txn,
    );
    report_overhead(
        t,
        "point reads",
        sqlite_stats.point_reads,
        evfs_stats.point_reads,
    );
    report_overhead(
        t,
        "update transaction",
        sqlite_stats.update_txn,
        evfs_stats.update_txn,
    );
    report_overhead(
        t,
        "scan aggregate",
        sqlite_stats.scan_sum,
        evfs_stats.scan_sum,
    );
    report_overhead(t, "total workload", sqlite_stats.total, evfs_stats.total);

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

fn benchmark_engine(engine: Engine, db_path: &Path, cfg: PerfConfig) -> Result<PerfSample> {
    if db_path.exists() {
        std::fs::remove_file(db_path)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    }

    for _ in 0..WARMUP_RUNS {
        let _ = run_single_workload(engine, db_path, cfg)?;
        if db_path.exists() {
            std::fs::remove_file(db_path)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        }
    }

    let mut samples = Vec::with_capacity(MEASURED_RUNS);
    for _ in 0..MEASURED_RUNS {
        let sample = run_single_workload(engine, db_path, cfg)?;
        samples.push(sample);
        if db_path.exists() {
            std::fs::remove_file(db_path)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        }
    }

    Ok(PerfSample {
        write_txn: median_duration(samples.iter().map(|s| s.write_txn).collect()),
        point_reads: median_duration(samples.iter().map(|s| s.point_reads).collect()),
        update_txn: median_duration(samples.iter().map(|s| s.update_txn).collect()),
        scan_sum: median_duration(samples.iter().map(|s| s.scan_sum).collect()),
        total: median_duration(samples.iter().map(|s| s.total).collect()),
    })
}

fn run_single_workload(engine: Engine, db_path: &Path, cfg: PerfConfig) -> Result<PerfSample> {
    let start_total = Instant::now();
    let conn = open_conn(engine, db_path)?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA temp_store = MEMORY;
         PRAGMA cache_size = -8192;
         PRAGMA page_size = 4096;",
    )?;

    conn.execute_batch(
        "CREATE TABLE kv (
            id      INTEGER PRIMARY KEY,
            tenant  INTEGER NOT NULL,
            payload TEXT NOT NULL,
            value   INTEGER NOT NULL
         );
         CREATE INDEX idx_kv_tenant ON kv(tenant);",
    )?;

    let start_write = Instant::now();
    conn.execute_batch("BEGIN IMMEDIATE;")?;
    {
        let mut stmt =
            conn.prepare("INSERT INTO kv (id, tenant, payload, value) VALUES (?1, ?2, ?3, ?4)")?;
        for id in 1..=cfg.rows {
            let tenant = id % 100;
            let payload = format!("payload-{id:08}");
            stmt.execute(params![id, tenant, payload, id * 7])?;
        }
    }
    conn.execute_batch("COMMIT;")?;
    let write_txn = start_write.elapsed();

    let start_reads = Instant::now();
    let mut checksum = 0i64;
    {
        let mut stmt = conn.prepare("SELECT value FROM kv WHERE id = ?1")?;
        for i in 0..cfg.point_reads {
            let id = ((i * 17_321) % cfg.rows) + 1;
            let v: i64 = stmt.query_row([id], |row| row.get(0))?;
            checksum ^= v;
        }
    }
    let point_reads = start_reads.elapsed();

    let start_update = Instant::now();
    conn.execute_batch("BEGIN IMMEDIATE;")?;
    {
        let mut stmt = conn.prepare("UPDATE kv SET value = value + 1 WHERE id = ?1")?;
        for i in 0..cfg.updates {
            let id = ((i * 7_919) % cfg.rows) + 1;
            stmt.execute([id])?;
        }
    }
    conn.execute_batch("COMMIT;")?;
    let update_txn = start_update.elapsed();

    let start_scan = Instant::now();
    let scan_sum_value: i64 = conn.query_row(
        "SELECT SUM(value) FROM kv WHERE tenant BETWEEN 10 AND 39",
        [],
        |row| row.get(0),
    )?;
    let scan_sum = start_scan.elapsed();

    if checksum == 0 || scan_sum_value == 0 {
        return Err(rusqlite::Error::ExecuteReturnedResults);
    }

    let total = start_total.elapsed();

    Ok(PerfSample {
        write_txn,
        point_reads,
        update_txn,
        scan_sum,
        total,
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
    }
}

fn median_duration(mut durs: Vec<Duration>) -> Duration {
    durs.sort_unstable();
    durs[durs.len() / 2]
}

fn report_overhead(t: &mut TestRunner, label: &str, plain: Duration, evfs: Duration) {
    let p = duration_ms(plain);
    let e = duration_ms(evfs);
    if p <= f64::EPSILON {
        t.fail(label, &"plain sqlite timing was zero");
        return;
    }

    let overhead_pct = ((e / p) - 1.0) * 100.0;
    t.ok(&format!(
        "{label}: sqlite={p:.2}ms evfs={e:.2}ms overhead={overhead_pct:+.2}%"
    ));
}

fn duration_ms(dur: Duration) -> f64 {
    dur.as_secs_f64() * 1000.0
}
