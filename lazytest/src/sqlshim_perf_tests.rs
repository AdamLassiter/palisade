use std::{
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use rusqlite::{Connection, Result, params};

use crate::helpers::TestRunner;

const WARMUP_RUNS: usize = 1;
const MEASURED_RUNS: usize = 5;
const RESULT_PREFIX: &str = "LAZYTEST_SQLSHIM_PERF_RESULT";

#[derive(Copy, Clone, Default)]
struct SqlshimPerfSample {
    prepare_heavy: Duration,
    mixed_query: Duration,
    total: Duration,
}

pub(crate) fn run_sqlshim_perf_tests(t: &mut TestRunner, mode: &str) -> Result<()> {
    t.section("Performance: sqlshim Overhead vs Plain SQLite");

    let sqlshim_path = format!("../sqlshim/target/{mode}/libsqlshim.so");
    if !Path::new(&sqlshim_path).exists() {
        t.fail(
            "sqlshim perf prerequisites",
            &format!("missing sqlshim preload library: {sqlshim_path}"),
        );
        return Ok(());
    }

    let plain = benchmark_parent_runs(mode, None)?;
    let sqlshim = benchmark_parent_runs(mode, Some(PathBuf::from(sqlshim_path)))?;

    report_overhead(
        t,
        "prepare-heavy point lookups",
        plain.prepare_heavy,
        sqlshim.prepare_heavy,
    );
    report_overhead(
        t,
        "mixed query workload",
        plain.mixed_query,
        sqlshim.mixed_query,
    );
    report_overhead(t, "total sqlshim benchmark", plain.total, sqlshim.total);

    Ok(())
}

pub(crate) fn run_sqlshim_perf_child() -> Result<()> {
    let sample = run_sqlshim_workload()?;
    println!(
        "{RESULT_PREFIX} prepare_ms={:.6} mixed_ms={:.6} total_ms={:.6}",
        ms(sample.prepare_heavy),
        ms(sample.mixed_query),
        ms(sample.total)
    );
    Ok(())
}

fn benchmark_parent_runs(
    mode: &str,
    sqlshim_preload: Option<PathBuf>,
) -> Result<SqlshimPerfSample> {
    let mut samples = Vec::with_capacity(MEASURED_RUNS);

    for _ in 0..WARMUP_RUNS {
        let _ = run_child_once(mode, sqlshim_preload.as_deref())?;
    }
    for _ in 0..MEASURED_RUNS {
        samples.push(run_child_once(mode, sqlshim_preload.as_deref())?);
    }

    Ok(SqlshimPerfSample {
        prepare_heavy: median_duration(samples.iter().map(|s| s.prepare_heavy).collect()),
        mixed_query: median_duration(samples.iter().map(|s| s.mixed_query).collect()),
        total: median_duration(samples.iter().map(|s| s.total).collect()),
    })
}

fn run_child_once(mode: &str, sqlshim_preload: Option<&Path>) -> Result<SqlshimPerfSample> {
    let exe = std::env::current_exe()
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    let mut cmd = Command::new(exe);
    cmd.arg(format!("--{mode}")).arg("--perf-sqlshim-child");
    cmd.env_remove("LD_PRELOAD");
    if let Some(preload_path) = sqlshim_preload {
        cmd.env("LD_PRELOAD", preload_path);
    }

    let output = cmd
        .output()
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
            std::io::Error::other(format!("sqlshim perf child failed: {stderr}")),
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_child_result(&stdout)
}

fn parse_child_result(stdout: &str) -> Result<SqlshimPerfSample> {
    let line = stdout
        .lines()
        .find(|l| l.starts_with(RESULT_PREFIX))
        .ok_or_else(|| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(format!(
                "missing perf result line in child output: {stdout}"
            ))))
        })?;

    let mut prepare_ms = None;
    let mut mixed_ms = None;
    let mut total_ms = None;

    for token in line.split_whitespace().skip(1) {
        let mut it = token.splitn(2, '=');
        let key = it.next().unwrap_or_default();
        let value = it.next().unwrap_or_default();
        let parsed = value.parse::<f64>().map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(format!(
                "could not parse {key}: {e}"
            ))))
        })?;
        match key {
            "prepare_ms" => prepare_ms = Some(parsed),
            "mixed_ms" => mixed_ms = Some(parsed),
            "total_ms" => total_ms = Some(parsed),
            _ => {}
        }
    }

    Ok(SqlshimPerfSample {
        prepare_heavy: Duration::from_secs_f64(
            prepare_ms.ok_or_else(|| {
                rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(
                    "missing prepare_ms in child result",
                )))
            })? / 1000.0,
        ),
        mixed_query: Duration::from_secs_f64(
            mixed_ms.ok_or_else(|| {
                rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(
                    "missing mixed_ms in child result",
                )))
            })? / 1000.0,
        ),
        total: Duration::from_secs_f64(
            total_ms.ok_or_else(|| {
                rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(
                    "missing total_ms in child result",
                )))
            })? / 1000.0,
        ),
    })
}

fn run_sqlshim_workload() -> Result<SqlshimPerfSample> {
    let rows = 6_000i64;
    let prepare_iters = 25_000i64;
    let mixed_iters = 18_000i64;

    let start_total = Instant::now();
    let conn = Connection::open(":memory:")?;
    conn.execute_batch(
        "PRAGMA journal_mode = MEMORY;
         PRAGMA temp_store = MEMORY;
         PRAGMA synchronous = OFF;",
    )?;
    conn.execute_batch(
        "CREATE TABLE bench (
            id      INTEGER PRIMARY KEY,
            tenant  INTEGER NOT NULL,
            value   INTEGER NOT NULL,
            payload TEXT NOT NULL
         );
         CREATE INDEX idx_bench_tenant ON bench(tenant);",
    )?;

    conn.execute_batch("BEGIN;")?;
    {
        let mut ins =
            conn.prepare("INSERT INTO bench (id, tenant, value, payload) VALUES (?1, ?2, ?3, ?4)")?;
        for id in 1..=rows {
            ins.execute(params![id, id % 50, id * 11, format!("r{id:05}")])?;
        }
    }
    conn.execute_batch("COMMIT;")?;

    let start_prepare = Instant::now();
    let mut checksum = 0i64;
    for i in 0..prepare_iters {
        let id = ((i * 1_103) % rows) + 1;
        let mut stmt = conn.prepare("SELECT value FROM bench WHERE id = ?1")?;
        let v: i64 = stmt.query_row([id], |row| row.get(0))?;
        checksum ^= v;
    }
    let prepare_heavy = start_prepare.elapsed();

    let start_mixed = Instant::now();
    for i in 0..mixed_iters {
        let tenant = i % 50;
        let floor = (i * 13) % 10_000;
        let mut stmt = conn.prepare(
            "SELECT COUNT(*) FROM bench
             WHERE tenant = ?1 AND value > ?2",
        )?;
        let c: i64 = stmt.query_row(params![tenant, floor], |row| row.get(0))?;
        checksum ^= c;

        let id = ((i * 1_871) % rows) + 1;
        let mut upd = conn.prepare("UPDATE bench SET value = value + 1 WHERE id = ?1")?;
        upd.execute([id])?;
    }
    let mixed_query = start_mixed.elapsed();

    if checksum == 0 {
        return Err(rusqlite::Error::ExecuteReturnedResults);
    }

    Ok(SqlshimPerfSample {
        prepare_heavy,
        mixed_query,
        total: start_total.elapsed(),
    })
}

fn report_overhead(t: &mut TestRunner, label: &str, plain: Duration, shim: Duration) {
    let plain_ms = ms(plain);
    let shim_ms = ms(shim);
    if plain_ms <= f64::EPSILON {
        t.fail(label, &"plain sqlite timing was zero");
        return;
    }

    let overhead_pct = ((shim_ms / plain_ms) - 1.0) * 100.0;
    t.ok(&format!(
        "{label}: sqlite={plain_ms:.2}ms sqlshim={shim_ms:.2}ms overhead={overhead_pct:+.2}%"
    ));
}

fn median_duration(mut durs: Vec<Duration>) -> Duration {
    durs.sort_unstable();
    durs[durs.len() / 2]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}
