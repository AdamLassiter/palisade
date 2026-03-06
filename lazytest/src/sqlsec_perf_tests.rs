use std::time::{Duration, Instant};

use rusqlite::{Connection, Result, params};

use crate::helpers::TestRunner;

const WARMUP_RUNS: usize = 1;
const MEASURED_RUNS: usize = 5;

#[derive(Copy, Clone, Default)]
struct SqlsecPerfSample {
    physical_point_reads: Duration,
    secure_point_reads: Duration,
    physical_scan: Duration,
    secure_scan: Duration,
    refresh_cycles: Duration,
}

pub(crate) fn run_sqlsec_perf_tests(t: &mut TestRunner, mode: &str) -> Result<()> {
    t.section("Performance: sqlsec Function-Call + View Overhead");

    let lib_path = format!("../sqlsec/target/{mode}/libsqlsec.so");
    if !std::path::Path::new(&lib_path).exists() {
        t.fail(
            "sqlsec perf prerequisites",
            &format!("missing sqlsec extension: {lib_path}"),
        );
        return Ok(());
    }

    for _ in 0..WARMUP_RUNS {
        let _ = run_single(mode)?;
    }

    let mut samples = Vec::with_capacity(MEASURED_RUNS);
    for _ in 0..MEASURED_RUNS {
        samples.push(run_single(mode)?);
    }

    let med = SqlsecPerfSample {
        physical_point_reads: median_duration(
            samples.iter().map(|s| s.physical_point_reads).collect(),
        ),
        secure_point_reads: median_duration(samples.iter().map(|s| s.secure_point_reads).collect()),
        physical_scan: median_duration(samples.iter().map(|s| s.physical_scan).collect()),
        secure_scan: median_duration(samples.iter().map(|s| s.secure_scan).collect()),
        refresh_cycles: median_duration(samples.iter().map(|s| s.refresh_cycles).collect()),
    };

    report_overhead(
        t,
        "point reads (secured view vs physical table)",
        med.physical_point_reads,
        med.secure_point_reads,
    );
    report_overhead(
        t,
        "range scans (secured view vs physical table)",
        med.physical_scan,
        med.secure_scan,
    );
    t.ok(&format!(
        "refresh cycle cost (set_attr + refresh_views x120): {:.2}ms",
        ms(med.refresh_cycles)
    ));

    Ok(())
}

fn run_single(mode: &str) -> Result<SqlsecPerfSample> {
    let rows = 12_000i64;
    let point_iters = 30_000i64;
    let scan_iters = 150i64;
    let refresh_iters = 120i64;

    let conn = Connection::open(":memory:")?;
    unsafe {
        conn.load_extension_enable()?;
        conn.load_extension(format!("../sqlsec/target/{mode}/libsqlsec"), None::<&str>)?;
        conn.load_extension_disable()?;
    }

    let label_true: i64 = conn.query_row("SELECT sec_define_label('true')", [], |r| r.get(0))?;
    let label_admin: i64 =
        conn.query_row("SELECT sec_define_label('role=admin')", [], |r| r.get(0))?;

    conn.execute_batch(
        "CREATE TABLE __sec_events (
            id INTEGER PRIMARY KEY,
            row_label_id INTEGER NOT NULL,
            value INTEGER NOT NULL,
            payload TEXT NOT NULL
         );",
    )?;

    conn.execute_batch("BEGIN;")?;
    {
        let mut ins = conn.prepare(
            "INSERT INTO __sec_events (id, row_label_id, value, payload) VALUES (?1, ?2, ?3, ?4)",
        )?;
        for id in 1..=rows {
            let label = if id % 2 == 0 { label_admin } else { label_true };
            ins.execute(params![id, label, id * 17, format!("evt-{id:06}")])?;
        }
    }
    conn.execute_batch("COMMIT;")?;

    let _: i64 = conn.query_row(
        "SELECT sec_register_table(?1, ?2, ?3, NULL, NULL)",
        params!["events", "__sec_events", "row_label_id"],
        |r| r.get(0),
    )?;
    let _: i64 = conn.query_row(
        "SELECT sec_set_attr(?1, ?2)",
        params!["role", "admin"],
        |r| r.get(0),
    )?;
    let _: i64 = conn.query_row("SELECT sec_refresh_views()", [], |r| r.get(0))?;

    let start_physical_point = Instant::now();
    {
        let mut stmt = conn.prepare("SELECT value FROM __sec_events WHERE id = ?1")?;
        let mut checksum = 0i64;
        for i in 0..point_iters {
            let id = ((i * 8_197) % rows) + 1;
            let v: i64 = stmt.query_row([id], |r| r.get(0))?;
            checksum ^= v;
        }
        if checksum == 0 {
            return Err(rusqlite::Error::ExecuteReturnedResults);
        }
    }
    let physical_point_reads = start_physical_point.elapsed();

    let start_secure_point = Instant::now();
    {
        let mut stmt = conn.prepare("SELECT value FROM events WHERE id = ?1")?;
        let mut checksum = 0i64;
        for i in 0..point_iters {
            let id = ((i * 8_197) % rows) + 1;
            let v: i64 = stmt.query_row([id], |r| r.get(0))?;
            checksum ^= v;
        }
        if checksum == 0 {
            return Err(rusqlite::Error::ExecuteReturnedResults);
        }
    }
    let secure_point_reads = start_secure_point.elapsed();

    let start_physical_scan = Instant::now();
    {
        let mut checksum = 0i64;
        for i in 0..scan_iters {
            let low = ((i * 71) % rows) + 1;
            let high = (low + 700).min(rows);
            let s: i64 = conn.query_row(
                "SELECT SUM(value) FROM __sec_events WHERE id BETWEEN ?1 AND ?2",
                params![low, high],
                |r| r.get(0),
            )?;
            checksum ^= s;
        }
        if checksum == 0 {
            return Err(rusqlite::Error::ExecuteReturnedResults);
        }
    }
    let physical_scan = start_physical_scan.elapsed();

    let start_secure_scan = Instant::now();
    {
        let mut checksum = 0i64;
        for i in 0..scan_iters {
            let low = ((i * 71) % rows) + 1;
            let high = (low + 700).min(rows);
            let s: i64 = conn.query_row(
                "SELECT SUM(value) FROM events WHERE id BETWEEN ?1 AND ?2",
                params![low, high],
                |r| r.get(0),
            )?;
            checksum ^= s;
        }
        if checksum == 0 {
            return Err(rusqlite::Error::ExecuteReturnedResults);
        }
    }
    let secure_scan = start_secure_scan.elapsed();

    let start_refresh = Instant::now();
    for i in 0..refresh_iters {
        let role = if i % 2 == 0 { "admin" } else { "user" };
        let _: i64 = conn.query_row("SELECT sec_set_attr(?1, ?2)", params!["role", role], |r| {
            r.get(0)
        })?;
        let _: i64 = conn.query_row("SELECT sec_refresh_views()", [], |r| r.get(0))?;
    }
    let refresh_cycles = start_refresh.elapsed();

    Ok(SqlsecPerfSample {
        physical_point_reads,
        secure_point_reads,
        physical_scan,
        secure_scan,
        refresh_cycles,
    })
}

fn report_overhead(t: &mut TestRunner, label: &str, base: Duration, secured: Duration) {
    let base_ms = ms(base);
    let sec_ms = ms(secured);
    if base_ms <= f64::EPSILON {
        t.fail(label, &"baseline timing was zero");
        return;
    }
    let overhead_pct = ((sec_ms / base_ms) - 1.0) * 100.0;
    t.ok(&format!(
        "{label}: baseline={base_ms:.2}ms secured={sec_ms:.2}ms overhead={overhead_pct:+.2}%"
    ));
}

fn median_duration(mut durs: Vec<Duration>) -> Duration {
    durs.sort_unstable();
    durs[durs.len() / 2]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}
