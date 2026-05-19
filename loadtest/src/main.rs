mod cli;
mod db;
mod runtime;
mod types;
mod util;
mod validation;
mod workload;

use std::{
    env,
    sync::{Arc, Mutex, atomic::AtomicU64},
    thread,
    time::{Duration, Instant},
};

use cli::parse_args;
use db::checkpoint_best_effort;
use runtime::{prepare_runtime, seed_database};
use types::{
    AppResult,
    Config,
    Engine,
    Oracle,
    SummaryOutput,
    ValidationReport,
    WorkerMetrics,
    WorkloadProfile,
};
use util::{
    BLUE,
    BOLD,
    CYAN,
    DIM,
    GREEN,
    RESET,
    Spinner,
    YELLOW,
    banner,
    fail,
    phase,
    print_metrics,
    print_validation,
    style,
    success,
};
use validation::run_validation_with_retries;
use workload::run_workers;

fn main() {
    if let Err(err) = run() {
        fail(format!("loadtest failed: {err}"));
        std::process::exit(1);
    }
}

fn run() -> AppResult<()> {
    let cfg = parse_args(env::args().skip(1).collect())?;

    match (
        cfg.engine == Engine::All,
        cfg.workload == WorkloadProfile::All,
    ) {
        (false, false) => {
            let _ = run_one(cfg)?;
            Ok(())
        }
        (false, true) => run_all_workloads_for_engine(&cfg),
        (true, false) => run_all_engines_for_workload(&cfg),
        (true, true) => run_all_engines_and_workloads(&cfg),
    }
}

fn run_one(cfg: Config) -> AppResult<ProfileSummary> {
    if cfg.engine == Engine::All || cfg.workload == WorkloadProfile::All {
        return Err("run_one requires a concrete engine and workload".into());
    }

    let started = Instant::now();
    banner(&cfg);

    phase("preparing runtime");
    let mut runtime = prepare_runtime(&cfg)?;
    let oracle = Arc::new(Mutex::new(Oracle::new()));
    let next_order_id = Arc::new(AtomicU64::new(1));
    let next_transfer_id = Arc::new(AtomicU64::new(1));
    let next_audit_id = Arc::new(AtomicU64::new(1));

    phase("seeding database");
    let seeded_orders = seed_database(&cfg, &mut runtime, &oracle, &next_order_id, &next_audit_id)?;
    success(format!(
        "seeded database at {} with {} initial orders",
        runtime.leader_db_path.display(),
        seeded_orders
    ));

    let mut metrics = WorkerMetrics::default();
    let mut workload_elapsed = Duration::ZERO;
    if !cfg.validate_only {
        let spinner = Spinner::start(workload_run_label(&cfg, &runtime));
        let workload_started = Instant::now();
        let run_metrics = run_workers(
            &cfg,
            &runtime,
            oracle.clone(),
            next_order_id.clone(),
            next_transfer_id.clone(),
            next_audit_id.clone(),
        )?;
        workload_elapsed = workload_started.elapsed();
        spinner.finish("workload complete");
        metrics.merge(&run_metrics);
        thread::sleep(Duration::from_millis(250));
        checkpoint_best_effort(&cfg, &runtime);
    }

    let spinner = Spinner::start("validating database and replicas");
    let validation_started = Instant::now();
    let mut report = ValidationReport::default();
    run_validation_with_retries(&cfg, &runtime, &oracle, &mut report)?;
    let validation_elapsed = validation_started.elapsed();
    spinner.finish("validation complete");

    print_validation(&report.checks);

    let elapsed = started.elapsed();
    print_metrics(
        &cfg,
        &metrics,
        elapsed,
        workload_elapsed,
        validation_elapsed,
    );

    if cfg.keep_artifacts {
        println!("\nArtifacts kept at {}", runtime.workspace_path.display());
    }

    Ok(ProfileSummary {
        engine: cfg.engine,
        workload: cfg.workload,
        metrics,
        workload_elapsed,
        validation_elapsed,
    })
}

fn workload_run_label(cfg: &Config, runtime: &types::Runtime) -> String {
    let mut label = format!(
        "running workload={} engine={} workers={} duration={:.2}s ramp={:.2}s seed={:#x} db={}",
        cfg.workload,
        cfg.engine,
        cfg.workers,
        cfg.duration.as_secs_f64(),
        cfg.ramp.as_secs_f64(),
        cfg.seed,
        runtime.leader_db_path.display()
    );
    if cfg.engine.uses_cluster() {
        label.push_str(&format!(" followers={}", runtime.followers.len()));
    }
    label
}

fn run_all_workloads_for_engine(cfg: &Config) -> AppResult<()> {
    let started = Instant::now();
    let mut summaries = Vec::new();
    phase(format!(
        "running all workload profiles with engine={} workers={} duration={}s",
        cfg.engine,
        cfg.workers,
        cfg.duration.as_secs()
    ));

    for workload in WorkloadProfile::runnable() {
        let mut profile_cfg = cfg.clone();
        profile_cfg.workload = *workload;
        summaries.push(run_one(profile_cfg)?);
    }

    print_workload_summary(&summaries, started.elapsed(), Some(cfg.engine));
    Ok(())
}

fn run_all_engines_for_workload(cfg: &Config) -> AppResult<()> {
    let started = Instant::now();
    let mut summaries = Vec::new();
    phase(format!(
        "running all engines with workload={} workers={} duration={}s",
        cfg.workload,
        cfg.workers,
        cfg.duration.as_secs()
    ));

    for engine in Engine::runnable() {
        let mut engine_cfg = cfg.clone();
        engine_cfg.engine = *engine;
        summaries.push(run_one(engine_cfg)?);
    }

    print_engine_summary(&summaries, started.elapsed(), Some(cfg.workload));
    Ok(())
}

fn run_all_engines_and_workloads(cfg: &Config) -> AppResult<()> {
    match summary_output(cfg) {
        SummaryOutput::Workloads => run_matrix_by_engine(cfg),
        SummaryOutput::Engines => run_matrix_by_workload(cfg),
    }
}

fn run_matrix_by_engine(cfg: &Config) -> AppResult<()> {
    let started = Instant::now();
    let mut all_summaries = Vec::new();
    phase(format!(
        "running all engines and all workload profiles grouped by engine workers={} duration={}s",
        cfg.workers,
        cfg.duration.as_secs()
    ));

    for engine in Engine::runnable() {
        let mut summaries = Vec::new();
        for workload in WorkloadProfile::runnable() {
            let mut profile_cfg = cfg.clone();
            profile_cfg.engine = *engine;
            profile_cfg.workload = *workload;
            let summary = run_one(profile_cfg)?;
            summaries.push(summary.clone());
            all_summaries.push(summary);
        }
        print_workload_summary(&summaries, Duration::ZERO, Some(*engine));
    }

    print_matrix_total(&all_summaries, started.elapsed());
    Ok(())
}

fn run_matrix_by_workload(cfg: &Config) -> AppResult<()> {
    let started = Instant::now();
    let mut all_summaries = Vec::new();
    phase(format!(
        "running all engines and all workload profiles grouped by workload workers={} duration={}s",
        cfg.workers,
        cfg.duration.as_secs()
    ));

    for workload in WorkloadProfile::runnable() {
        let mut summaries = Vec::new();
        for engine in Engine::runnable() {
            let mut profile_cfg = cfg.clone();
            profile_cfg.engine = *engine;
            profile_cfg.workload = *workload;
            let summary = run_one(profile_cfg)?;
            summaries.push(summary.clone());
            all_summaries.push(summary);
        }
        print_engine_summary(&summaries, Duration::ZERO, Some(*workload));
    }

    print_matrix_total(&all_summaries, started.elapsed());
    Ok(())
}

fn summary_output(cfg: &Config) -> SummaryOutput {
    cfg.output.unwrap_or(
        match (
            cfg.engine == Engine::All,
            cfg.workload == WorkloadProfile::All,
        ) {
            (true, false) => SummaryOutput::Engines,
            (false, true) => SummaryOutput::Workloads,
            (true, true) => SummaryOutput::Workloads,
            (false, false) => SummaryOutput::Workloads,
        },
    )
}

#[derive(Clone)]
struct ProfileSummary {
    engine: Engine,
    workload: WorkloadProfile,
    metrics: WorkerMetrics,
    workload_elapsed: Duration,
    validation_elapsed: Duration,
}

fn print_workload_summary(summaries: &[ProfileSummary], elapsed: Duration, engine: Option<Engine>) {
    let title = match engine {
        Some(engine) => format!("All Workloads (engine={engine})"),
        None => "All Workloads".to_string(),
    };
    print_summary(summaries, elapsed, &title, "workload", |summary| {
        summary.workload.to_string()
    });
}

fn print_engine_summary(
    summaries: &[ProfileSummary],
    elapsed: Duration,
    workload: Option<WorkloadProfile>,
) {
    let title = match workload {
        Some(workload) => format!("All Engines (workload={workload})"),
        None => "All Engines".to_string(),
    };
    print_summary(summaries, elapsed, &title, "engine", |summary| {
        summary.engine.to_string()
    });
}

fn print_summary(
    summaries: &[ProfileSummary],
    elapsed: Duration,
    title: &str,
    label: &str,
    label_value: impl Fn(&ProfileSummary) -> String,
) {
    println!("\n{}{}{title}{}", style(BOLD), style(CYAN), style(RESET));
    if elapsed > Duration::ZERO {
        println!(
            "  {}elapsed{}: {:.2}s",
            style(DIM),
            style(RESET),
            elapsed.as_secs_f64()
        );
    }
    println!(
        "{}{}{}",
        style(DIM),
        format!(
            "  {:<16} {:>10} {:>10} {:>10} {:>8} {:>8} {:>8} {:>10} {:>12}",
            label,
            "ops/sec",
            "read/sec",
            "write/sec",
            "ops",
            "locks",
            "writes",
            "workload",
            "validation"
        ),
        style(RESET)
    );
    for summary in summaries {
        let ops = total_ops(&summary.metrics);
        let read_ops = read_ops(&summary.metrics);
        let writes = summary.metrics.transfers_ok
            + summary.metrics.transfers_skipped
            + summary.metrics.orders_created
            + summary.metrics.order_updates;
        let lock_conflicts = summary.metrics.lock_conflicts();
        let label = left_cell(&label_value(summary), 16, CYAN);
        let ops_per_sec = right_cell(
            &format!(
                "{:.2}",
                ops as f64 / summary.workload_elapsed.as_secs_f64().max(0.001)
            ),
            10,
            GREEN,
        );
        let read_ops_per_sec = right_cell(
            &format!(
                "{:.2}",
                read_ops as f64 / summary.workload_elapsed.as_secs_f64().max(0.001)
            ),
            10,
            CYAN,
        );
        let write_ops_per_sec = right_cell(
            &format!(
                "{:.2}",
                writes as f64 / summary.workload_elapsed.as_secs_f64().max(0.001)
            ),
            10,
            BLUE,
        );
        let ops = right_cell(&ops.to_string(), 8, GREEN);
        let lock_conflicts = right_cell(
            &lock_conflicts.to_string(),
            8,
            if lock_conflicts == 0 { GREEN } else { YELLOW },
        );
        let writes = right_cell(&writes.to_string(), 8, BLUE);
        let workload_elapsed = right_cell(
            &format!("{:.2}s", summary.workload_elapsed.as_secs_f64()),
            10,
            YELLOW,
        );
        let validation_elapsed = right_cell(
            &format!("{:.2}s", summary.validation_elapsed.as_secs_f64()),
            12,
            YELLOW,
        );
        println!(
            "  {label} {ops_per_sec} {read_ops_per_sec} {write_ops_per_sec} {ops} {lock_conflicts} {writes} {workload_elapsed} {validation_elapsed}"
        );
    }
}

fn print_matrix_total(summaries: &[ProfileSummary], elapsed: Duration) {
    let total_ops = summaries
        .iter()
        .map(|summary| total_ops(&summary.metrics))
        .sum::<u64>();
    let lock_conflicts = summaries
        .iter()
        .map(|summary| summary.metrics.lock_conflicts())
        .sum::<u64>();
    println!(
        "\n{}{}All Engines + Workloads{}",
        style(BOLD),
        style(CYAN),
        style(RESET)
    );
    println!(
        "  {}elapsed{}: {:.2}s",
        style(DIM),
        style(RESET),
        elapsed.as_secs_f64()
    );
    println!("  {}runs{}: {}", style(DIM), style(RESET), summaries.len());
    println!("  {}total ops{}: {total_ops}", style(DIM), style(RESET));
    println!(
        "  {}lock/busy conflicts{}: {lock_conflicts}",
        style(DIM),
        style(RESET)
    );
}

fn left_cell(value: &str, width: usize, color: &'static str) -> String {
    left_cell_styled(value, width, style(color), style(RESET))
}

fn right_cell(value: &str, width: usize, color: &'static str) -> String {
    right_cell_styled(value, width, style(color), style(RESET))
}

fn left_cell_styled(value: &str, width: usize, start: &str, end: &str) -> String {
    let padding = width.saturating_sub(value.len());
    format!("{}{}{}{}", start, value, end, " ".repeat(padding))
}

fn right_cell_styled(value: &str, width: usize, start: &str, end: &str) -> String {
    let padding = width.saturating_sub(value.len());
    format!("{}{}{}{}", " ".repeat(padding), start, value, end)
}

fn total_ops(metrics: &WorkerMetrics) -> u64 {
    read_ops(metrics)
        + metrics.transfers_ok
        + metrics.transfers_skipped
        + metrics.orders_created
        + metrics.order_updates
}

fn read_ops(metrics: &WorkerMetrics) -> u64 {
    metrics.point_reads + metrics.range_reads + metrics.admin_scans
}

#[cfg(test)]
mod tests {
    use super::{left_cell_styled, right_cell_styled};

    fn strip_ansi(input: &str) -> String {
        let mut out = String::new();
        let mut chars = input.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\x1b' && chars.peek() == Some(&'[') {
                chars.next();
                for next in chars.by_ref() {
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(ch);
            }
        }
        out
    }

    #[test]
    fn left_cells_keep_rhs_padding_outside_color() {
        for workload in ["balanced", "scan-heavy", "transfer-heavy"] {
            let cell = left_cell_styled(workload, 16, "\x1b[36m", "\x1b[0m");
            assert!(cell.ends_with(' ') || workload.len() >= 16);
            assert_eq!(strip_ansi(&cell), format!("{workload:<16}"));
        }
    }

    #[test]
    fn right_cells_keep_lhs_padding_outside_color() {
        let cell = right_cell_styled("135.19", 10, "\x1b[32m", "\x1b[0m");
        assert!(cell.starts_with("    \x1b[32m"));
        assert_eq!(strip_ansi(&cell), format!("{:>10}", "135.19"));
    }
}
