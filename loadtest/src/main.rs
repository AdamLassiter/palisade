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
use types::{AppResult, Oracle, ValidationReport, WorkerMetrics};
use util::print_metrics;
use validation::run_validation_with_retries;
use workload::run_workers;

fn main() {
    if let Err(err) = run() {
        eprintln!("loadtest failed: {err}");
        std::process::exit(1);
    }
}

fn run() -> AppResult<()> {
    let cfg = parse_args(env::args().skip(1).collect())?;
    let started = Instant::now();

    println!(
        "loadtest starting: mode={} engine={} duration={}s workers={} seed={:#x}",
        cfg.mode,
        cfg.engine,
        cfg.duration.as_secs(),
        cfg.workers,
        cfg.seed
    );

    println!("initialization: preparing runtime");
    let mut runtime = prepare_runtime(&cfg)?;
    let oracle = Arc::new(Mutex::new(Oracle::new()));
    let next_order_id = Arc::new(AtomicU64::new(1));
    let next_transfer_id = Arc::new(AtomicU64::new(1));
    let next_audit_id = Arc::new(AtomicU64::new(1));

    println!("initialization: seeding database");
    let seeded_orders = seed_database(&cfg, &mut runtime, &oracle, &next_order_id, &next_audit_id)?;
    println!(
        "seeded database at {} with {} initial orders",
        runtime.leader_db_path.display(),
        seeded_orders
    );

    let mut metrics = WorkerMetrics::default();
    if !cfg.validate_only {
        let run_metrics = run_workers(
            &cfg,
            &runtime,
            oracle.clone(),
            next_order_id.clone(),
            next_transfer_id.clone(),
            next_audit_id.clone(),
        )?;
        metrics.merge(&run_metrics);
        thread::sleep(Duration::from_millis(250));
        checkpoint_best_effort(&cfg, &runtime);
    }

    let mut report = ValidationReport::default();
    run_validation_with_retries(&cfg, &runtime, &oracle, &mut report)?;

    println!("\nValidation");
    for line in &report.checks {
        println!("  {line}");
    }

    let elapsed = started.elapsed();
    print_metrics(&cfg, &metrics, elapsed);

    if cfg.keep_artifacts {
        println!("\nArtifacts kept at {}", runtime.workspace_path.display());
    }

    Ok(())
}
