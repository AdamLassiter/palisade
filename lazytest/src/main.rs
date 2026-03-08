use std::{
    env,
    path::{Path, PathBuf},
};

mod evfs_raft_perf_tests;
mod evfs_raft_tests;
mod evfs_vfs_tests;
mod helpers;
mod sec_tests;
mod shim_tests;
mod sqlevfs_perf_tests;
mod sqlsec_perf_tests;
mod sqlshim_perf_tests;

use evfs_raft_perf_tests::run_evfs_raft_perf_tests;
use evfs_raft_tests::run_evfs_raft_tests;
use evfs_vfs_tests::run_evfs_vfs_tests;
use helpers::TestRunner;
use sec_tests::run_sqlsec_tests;
use shim_tests::run_sqlshim_tests;
use sqlevfs_perf_tests::run_evfs_perf_tests;
use sqlsec_perf_tests::run_sqlsec_perf_tests;
use sqlshim_perf_tests::{run_sqlshim_perf_child, run_sqlshim_perf_tests};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "--perf-sqlshim-child") {
        if let Err(e) = run_sqlshim_perf_child() {
            eprintln!("sqlshim perf child failed: {e}");
            std::process::exit(1);
        }
        return;
    }

    println!("=== LazySQL + EVFS Test Suite ===");

    let mut mode = "debug";
    let mut run_perf = false;
    let mut perf_only = false;

    for arg in &args {
        match arg.as_str() {
            "--debug" => mode = "debug",
            "--release" => mode = "release",
            "--perf" => run_perf = true,
            "--perf-only" => {
                run_perf = true;
                perf_only = true;
            }
            "--help" | "-h" => {
                println!("Usage: lazytest [--release|--debug] [--perf|--perf-only]");
                std::process::exit(0);
            }
            other => {
                eprintln!("Usage: lazytest [--release|--debug] [--perf|--perf-only]");
                eprintln!("Unknown option: {}", other);
                std::process::exit(1);
            }
        }
    }

    println!("Running in {} mode...\n", mode);

    let mut t = TestRunner::new();

    if !perf_only {
        let sqlsec_path = PathBuf::from(format!("../sqlsec/target/{mode}/libsqlsec.so"));

        if sqlsec_path.exists() {
            match run_sqlsec_tests(&mut t, mode) {
                Ok(()) => {}
                Err(e) => t.fail("sqlsec function-call test suite", &e),
            }
            match run_sqlshim_tests(&mut t, mode) {
                Ok(()) => {}
                Err(e) => t.fail("sqlshim test suite", &e),
            }
        } else {
            println!(
                "\n⚠ Skipping sqlshim/sqlsec tests ({})",
                sqlsec_path.display()
            );
        }

        let evfs_path_str = format!("../sqlevfs/target/{}/libsqlevfs.so", mode);
        let evfs_path = Path::new(&evfs_path_str);

        if evfs_path.exists() {
            match run_evfs_vfs_tests(&mut t, mode) {
                Ok(()) => {}
                Err(e) => t.fail("evfs VFS test suite", &e),
            }
            if !run_perf {
                match run_evfs_raft_tests(&mut t, mode) {
                    Ok(()) => {}
                    Err(e) => t.fail("evfs raft test suite", &e),
                }
            }
        } else {
            println!("\n⚠ Skipping EVFS VFS tests ({})", evfs_path.display());
        }
    }

    if run_perf {
        match run_evfs_raft_perf_tests(&mut t, mode) {
            Ok(()) => {}
            Err(e) => t.fail("sqlevfs raft performance suite", &e),
        }
        match run_evfs_perf_tests(&mut t, mode) {
            Ok(()) => {}
            Err(e) => t.fail("sqlevfs performance suite", &e),
        }
        match run_sqlshim_perf_tests(&mut t, mode) {
            Ok(()) => {}
            Err(e) => t.fail("sqlshim performance suite", &e),
        }
        match run_sqlsec_perf_tests(&mut t, mode) {
            Ok(()) => {}
            Err(e) => t.fail("sqlsec performance suite", &e),
        }
        if !perf_only {
            match run_evfs_raft_tests(&mut t, mode) {
                Ok(()) => {}
                Err(e) => t.fail("evfs raft test suite", &e),
            }
        }
    }

    t.summary();

    if t.failed > 0 {
        std::process::exit(1);
    }
}
