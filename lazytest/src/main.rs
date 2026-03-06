use std::{env, path::{Path, PathBuf}};

// mod evfs_backup_tests;
// mod evfs_crypto_tests;
// mod evfs_keyring_tests;
mod evfs_raft_tests;
mod evfs_vfs_tests;
mod helpers;
mod sqlshim_tests;

// use evfs_backup_tests::run_evfs_backup_tests;
// use evfs_crypto_tests::run_evfs_crypto_tests;
// use evfs_keyring_tests::run_evfs_keyring_tests;
use evfs_raft_tests::run_evfs_raft_tests;
use evfs_vfs_tests::run_evfs_vfs_tests;
use helpers::TestRunner;
use sqlshim_tests::run_sqlshim_tests;

fn main() {
    println!("=== LazySQL + EVFS Test Suite ===");

    let mode = match env::args().nth(1).as_deref() {
        Some("--debug") | None => "debug",
        Some("--release") => "release",
        Some(other) => {
            eprintln!("Usage: lazytest [--release|--debug]");
            eprintln!("Unknown option: {}", other);
            std::process::exit(1);
        }
    };

    println!("Running in {} mode...\n", mode);

    let mut t = TestRunner::new();

    let sqlsec_path = PathBuf::from(format!("../sqlsec/target/{mode}/libsqlsec.so"));

    if sqlsec_path.exists() {
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

    // run_evfs_crypto_tests(&mut t);
    // run_evfs_keyring_tests(&mut t);
    // run_evfs_backup_tests(&mut t);

    let evfs_path_str = format!("../sqlevfs/target/{}/libsqlevfs.so", mode);
    let evfs_path = Path::new(&evfs_path_str);

    if evfs_path.exists() {
        match run_evfs_vfs_tests(&mut t, mode) {
            Ok(()) => {}
            Err(e) => t.fail("evfs VFS test suite", &e),
        }
    } else {
        println!("\n⚠ Skipping EVFS VFS tests ({})", evfs_path.display());
    }

    run_evfs_raft_tests(&mut t);

    t.summary();

    if t.failed > 0 {
        std::process::exit(1);
    }
}
