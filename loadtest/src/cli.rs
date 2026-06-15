use std::time::Duration;

use crate::types::{
    AppResult,
    ClusterFollowerWalSync,
    ClusterRaftStorage,
    Config,
    Engine,
    SummaryOutput,
    WorkloadProfile,
};

pub(crate) fn parse_args(args: Vec<String>) -> AppResult<Config> {
    let mut cfg = Config::default();
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--mode" => {
                i += 1;
                cfg.mode = args.get(i).ok_or("missing value for --mode")?.clone();
                if cfg.mode != "debug" && cfg.mode != "release" {
                    return Err("mode must be 'debug' or 'release'".into());
                }
            }
            "--debug" => cfg.mode = "debug".to_string(),
            "--release" => cfg.mode = "release".to_string(),
            "--engine" => {
                i += 1;
                let value = args.get(i).ok_or("missing value for --engine")?;
                cfg.engine =
                    Engine::parse(value).ok_or_else(|| format!("unknown engine '{value}'"))?;
            }
            "--workload" | "--profile" => {
                i += 1;
                let value = args.get(i).ok_or("missing value for --workload")?;
                cfg.workload = WorkloadProfile::parse(value)
                    .ok_or_else(|| format!("unknown workload '{value}'"))?;
            }
            "--duration-secs" => {
                i += 1;
                cfg.duration = Duration::from_secs(
                    args.get(i)
                        .ok_or("missing value for --duration-secs")?
                        .parse()?,
                );
            }
            "--workers" => {
                i += 1;
                cfg.workers = args.get(i).ok_or("missing value for --workers")?.parse()?;
                if cfg.workers == 0 {
                    return Err("--workers must be > 0".into());
                }
            }
            "--seed" => {
                i += 1;
                cfg.seed = args.get(i).ok_or("missing value for --seed")?.parse()?;
            }
            "--ramp-secs" => {
                i += 1;
                cfg.ramp = Duration::from_secs(
                    args.get(i)
                        .ok_or("missing value for --ramp-secs")?
                        .parse()?,
                );
            }
            "--validate-only" => cfg.validate_only = true,
            "--keep-artifacts" => cfg.keep_artifacts = true,
            "--output" => {
                i += 1;
                let value = args.get(i).ok_or("missing value for --output")?;
                cfg.output = Some(
                    SummaryOutput::parse(value)
                        .ok_or_else(|| format!("unknown output '{value}'"))?,
                );
            }
            "--cluster-follower-wal-sync" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or("missing value for --cluster-follower-wal-sync")?;
                cfg.cluster_follower_wal_sync = ClusterFollowerWalSync::parse(value)
                    .ok_or_else(|| format!("unknown cluster follower WAL sync mode '{value}'"))?;
            }
            "--cluster-follower-wal-sync-batches" => {
                i += 1;
                cfg.cluster_follower_wal_sync_batches = args
                    .get(i)
                    .ok_or("missing value for --cluster-follower-wal-sync-batches")?
                    .parse()?;
                if cfg.cluster_follower_wal_sync_batches == 0 {
                    return Err("--cluster-follower-wal-sync-batches must be > 0".into());
                }
            }
            "--cluster-follower-wal-sync-ms" => {
                i += 1;
                cfg.cluster_follower_wal_sync_ms = args
                    .get(i)
                    .ok_or("missing value for --cluster-follower-wal-sync-ms")?
                    .parse()?;
                if cfg.cluster_follower_wal_sync_ms == 0 {
                    return Err("--cluster-follower-wal-sync-ms must be > 0".into());
                }
            }
            "--cluster-raft-storage" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or("missing value for --cluster-raft-storage")?;
                cfg.cluster_raft_storage = ClusterRaftStorage::parse(value)
                    .ok_or_else(|| format!("unknown cluster raft storage mode '{value}'"))?;
            }
            other => return Err(format!("unknown option '{other}'").into()),
        }
        i += 1;
    }
    Ok(cfg)
}

fn print_help() {
    println!("Usage: loadtest [options]");
    println!("  --debug | --release");
    println!("  --engine sqlite|secure|cluster|all");
    println!("    baseline is accepted as a deprecated alias for sqlite");
    println!(
        "  --workload balanced|read-heavy|write-heavy|transfer-heavy|scan-heavy|contention|all"
    );
    println!("  --duration-secs N");
    println!("  --workers N");
    println!("  --seed N");
    println!("  --ramp-secs N");
    println!("  --validate-only");
    println!("  --keep-artifacts");
    println!("  --output workloads|engines");
    println!("    controls roll-up orientation when --engine all and --workload all");
    println!("  --cluster-follower-wal-sync per-batch|coalesced");
    println!("  --cluster-follower-wal-sync-batches N");
    println!("  --cluster-follower-wal-sync-ms N");
    println!("  --cluster-raft-storage memory|persistent");
}

#[cfg(test)]
mod tests {
    use crate::{
        cli::parse_args,
        types::{ClusterRaftStorage, Engine},
    };

    #[test]
    fn default_cluster_raft_storage_is_memory() {
        let cfg = parse_args(vec![]).expect("parse default config");
        assert_eq!(cfg.engine, Engine::Cluster);
        assert_eq!(cfg.cluster_raft_storage, ClusterRaftStorage::Memory);
    }

    #[test]
    fn parses_persistent_cluster_raft_storage() {
        let cfg = parse_args(vec![
            "--cluster-raft-storage".to_string(),
            "persistent".to_string(),
        ])
        .expect("parse persistent storage mode");
        assert_eq!(cfg.cluster_raft_storage, ClusterRaftStorage::Persistent);
    }
}
