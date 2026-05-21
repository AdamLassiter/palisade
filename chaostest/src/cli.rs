use std::time::Duration;

use crate::types::{AppResult, DEFAULT_SEED, FollowerWalSync, Scenario};

#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) mode: String,
    pub(crate) scenario: Scenario,
    pub(crate) duration: Duration,
    pub(crate) workers: usize,
    pub(crate) seed: u64,
    pub(crate) keep_artifacts: bool,
    pub(crate) include_known_gaps: bool,
    pub(crate) wal_sync: FollowerWalSync,
    pub(crate) tags: Vec<String>,
    pub(crate) report_json: Option<String>,
    pub(crate) report_junit: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: "debug".to_string(),
            scenario: Scenario::FollowerKill,
            duration: Duration::from_secs(5),
            workers: 4,
            seed: DEFAULT_SEED,
            keep_artifacts: false,
            include_known_gaps: false,
            wal_sync: FollowerWalSync::PerBatch,
            tags: Vec::new(),
            report_json: None,
            report_junit: None,
        }
    }
}

impl Config {
    pub(crate) fn parse(args: Vec<String>) -> AppResult<Self> {
        let mut cfg = Self::default();
        let mut i = 0usize;
        while i < args.len() {
            match args[i].as_str() {
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                "--debug" => cfg.mode = "debug".to_string(),
                "--release" => cfg.mode = "release".to_string(),
                "--scenario" => {
                    i += 1;
                    let value = args.get(i).ok_or("missing value for --scenario")?;
                    cfg.scenario = Scenario::parse(value)
                        .ok_or_else(|| format!("unknown scenario '{value}'"))?;
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
                "--keep-artifacts" => cfg.keep_artifacts = true,
                "--include-known-gaps" => cfg.include_known_gaps = true,
                "--tags" => {
                    i += 1;
                    cfg.tags = args
                        .get(i)
                        .ok_or("missing value for --tags")?
                        .split(',')
                        .filter(|tag| !tag.is_empty())
                        .map(str::to_string)
                        .collect();
                }
                "--ci" => cfg.tags = vec!["ci".to_string()],
                "--nightly" => cfg.tags = vec!["durability".to_string(), "security".to_string()],
                "--report-json" => {
                    i += 1;
                    cfg.report_json = Some(
                        args.get(i)
                            .ok_or("missing value for --report-json")?
                            .clone(),
                    );
                }
                "--report-junit" => {
                    i += 1;
                    cfg.report_junit = Some(
                        args.get(i)
                            .ok_or("missing value for --report-junit")?
                            .clone(),
                    );
                }
                "--cluster-follower-wal-sync" => {
                    i += 1;
                    let value = args
                        .get(i)
                        .ok_or("missing value for --cluster-follower-wal-sync")?;
                    cfg.wal_sync = FollowerWalSync::parse(value)
                        .ok_or_else(|| format!("unknown follower WAL sync mode '{value}'"))?;
                }
                other => return Err(format!("unknown option '{other}'").into()),
            }
            i += 1;
        }
        Ok(cfg)
    }
}

fn print_help() {
    println!("Usage: chaostest [options]");
    println!("  --debug | --release");
    println!(
        "  --scenario follower-kill|leader-kill|whole-process-restart|key-loss|sidecar-corrupt|all"
    );
    println!("  --duration-secs N");
    println!("  --workers N");
    println!("  --seed N");
    println!("  --keep-artifacts");
    println!("  --include-known-gaps");
    println!("  --tags ci,durability,security,known-gap");
    println!("  --ci");
    println!("  --nightly");
    println!("  --report-json PATH");
    println!("  --report-junit PATH");
    println!("  --cluster-follower-wal-sync per-batch|coalesced");
}
