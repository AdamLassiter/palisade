use std::time::Duration;

use crate::types::{AppResult, Config, Engine};

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
                cfg.engine = match args.get(i).ok_or("missing value for --engine")?.as_str() {
                    "baseline" => Engine::Baseline,
                    "secure" => Engine::Secure,
                    "cluster" => Engine::Cluster,
                    other => return Err(format!("unknown engine '{other}'").into()),
                };
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
            other => return Err(format!("unknown option '{other}'").into()),
        }
        i += 1;
    }
    Ok(cfg)
}

fn print_help() {
    println!("Usage: loadtest [options]");
    println!("  --debug | --release");
    println!("  --engine baseline|secure|cluster");
    println!("  --duration-secs N");
    println!("  --workers N");
    println!("  --seed N");
    println!("  --ramp-secs N");
    println!("  --validate-only");
    println!("  --keep-artifacts");
}
