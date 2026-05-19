use std::time::Duration;

use crate::types::{AppResult, Config, Engine, SummaryOutput, WorkloadProfile};

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
}
