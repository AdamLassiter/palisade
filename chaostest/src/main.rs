mod child;
mod cli;
mod cluster;
mod db;
mod protocol;
mod report;
mod status;
mod supervisor;
mod types;
mod util;
mod workload;

use std::env;

use child::child_main;
use cli::Config;
use supervisor::Supervisor;
use types::AppResult;

fn main() {
    if let Err(err) = run() {
        palisade_log::fail(format!("chaostest failed: {err}"));
        std::process::exit(1);
    }
}

fn run() -> AppResult<()> {
    let raw_args = env::args().skip(1).collect::<Vec<_>>();
    if raw_args.iter().any(|arg| arg == "--node") {
        return child_main(raw_args);
    }

    let cfg = Config::parse(raw_args)?;
    let mut supervisor = Supervisor::new(cfg)?;
    let failed = supervisor.run()?;
    if failed {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{
        cli::Config,
        protocol::ChildRequest,
        report::{ScenarioReport, ScenarioStatus, ScenarioStep},
        types::Scenario,
    };

    #[test]
    fn config_defaults_to_follower_kill() {
        let cfg = Config::parse(vec![]).expect("parse");
        assert_eq!(cfg.scenario, Scenario::FollowerKill);
        assert_eq!(cfg.duration, Duration::from_secs(5));
        assert_eq!(cfg.workers, 4);
    }

    #[test]
    fn config_parses_scenario_and_known_gaps() {
        let cfg = Config::parse(vec![
            "--scenario".into(),
            "all".into(),
            "--include-known-gaps".into(),
            "--workers".into(),
            "2".into(),
        ])
        .expect("parse");
        assert_eq!(cfg.scenario, Scenario::All);
        assert!(cfg.include_known_gaps);
        assert_eq!(cfg.workers, 2);
    }

    #[test]
    fn child_command_json_round_trips() {
        let cmd = ChildRequest::RunWorkload {
            duration_secs: 1,
            workers: 2,
            seed: 42,
        };
        let json = serde_json::to_string(&cmd).expect("json");
        let parsed: ChildRequest = serde_json::from_str(&json).expect("parse");
        match parsed {
            ChildRequest::RunWorkload {
                duration_secs,
                workers,
                seed,
            } => {
                assert_eq!(duration_secs, 1);
                assert_eq!(workers, 2);
                assert_eq!(seed, 42);
            }
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn scenario_all_respects_known_gap_flag() {
        assert_eq!(
            Scenario::All.runnable(false),
            vec![
                Scenario::FollowerKill,
                Scenario::KeyLoss,
                Scenario::SidecarCorrupt
            ]
        );
        assert!(Scenario::All.runnable(true).contains(&Scenario::LeaderKill));
    }

    #[test]
    fn report_can_classify_known_gap() {
        let report = ScenarioReport {
            scenario: Scenario::LeaderKill,
            status: ScenarioStatus::KnownGap,
            elapsed_ms: 10,
            steps: vec![ScenarioStep::known_gap("gap")],
            error: Some("no persistent raft storage".to_string()),
        };
        let json = serde_json::to_string(&report).expect("json");
        assert!(json.contains("known-gap"));
    }
}
