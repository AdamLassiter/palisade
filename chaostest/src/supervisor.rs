use std::{
    env,
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use tempfile::{Builder, TempDir};

use crate::{
    cli::Config,
    cluster::ClusterSupervisor,
    db::make_node_configs,
    report::{
        ScenarioReport,
        ScenarioStatus,
        ScenarioStep,
        junit_xml,
        print_scenario_report,
        print_summary,
    },
    types::{AppResult, LibPaths, NodeConfig, Scenario},
    util::{evfs_keyring_path, node_artifacts, try_open_evfs_db},
};

pub(crate) struct Supervisor {
    cfg: Config,
    repo_root: PathBuf,
    workspace_root: PathBuf,
    workspace_path: PathBuf,
    _guard: Option<TempDir>,
    libs: LibPaths,
    nodes: Vec<NodeConfig>,
    reports: Vec<ScenarioReport>,
}

impl Supervisor {
    pub(crate) fn new(cfg: Config) -> AppResult<Self> {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or("chaostest manifest missing parent")?
            .to_path_buf();
        let libs = LibPaths {
            sqlsec: repo_root
                .join("target")
                .join(&cfg.mode)
                .join("libsqlsec.so"),
            sqlevfs: repo_root
                .join("target")
                .join(&cfg.mode)
                .join("libsqlevfs.so"),
        };
        if !libs.sqlsec.exists() {
            return Err(format!("missing sqlsec extension at {}", libs.sqlsec.display()).into());
        }
        if !libs.sqlevfs.exists() {
            return Err(format!("missing sqlevfs extension at {}", libs.sqlevfs.display()).into());
        }

        let (guard, workspace_path) = if cfg.keep_artifacts {
            let path = env::temp_dir().join(format!("palisade-chaostest-{}", std::process::id()));
            fs::create_dir_all(&path)?;
            (None, path)
        } else {
            let dir = Builder::new().prefix("palisade-chaostest-").tempdir()?;
            let path = dir.path().to_path_buf();
            (Some(dir), path)
        };

        let keyfile = workspace_path.join("evfs.key");
        fs::write(&keyfile, [0x42_u8; 32])?;
        unsafe {
            env::set_var("EVFS_KEYFILE", &keyfile);
        }

        let nodes = make_node_configs(&workspace_path)?;

        Ok(Self {
            cfg,
            repo_root,
            workspace_root: workspace_path.clone(),
            workspace_path,
            _guard: guard,
            libs,
            nodes,
            reports: Vec::new(),
        })
    }

    pub(crate) fn run(&mut self) -> AppResult<bool> {
        palisade_log::banner(
            "palisade chaostest",
            format!(
                "mode={} workspace={}",
                self.cfg.mode,
                self.workspace_path.display()
            ),
        );
        for scenario in self.selected_scenarios() {
            self.prepare_scenario_workspace(scenario)?;
            let report = self.run_one(scenario);
            print_scenario_report(&report);
            self.reports.push(report);
        }
        self.write_report_if_needed()?;
        print_summary(&self.reports);
        Ok(self
            .reports
            .iter()
            .any(|r| matches!(r.status, ScenarioStatus::Fail)))
    }

    fn selected_scenarios(&self) -> Vec<Scenario> {
        self.cfg
            .scenario
            .runnable(self.cfg.include_known_gaps)
            .into_iter()
            .filter(|scenario| {
                self.cfg.tags.is_empty() || self.cfg.tags.iter().any(|tag| scenario.has_tag(tag))
            })
            .collect()
    }

    fn prepare_scenario_workspace(&mut self, scenario: Scenario) -> AppResult<()> {
        let path = self.workspace_root.join(scenario.as_str());
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        let keyfile = path.join("evfs.key");
        fs::write(&keyfile, [0x42_u8; 32])?;
        unsafe {
            env::set_var("EVFS_KEYFILE", &keyfile);
        }
        self.workspace_path = path;
        self.nodes = make_node_configs(&self.workspace_path)?;
        Ok(())
    }

    fn run_one(&self, scenario: Scenario) -> ScenarioReport {
        let started = Instant::now();
        let mut steps = Vec::new();
        let result = match scenario {
            Scenario::FollowerKill => self.scenario_follower_kill(&mut steps),
            Scenario::KeyLoss => self.scenario_key_loss(&mut steps),
            Scenario::SidecarCorrupt => self.scenario_sidecar_corrupt(&mut steps),
            Scenario::LeaderKill => self.scenario_leader_kill(&mut steps),
            Scenario::WholeProcessRestart => self.scenario_whole_process_restart(&mut steps),
            Scenario::All => unreachable!(),
        };

        match result {
            Ok(status) => ScenarioReport {
                scenario,
                status,
                elapsed_ms: started.elapsed().as_millis() as u64,
                seed: self.cfg.seed,
                tags: scenario.tags().iter().map(|tag| tag.to_string()).collect(),
                artifact_dir: Some(self.workspace_path.display().to_string()),
                failure_point: Some(scenario.as_str().to_string()),
                expected: expected_result(scenario).to_string(),
                steps,
                error: None,
            },
            Err(err) if scenario.is_known_gap() => {
                steps.push(ScenarioStep::known_gap(format!(
                    "known durability gap observed: {err}"
                )));
                ScenarioReport {
                    scenario,
                    status: ScenarioStatus::KnownGap,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    seed: self.cfg.seed,
                    tags: scenario.tags().iter().map(|tag| tag.to_string()).collect(),
                    artifact_dir: Some(self.workspace_path.display().to_string()),
                    failure_point: Some(scenario.as_str().to_string()),
                    expected: expected_result(scenario).to_string(),
                    steps,
                    error: Some(err.to_string()),
                }
            }
            Err(err) => ScenarioReport {
                scenario,
                status: ScenarioStatus::Fail,
                elapsed_ms: started.elapsed().as_millis() as u64,
                seed: self.cfg.seed,
                tags: scenario.tags().iter().map(|tag| tag.to_string()).collect(),
                artifact_dir: Some(self.workspace_path.display().to_string()),
                failure_point: Some(scenario.as_str().to_string()),
                expected: expected_result(scenario).to_string(),
                steps,
                error: Some(err.to_string()),
            },
        }
    }

    fn scenario_follower_kill(&self, steps: &mut Vec<ScenarioStep>) -> AppResult<ScenarioStatus> {
        let mut cluster = self.start_cluster()?;
        steps.push(ScenarioStep::pass("cluster started"));
        cluster.seed(self.cfg.seed)?;
        steps.push(ScenarioStep::pass("seeded database"));
        cluster.run_workload(self.cfg.duration, self.cfg.workers, self.cfg.seed)?;
        steps.push(ScenarioStep::pass("baseline workload completed"));
        cluster.sync_keyrings()?;

        cluster.kill(2)?;
        steps.push(ScenarioStep::pass("killed follower node 2"));
        cluster.run_workload(self.cfg.duration, self.cfg.workers, self.cfg.seed ^ 0x51A7E)?;
        steps.push(ScenarioStep::pass(
            "continued writes while follower was down",
        ));
        cluster.restart(2)?;
        steps.push(ScenarioStep::pass("restarted follower node 2"));
        if let Err(err) = cluster.wait_converged(Duration::from_secs(15)) {
            let detail = cluster
                .convergence_diagnostics()
                .unwrap_or_else(|diag_err| format!("diagnostics unavailable: {diag_err}"));
            steps.push(ScenarioStep::known_gap(format!(
                "follower restart did not converge; persistent follower recovery is incomplete: {err}; {detail}"
            )));
            cluster.shutdown_all();
            return Ok(ScenarioStatus::KnownGap);
        }
        steps.push(ScenarioStep::pass("followers converged"));
        cluster.validate_all()?;
        steps.push(ScenarioStep::pass("cluster invariants validated"));
        cluster.shutdown_all();
        Ok(ScenarioStatus::Pass)
    }

    fn scenario_key_loss(&self, steps: &mut Vec<ScenarioStep>) -> AppResult<ScenarioStatus> {
        let mut cluster = self.start_cluster()?;
        cluster.seed(self.cfg.seed)?;
        cluster.run_workload(Duration::from_secs(1), 1, self.cfg.seed)?;
        cluster.shutdown_all();
        steps.push(ScenarioStep::pass("created encrypted database"));

        let original = self.workspace_path.join("evfs.key");
        fs::write(&original, [0x13_u8; 32])?;
        let err = try_open_evfs_db(&self.libs, &self.nodes[0].db_path)
            .expect_err("opening with wrong key should fail");
        steps.push(ScenarioStep::pass(format!("wrong key rejected: {err}")));
        Ok(ScenarioStatus::Pass)
    }

    fn scenario_sidecar_corrupt(&self, steps: &mut Vec<ScenarioStep>) -> AppResult<ScenarioStatus> {
        let mut cluster = self.start_cluster()?;
        cluster.seed(self.cfg.seed)?;
        cluster.run_workload(Duration::from_secs(1), 1, self.cfg.seed)?;
        cluster.shutdown_all();
        steps.push(ScenarioStep::pass("created encrypted database"));

        let keyring = evfs_keyring_path(&self.nodes[0].db_path);
        fs::write(&keyring, b"corrupt-keyring")?;
        let err = try_open_evfs_db(&self.libs, &self.nodes[0].db_path)
            .expect_err("opening with corrupt keyring should fail");
        steps.push(ScenarioStep::pass(format!(
            "corrupt keyring rejected: {err}"
        )));
        Ok(ScenarioStatus::Pass)
    }

    fn scenario_leader_kill(&self, steps: &mut Vec<ScenarioStep>) -> AppResult<ScenarioStatus> {
        let mut cluster = self.start_cluster()?;
        cluster.seed(self.cfg.seed)?;
        cluster.run_workload(Duration::from_secs(1), 1, self.cfg.seed)?;
        steps.push(ScenarioStep::pass(
            "seeded database and baseline workload completed",
        ));
        cluster.kill(1)?;
        steps.push(ScenarioStep::pass("killed leader node 1"));
        cluster.restart(1)?;
        steps.push(ScenarioStep::pass("restarted leader node 1"));
        let leader = cluster.wait_leader(Duration::from_secs(15))?;
        steps.push(ScenarioStep::pass(format!("node {leader} elected leader")));
        cluster.run_workload(Duration::from_secs(1), 1, self.cfg.seed ^ 0xDEAD)?;
        steps.push(ScenarioStep::pass("continued writes on new leader"));
        cluster.wait_converged(Duration::from_secs(15))?;
        steps.push(ScenarioStep::pass("surviving followers converged"));
        cluster.validate_all()?;
        steps.push(ScenarioStep::pass("cluster invariants validated"));
        cluster.shutdown_all();
        Ok(ScenarioStatus::Pass)
    }

    fn scenario_whole_process_restart(
        &self,
        steps: &mut Vec<ScenarioStep>,
    ) -> AppResult<ScenarioStatus> {
        let mut cluster = self.start_cluster()?;
        cluster.seed(self.cfg.seed)?;
        cluster.run_workload(Duration::from_secs(1), 1, self.cfg.seed)?;
        steps.push(ScenarioStep::pass(
            "seeded database and baseline workload completed",
        ));
        cluster.kill_all();
        steps.push(ScenarioStep::pass("killed all node processes"));
        cluster.restart_all()?;
        steps.push(ScenarioStep::pass("restarted all node processes"));
        let leader = cluster.wait_leader(Duration::from_secs(15))?;
        steps.push(ScenarioStep::pass(format!("node {leader} elected leader")));
        cluster.wait_converged(Duration::from_secs(15))?;
        steps.push(ScenarioStep::pass("followers converged after restart"));
        cluster.validate_all()?;
        steps.push(ScenarioStep::pass("cluster invariants validated"));
        cluster.shutdown_all();
        Ok(ScenarioStatus::Pass)
    }

    fn start_cluster(&self) -> AppResult<ClusterSupervisor> {
        self.reset_workspace()?;
        let mut cluster = ClusterSupervisor::new(
            self.repo_root.clone(),
            self.workspace_path.clone(),
            self.libs.clone(),
            self.nodes.clone(),
            self.cfg.mode.clone(),
            self.cfg.wal_sync,
        );
        cluster.start_all()?;
        cluster.add_followers()?;
        Ok(cluster)
    }

    fn reset_workspace(&self) -> AppResult<()> {
        fs::write(self.workspace_path.join("evfs.key"), [0x42_u8; 32])?;
        for node in &self.nodes {
            for path in node_artifacts(node) {
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => {
                        return Err(format!("failed to remove {}: {err}", path.display()).into());
                    }
                }
            }
        }
        Ok(())
    }

    fn write_report_if_needed(&self) -> AppResult<()> {
        if self.cfg.keep_artifacts
            || self
                .reports
                .iter()
                .any(|report| matches!(report.status, ScenarioStatus::Fail))
        {
            let path = self.workspace_path.join("chaostest-report.json");
            fs::write(&path, serde_json::to_vec_pretty(&self.reports)?)?;
            palisade_log::persist(format!("report {}", path.display()));
        }
        if let Some(path) = &self.cfg.report_json {
            fs::write(path, serde_json::to_vec_pretty(&self.reports)?)?;
            palisade_log::persist(format!("json report {path}"));
        }
        if let Some(path) = &self.cfg.report_junit {
            fs::write(path, junit_xml(&self.reports))?;
            palisade_log::persist(format!("junit report {path}"));
        }
        Ok(())
    }
}

fn expected_result(scenario: Scenario) -> &'static str {
    if scenario.is_known_gap() {
        "pass-or-known-gap"
    } else {
        "pass"
    }
}
