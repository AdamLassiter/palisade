use serde::{Deserialize, Serialize};

use crate::types::Scenario;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ScenarioReport {
    pub(crate) scenario: Scenario,
    pub(crate) status: ScenarioStatus,
    pub(crate) elapsed_ms: u64,
    pub(crate) steps: Vec<ScenarioStep>,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ScenarioStatus {
    Pass,
    Fail,
    KnownGap,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ScenarioStep {
    pub(crate) status: ScenarioStatus,
    pub(crate) message: String,
}

impl ScenarioStep {
    pub(crate) fn pass(message: impl ToString) -> Self {
        Self {
            status: ScenarioStatus::Pass,
            message: message.to_string(),
        }
    }

    pub(crate) fn known_gap(message: impl ToString) -> Self {
        Self {
            status: ScenarioStatus::KnownGap,
            message: message.to_string(),
        }
    }
}

pub(crate) fn print_scenario_report(report: &ScenarioReport) {
    palisade_log::section(format!("Scenario {}", report.scenario.as_str()));
    for step in &report.steps {
        println!("  {:<9} {}", status_label(&step.status), step.message);
    }
    if let Some(error) = &report.error {
        println!("  error     {error}");
    }
}

pub(crate) fn print_summary(reports: &[ScenarioReport]) {
    palisade_log::section("Summary");
    println!("  {:<24} {:<10} {:>10}", "scenario", "status", "elapsed");
    for report in reports {
        println!(
            "  {:<24} {:<10} {:>7.2}s",
            report.scenario.as_str(),
            status_label(&report.status),
            report.elapsed_ms as f64 / 1000.0
        );
    }
}

fn status_label(status: &ScenarioStatus) -> &'static str {
    match status {
        ScenarioStatus::Pass => "PASS",
        ScenarioStatus::Fail => "FAIL",
        ScenarioStatus::KnownGap => "KNOWN-GAP",
    }
}
