use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub(crate) type AppResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(crate) const TENANTS: usize = 8;
pub(crate) const ACCOUNTS_PER_TENANT: usize = 24;
pub(crate) const INITIAL_BALANCE: i64 = 10_000;
pub(crate) const DEFAULT_SEED: u64 = 0xC0A5_7E57_D15C_A11E;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Scenario {
    FollowerKill,
    LeaderKill,
    WholeProcessRestart,
    KeyLoss,
    SidecarCorrupt,
    All,
}

impl Scenario {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "follower-kill" => Some(Self::FollowerKill),
            "leader-kill" => Some(Self::LeaderKill),
            "whole-process-restart" => Some(Self::WholeProcessRestart),
            "key-loss" => Some(Self::KeyLoss),
            "sidecar-corrupt" => Some(Self::SidecarCorrupt),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    pub(crate) fn runnable(self, include_known_gaps: bool) -> Vec<Self> {
        match self {
            Self::All => {
                let mut scenarios = vec![Self::FollowerKill, Self::KeyLoss, Self::SidecarCorrupt];
                if include_known_gaps {
                    scenarios.push(Self::LeaderKill);
                    scenarios.push(Self::WholeProcessRestart);
                }
                scenarios
            }
            other => vec![other],
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::FollowerKill => "follower-kill",
            Self::LeaderKill => "leader-kill",
            Self::WholeProcessRestart => "whole-process-restart",
            Self::KeyLoss => "key-loss",
            Self::SidecarCorrupt => "sidecar-corrupt",
            Self::All => "all",
        }
    }

    pub(crate) fn is_known_gap(self) -> bool {
        matches!(self, Self::LeaderKill | Self::WholeProcessRestart)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum FollowerWalSync {
    PerBatch,
    Coalesced,
}

impl FollowerWalSync {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "per-batch" | "per_batch" => Some(Self::PerBatch),
            "coalesced" => Some(Self::Coalesced),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::PerBatch => "per-batch",
            Self::Coalesced => "coalesced",
        }
    }
}

#[derive(Clone)]
pub(crate) struct LibPaths {
    pub(crate) sqlsec: PathBuf,
    pub(crate) sqlevfs: PathBuf,
}

#[derive(Clone, Debug)]
pub(crate) struct NodeConfig {
    pub(crate) node_id: u64,
    pub(crate) db_path: PathBuf,
    pub(crate) listen_addr: String,
    pub(crate) rpc_addr: String,
    pub(crate) raft_vfs_name: String,
}
