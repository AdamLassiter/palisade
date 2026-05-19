use std::{
    collections::HashMap,
    fmt,
    path::PathBuf,
    sync::{Mutex, atomic::AtomicU64},
    time::{Duration, Instant},
};

use serde::Deserialize;
use tempfile::TempDir;

pub(crate) const TENANTS: usize = 8;
pub(crate) const ACCOUNTS_PER_TENANT: usize = 24;
pub(crate) const INITIAL_BALANCE: i64 = 10_000;
pub(crate) const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) type AppResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Engine {
    Sqlite,
    Secure,
    Cluster,
    All,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SummaryOutput {
    Workloads,
    Engines,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkloadProfile {
    Balanced,
    ReadHeavy,
    WriteHeavy,
    TransferHeavy,
    ScanHeavy,
    Contention,
    All,
}

impl WorkloadProfile {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::ReadHeavy => "read-heavy",
            Self::WriteHeavy => "write-heavy",
            Self::TransferHeavy => "transfer-heavy",
            Self::ScanHeavy => "scan-heavy",
            Self::Contention => "contention",
            Self::All => "all",
        }
    }

    pub(crate) fn description(self) -> &'static str {
        match self {
            Self::Balanced => "mixed reads, writes, transfers, and admin scans",
            Self::ReadHeavy => "tenant point/range reads with light writes",
            Self::WriteHeavy => "order creation/update pressure",
            Self::TransferHeavy => "multi-row transfer transactions",
            Self::ScanHeavy => "admin aggregate scans",
            Self::Contention => "hot-tenant writes and transfers",
            Self::All => "run every workload profile",
        }
    }

    pub(crate) fn runnable() -> &'static [Self] {
        &[
            Self::Balanced,
            Self::ReadHeavy,
            Self::WriteHeavy,
            Self::TransferHeavy,
            Self::ScanHeavy,
            Self::Contention,
        ]
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "balanced" => Some(Self::Balanced),
            "read-heavy" | "read_heavy" => Some(Self::ReadHeavy),
            "write-heavy" | "write_heavy" => Some(Self::WriteHeavy),
            "transfer-heavy" | "transfer_heavy" => Some(Self::TransferHeavy),
            "scan-heavy" | "scan_heavy" => Some(Self::ScanHeavy),
            "contention" => Some(Self::Contention),
            "all" => Some(Self::All),
            _ => None,
        }
    }
}

impl fmt::Display for WorkloadProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Engine {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Secure => "secure",
            Self::Cluster => "cluster",
            Self::All => "all",
        }
    }

    pub(crate) fn runnable() -> &'static [Self] {
        &[Self::Sqlite, Self::Secure, Self::Cluster]
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "sqlite" | "baseline" => Some(Self::Sqlite),
            "secure" => Some(Self::Secure),
            "cluster" => Some(Self::Cluster),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    pub(crate) fn uses_security(self) -> bool {
        !matches!(self, Self::Sqlite)
    }

    pub(crate) fn uses_evfs(self) -> bool {
        !matches!(self, Self::Sqlite)
    }

    pub(crate) fn uses_cluster(self) -> bool {
        matches!(self, Self::Cluster)
    }
}

impl fmt::Display for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl SummaryOutput {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "workloads" | "workload" => Some(Self::Workloads),
            "engines" | "engine" => Some(Self::Engines),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) mode: String,
    pub(crate) engine: Engine,
    pub(crate) workload: WorkloadProfile,
    pub(crate) duration: Duration,
    pub(crate) workers: usize,
    pub(crate) seed: u64,
    pub(crate) ramp: Duration,
    pub(crate) validate_only: bool,
    pub(crate) keep_artifacts: bool,
    pub(crate) output: Option<SummaryOutput>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: "debug".to_string(),
            engine: Engine::Cluster,
            workload: WorkloadProfile::Balanced,
            duration: Duration::from_secs(60),
            workers: 8,
            seed: 0x5EED_5EED_D15C_A11E,
            ramp: Duration::from_secs(5),
            validate_only: false,
            keep_artifacts: false,
            output: None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct LibPaths {
    pub(crate) sqlsec: PathBuf,
    pub(crate) sqlevfs: PathBuf,
}

#[derive(Clone)]
pub(crate) struct Labels {
    pub(crate) tenant_labels: Vec<i64>,
}

#[derive(Clone)]
pub(crate) struct NodeInfo {
    pub(crate) node_id: u64,
    pub(crate) db_path: PathBuf,
    pub(crate) listen_addr: String,
    pub(crate) rpc_addr: String,
    pub(crate) raft_vfs_name: String,
}

pub(crate) struct Runtime {
    pub(crate) workspace_path: PathBuf,
    pub(crate) _workspace_guard: Option<TempDir>,
    pub(crate) libs: LibPaths,
    pub(crate) leader_db_path: PathBuf,
    pub(crate) leader_raft_vfs_name: Option<String>,
    pub(crate) followers: Vec<NodeInfo>,
    pub(crate) labels: Labels,
    pub(crate) use_shim_syntax: bool,
}

#[derive(Clone, Copy)]
pub(crate) enum Role {
    User,
    Admin,
    Ops,
}

impl Role {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
            Self::Ops => "ops",
        }
    }
}

pub(crate) struct WorkerSpec {
    pub(crate) role: Role,
    pub(crate) tenant: Option<usize>,
}

#[derive(Default, Clone)]
pub(crate) struct WorkerMetrics {
    pub(crate) point_reads: u64,
    pub(crate) range_reads: u64,
    pub(crate) transfers_ok: u64,
    pub(crate) transfers_skipped: u64,
    pub(crate) orders_created: u64,
    pub(crate) order_updates: u64,
    pub(crate) admin_scans: u64,
    pub(crate) refreshes: u64,
    pub(crate) errors: u64,
    pub(crate) point_read_ns: u128,
    pub(crate) range_read_ns: u128,
    pub(crate) transfer_ns: u128,
    pub(crate) order_create_ns: u128,
    pub(crate) order_update_ns: u128,
    pub(crate) admin_scan_ns: u128,
}

impl WorkerMetrics {
    pub(crate) fn add_latency(target: &mut u128, started: Instant) {
        *target += started.elapsed().as_nanos();
    }

    pub(crate) fn merge(&mut self, other: &WorkerMetrics) {
        self.point_reads += other.point_reads;
        self.range_reads += other.range_reads;
        self.transfers_ok += other.transfers_ok;
        self.transfers_skipped += other.transfers_skipped;
        self.orders_created += other.orders_created;
        self.order_updates += other.order_updates;
        self.admin_scans += other.admin_scans;
        self.refreshes += other.refreshes;
        self.errors += other.errors;
        self.point_read_ns += other.point_read_ns;
        self.range_read_ns += other.range_read_ns;
        self.transfer_ns += other.transfer_ns;
        self.order_create_ns += other.order_create_ns;
        self.order_update_ns += other.order_update_ns;
        self.admin_scan_ns += other.admin_scan_ns;
    }
}

pub(crate) struct Oracle {
    pub(crate) balances: Vec<i64>,
    pub(crate) orders: HashMap<i64, String>,
    pub(crate) transfer_count: u64,
    pub(crate) audit_count: u64,
}

impl Oracle {
    pub(crate) fn new() -> Self {
        let mut balances = Vec::with_capacity(TENANTS * ACCOUNTS_PER_TENANT + 1);
        balances.push(0);
        for _ in 0..TENANTS * ACCOUNTS_PER_TENANT {
            balances.push(INITIAL_BALANCE);
        }

        Self {
            balances,
            orders: HashMap::new(),
            transfer_count: 0,
            audit_count: 0,
        }
    }

    pub(crate) fn record_seed_order(&mut self, order_id: i64, status: &str) {
        self.orders.insert(order_id, status.to_string());
    }

    pub(crate) fn record_transfer(&mut self, from_id: i64, to_id: i64, amount: i64) {
        self.balances[from_id as usize] -= amount;
        self.balances[to_id as usize] += amount;
        self.transfer_count += 1;
        self.audit_count += 1;
    }

    pub(crate) fn record_order_create(&mut self, order_id: i64) {
        self.orders.insert(order_id, "new".to_string());
        self.audit_count += 1;
    }

    pub(crate) fn record_order_transition(&mut self, order_id: i64, next: &'static str) {
        if let Some(state) = self.orders.get_mut(&order_id) {
            *state = next.to_string();
            self.audit_count += 1;
        }
    }

    pub(crate) fn expected_total_balance(&self) -> i64 {
        self.balances.iter().skip(1).sum()
    }
}

#[derive(Default)]
pub(crate) struct ValidationReport {
    pub(crate) checks: Vec<String>,
}

impl ValidationReport {
    pub(crate) fn ok(&mut self, msg: impl Into<String>) {
        self.checks.push(format!("PASS {}", msg.into()));
    }
}

#[derive(Deserialize)]
pub(crate) struct RaftStatusDoc {
    pub(crate) nodes: Vec<RaftNodeStatus>,
}

#[derive(Deserialize)]
pub(crate) struct RaftNodeStatus {
    pub(crate) node_id: u64,
    pub(crate) raft_vfs_name: String,
    #[serde(default)]
    pub(crate) committed_wal_offset: u64,
    pub(crate) leader_id: Option<u64>,
    pub(crate) is_leader: bool,
    pub(crate) voters: Vec<u64>,
    #[serde(default)]
    pub(crate) replay: RaftReplayStatus,
}

#[derive(Default, Deserialize)]
pub(crate) struct RaftReplayStatus {
    #[serde(default)]
    pub(crate) last_applied_offset: i64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Aggregate {
    pub(crate) account_count: i64,
    pub(crate) transfer_count: i64,
    pub(crate) order_count: i64,
    pub(crate) audit_count: i64,
    pub(crate) total_balance: i64,
    pub(crate) transfer_amount_sum: i64,
    pub(crate) balance_checksum: i64,
}

#[derive(Clone, Copy)]
pub(crate) enum ReadSurface {
    Physical,
}

#[derive(Clone)]
pub(crate) struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    pub(crate) fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    pub(crate) fn range(&mut self, upper: u64) -> u64 {
        self.next_u64() % upper.max(1)
    }
}

pub(crate) type SharedOracle = std::sync::Arc<Mutex<Oracle>>;
pub(crate) type SharedCounter = std::sync::Arc<AtomicU64>;
