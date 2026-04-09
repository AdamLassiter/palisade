use std::{
    collections::HashMap,
    env,
    fmt,
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        Arc,
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::Deserialize;
use tempfile::{Builder, TempDir};

const TENANTS: usize = 8;
const ACCOUNTS_PER_TENANT: usize = 24;
const INITIAL_BALANCE: i64 = 10_000;
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(15);

type AppResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Engine {
    Baseline,
    Secure,
    Cluster,
}

impl Engine {
    fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Secure => "secure",
            Self::Cluster => "cluster",
        }
    }

    fn uses_security(self) -> bool {
        !matches!(self, Self::Baseline)
    }

    fn uses_evfs(self) -> bool {
        !matches!(self, Self::Baseline)
    }

    fn uses_cluster(self) -> bool {
        matches!(self, Self::Cluster)
    }
}

impl fmt::Display for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug)]
struct Config {
    mode: String,
    engine: Engine,
    duration: Duration,
    workers: usize,
    seed: u64,
    ramp: Duration,
    validate_only: bool,
    keep_artifacts: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: "debug".to_string(),
            engine: Engine::Cluster,
            duration: Duration::from_secs(60),
            workers: 8,
            seed: 0x5EED_5EED_D15C_A11E,
            ramp: Duration::from_secs(5),
            validate_only: false,
            keep_artifacts: false,
        }
    }
}

#[derive(Clone)]
struct LibPaths {
    sqlsec: PathBuf,
    sqlevfs: PathBuf,
}

#[derive(Clone)]
struct Labels {
    tenant_labels: Vec<i64>,
}

#[derive(Clone)]
struct NodeInfo {
    node_id: u64,
    db_path: PathBuf,
    // Raw host:port used by the local gRPC server bind.
    listen_addr: String,
    // URI-form endpoint used by Raft gRPC clients.
    rpc_addr: String,
    raft_vfs_name: String,
}

struct Runtime {
    workspace_path: PathBuf,
    _workspace_guard: Option<TempDir>,
    libs: LibPaths,
    leader_db_path: PathBuf,
    followers: Vec<NodeInfo>,
    labels: Labels,
    use_shim_syntax: bool,
}

#[derive(Clone, Copy)]
enum Role {
    User,
    Admin,
    Ops,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
            Self::Ops => "ops",
        }
    }
}

struct WorkerSpec {
    role: Role,
    tenant: Option<usize>,
}

#[derive(Default, Clone)]
struct WorkerMetrics {
    point_reads: u64,
    range_reads: u64,
    transfers_ok: u64,
    transfers_skipped: u64,
    orders_created: u64,
    order_updates: u64,
    admin_scans: u64,
    refreshes: u64,
    errors: u64,
    point_read_ns: u128,
    range_read_ns: u128,
    transfer_ns: u128,
    order_create_ns: u128,
    order_update_ns: u128,
    admin_scan_ns: u128,
}

impl WorkerMetrics {
    fn add_latency(target: &mut u128, started: Instant) {
        *target += started.elapsed().as_nanos();
    }

    fn merge(&mut self, other: &WorkerMetrics) {
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

struct Oracle {
    balances: Vec<i64>,
    orders: HashMap<i64, String>,
    transfer_count: u64,
    audit_count: u64,
}

impl Oracle {
    fn new() -> Self {
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

    fn record_seed_order(&mut self, order_id: i64, status: &str) {
        self.orders.insert(order_id, status.to_string());
    }

    fn record_transfer(&mut self, from_id: i64, to_id: i64, amount: i64) {
        self.balances[from_id as usize] -= amount;
        self.balances[to_id as usize] += amount;
        self.transfer_count += 1;
        self.audit_count += 1;
    }

    fn record_order_create(&mut self, order_id: i64) {
        self.orders.insert(order_id, "new".to_string());
        self.audit_count += 1;
    }

    fn record_order_transition(&mut self, order_id: i64, next: &'static str) {
        if let Some(state) = self.orders.get_mut(&order_id) {
            *state = next.to_string();
            self.audit_count += 1;
        }
    }

    fn expected_total_balance(&self) -> i64 {
        self.balances.iter().skip(1).sum()
    }
}

#[derive(Default)]
struct ValidationReport {
    checks: Vec<String>,
}

impl ValidationReport {
    fn ok(&mut self, msg: impl Into<String>) {
        self.checks.push(format!("PASS {}", msg.into()));
    }
}

#[derive(Deserialize)]
struct RaftStatusDoc {
    nodes: Vec<RaftNodeStatus>,
}

#[derive(Deserialize)]
struct RaftNodeStatus {
    node_id: u64,
    leader_id: Option<u64>,
    is_leader: bool,
    voters: Vec<u64>,
}

#[derive(Clone, Copy)]
struct Aggregate {
    account_count: i64,
    transfer_count: i64,
    order_count: i64,
    audit_count: i64,
    total_balance: i64,
    transfer_amount_sum: i64,
    balance_checksum: i64,
}

#[derive(Clone, Copy)]
enum ReadSurface {
    Physical,
}

#[derive(Clone)]
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn range(&mut self, upper: u64) -> u64 {
        self.next_u64() % upper.max(1)
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("loadtest failed: {err}");
        std::process::exit(1);
    }
}

fn run() -> AppResult<()> {
    let cfg = parse_args(env::args().skip(1).collect())?;
    let started = Instant::now();

    println!(
        "loadtest starting: mode={} engine={} duration={}s workers={} seed={:#x}",
        cfg.mode,
        cfg.engine,
        cfg.duration.as_secs(),
        cfg.workers,
        cfg.seed
    );

    println!("initialization: preparing runtime");
    let mut runtime = prepare_runtime(&cfg)?;
    let oracle = Arc::new(Mutex::new(Oracle::new()));
    let next_order_id = Arc::new(AtomicU64::new(1));
    let next_transfer_id = Arc::new(AtomicU64::new(1));
    let next_audit_id = Arc::new(AtomicU64::new(1));

    println!("initialization: seeding database");
    let seeded_orders = seed_database(&cfg, &mut runtime, &oracle, &next_order_id, &next_audit_id)?;
    println!(
        "seeded database at {} with {} initial orders",
        runtime.leader_db_path.display(),
        seeded_orders
    );

    let mut metrics = WorkerMetrics::default();
    if !cfg.validate_only {
        let run_metrics = run_workers(
            &cfg,
            &runtime,
            oracle.clone(),
            next_order_id.clone(),
            next_transfer_id.clone(),
            next_audit_id.clone(),
        )?;
        metrics.merge(&run_metrics);
        thread::sleep(Duration::from_millis(250));
        checkpoint_best_effort(&cfg, &runtime);
    }

    let mut report = ValidationReport::default();
    run_validation_with_retries(&cfg, &runtime, &oracle, &mut report)?;

    println!("\nValidation");
    for line in &report.checks {
        println!("  {line}");
    }

    let elapsed = started.elapsed();
    print_metrics(&cfg, &metrics, elapsed);

    if cfg.keep_artifacts {
        println!("\nArtifacts kept at {}", runtime.workspace_path.display());
    }

    Ok(())
}

fn parse_args(args: Vec<String>) -> AppResult<Config> {
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

fn prepare_runtime(cfg: &Config) -> AppResult<Runtime> {
    println!("initialization: resolving repo paths and extension libraries");
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("loadtest manifest missing parent")?
        .to_path_buf();
    let libs = LibPaths {
        sqlsec: repo_root
            .join("sqlsec")
            .join("target")
            .join(&cfg.mode)
            .join("libsqlsec.so"),
        sqlevfs: repo_root
            .join("sqlevfs")
            .join("target")
            .join(&cfg.mode)
            .join("libsqlevfs.so"),
    };

    if cfg.engine.uses_security() && !libs.sqlsec.exists() {
        return Err(format!("missing sqlsec extension at {}", libs.sqlsec.display()).into());
    }
    if cfg.engine.uses_evfs() && !libs.sqlevfs.exists() {
        return Err(format!("missing sqlevfs extension at {}", libs.sqlevfs.display()).into());
    }
    if cfg.engine.uses_security() {
        println!("initialization: sqlsec -> {}", libs.sqlsec.display());
    }
    if cfg.engine.uses_evfs() {
        println!("initialization: sqlevfs -> {}", libs.sqlevfs.display());
    }

    let (workspace_guard, workspace_path) = if cfg.keep_artifacts {
        let path = std::env::temp_dir().join(format!(
            "palisade-loadtest-{}-{}",
            cfg.engine.as_str(),
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        (None, path)
    } else {
        let dir = Builder::new().prefix("palisade-loadtest-").tempdir()?;
        let path = dir.path().to_path_buf();
        (Some(dir), path)
    };
    println!("initialization: workspace {}", workspace_path.display());

    if cfg.engine.uses_evfs() {
        let path = workspace_path.join("evfs.key");
        fs::write(&path, [0x42_u8; 32])?;
        unsafe {
            env::set_var("EVFS_KEYFILE", &path);
        }
        println!("initialization: wrote keyfile {}", path.display());
    }

    if cfg.engine.uses_evfs() {
        println!("initialization: registering EVFS bootstrap connection");
        prepare_evfs_registration(&libs.sqlevfs)?;
    }

    let use_shim_syntax = env::var("LD_PRELOAD")
        .ok()
        .map(|v| v.contains("libsqlshim"))
        .unwrap_or(false);
    println!(
        "initialization: sqlshim preload {}",
        if use_shim_syntax {
            "detected"
        } else {
            "not detected"
        }
    );

    let leader_db_path = workspace_path.join("leader.db");
    let followers = if cfg.engine.uses_cluster() {
        println!("initialization: building raft cluster");
        build_cluster(&libs, &leader_db_path, &workspace_path)?
    } else {
        Vec::new()
    };
    println!("initialization: leader db {}", leader_db_path.display());
    if !followers.is_empty() {
        println!("initialization: follower count {}", followers.len());
    }

    let labels = Labels {
        tenant_labels: vec![0; TENANTS],
    };

    Ok(Runtime {
        workspace_path,
        _workspace_guard: workspace_guard,
        libs,
        leader_db_path,
        followers,
        labels,
        use_shim_syntax,
    })
}

fn prepare_evfs_registration(sqlevfs_path: &Path) -> AppResult<()> {
    println!(
        "initialization: loading sqlevfs from {}",
        sqlevfs_path.display()
    );
    let conn = Connection::open(":memory:")?;
    load_sqlevfs_on_conn(&conn, sqlevfs_path)?;
    Ok(())
}

fn sync_cluster_keyrings(runtime: &Runtime) -> AppResult<()> {
    let leader_sidecar = evfs_keyring_path(&runtime.leader_db_path);
    if !leader_sidecar.exists() {
        return Err(format!(
            "leader keyring sidecar missing after seed: {}",
            leader_sidecar.display()
        )
        .into());
    }

    for follower in &runtime.followers {
        fs::copy(&leader_sidecar, evfs_keyring_path(&follower.db_path))?;
    }
    println!("initialization: mirrored leader keyring sidecar to followers");
    Ok(())
}

fn build_cluster(
    libs: &LibPaths,
    leader_db_path: &Path,
    workspace_path: &Path,
) -> AppResult<Vec<NodeInfo>> {
    println!("initialization: allocating raft listener addresses");
    let leader_addr = ephemeral_addr()?;
    let follower_2_addr = ephemeral_addr()?;
    let follower_3_addr = ephemeral_addr()?;
    let leader_rpc_addr = grpc_uri(&leader_addr);
    let follower_2_rpc_addr = grpc_uri(&follower_2_addr);
    let follower_3_rpc_addr = grpc_uri(&follower_3_addr);
    println!("initialization: node 1 listen_addr {leader_addr}");
    println!("initialization: node 1 rpc_addr {leader_rpc_addr}");
    println!("initialization: node 2 listen_addr {follower_2_addr}");
    println!("initialization: node 2 rpc_addr {follower_2_rpc_addr}");
    println!("initialization: node 3 listen_addr {follower_3_addr}");
    println!("initialization: node 3 rpc_addr {follower_3_rpc_addr}");

    let nodes = vec![
        NodeInfo {
            node_id: 1,
            db_path: leader_db_path.to_path_buf(),
            listen_addr: leader_addr.clone(),
            rpc_addr: leader_rpc_addr.clone(),
            raft_vfs_name: "evfs_raft_node1".to_string(),
        },
        NodeInfo {
            node_id: 2,
            db_path: workspace_path.join("node2.db"),
            listen_addr: follower_2_addr.clone(),
            rpc_addr: follower_2_rpc_addr.clone(),
            raft_vfs_name: "evfs_raft_node2".to_string(),
        },
        NodeInfo {
            node_id: 3,
            db_path: workspace_path.join("node3.db"),
            listen_addr: follower_3_addr.clone(),
            rpc_addr: follower_3_rpc_addr.clone(),
            raft_vfs_name: "evfs_raft_node3".to_string(),
        },
    ];

    println!("initialization: opening leader control connection");
    let leader_control = open_evfs_control_conn(leader_db_path, libs)?;
    let peers_leader = "{}";
    println!("initialization: starting raft node 1");
    leader_control.query_row::<String, _, _>(
        "SELECT evfs_raft_init(?1, ?2, ?3, 'evfs', ?4)",
        params![1_i64, &leader_addr, peers_leader, &nodes[0].raft_vfs_name],
        |r| r.get(0),
    )?;
    println!("initialization: waiting for leader election");
    wait_for_leader(&leader_control, 1, Duration::from_secs(5))?;
    println!("initialization: node 1 elected leader");

    for node in nodes.iter().skip(1) {
        println!(
            "initialization: opening follower control node={} db={}",
            node.node_id,
            node.db_path.display()
        );
        let conn = open_evfs_control_conn(&node.db_path, libs)?;
        let peers_json = serde_json::to_string(&HashMap::from([
            (1_u64, leader_rpc_addr.clone()),
            (
                if node.node_id == 2 { 3_u64 } else { 2_u64 },
                if node.node_id == 2 {
                    follower_3_rpc_addr.clone()
                } else {
                    follower_2_rpc_addr.clone()
                },
            ),
        ]))?;
        println!("initialization: starting follower node {}", node.node_id);
        conn.query_row::<String, _, _>(
            "SELECT evfs_raft_init(?1, ?2, ?3, 'evfs', ?4)",
            params![
                node.node_id as i64,
                &node.listen_addr,
                peers_json,
                &node.raft_vfs_name
            ],
            |r| r.get(0),
        )?;
    }

    for node in nodes.iter().skip(1) {
        println!(
            "initialization: adding node {} to membership via {}",
            node.node_id, node.rpc_addr
        );
        leader_control.query_row::<String, _, _>(
            "SELECT evfs_raft_add_node(?1, ?2, 10)",
            params![node.node_id as i64, &node.rpc_addr],
            |r| r.get(0),
        )?;
    }

    println!("initialization: waiting for voter set [1, 2, 3]");
    wait_for_voters(&leader_control, &[1, 2, 3], Duration::from_secs(10))?;
    println!("initialization: raft cluster ready");
    Ok(nodes.into_iter().skip(1).collect())
}

fn seed_database(
    cfg: &Config,
    runtime: &mut Runtime,
    oracle: &Arc<Mutex<Oracle>>,
    next_order_id: &Arc<AtomicU64>,
    next_audit_id: &Arc<AtomicU64>,
) -> AppResult<u64> {
    println!("initialization: opening writer connection");
    let conn = open_writer_conn(cfg, runtime)?;
    println!("initialization: configuring setup pragmas");
    configure_setup_conn(&conn)?;

    println!("initialization: creating schema");
    let labels = create_schema(cfg, runtime, &conn)?;
    runtime.labels = labels.clone();
    println!(
        "initialization: ready with {} tenant labels",
        runtime.labels.tenant_labels.len()
    );

    let physical_accounts = table_name(cfg.engine, "accounts", ReadSurface::Physical);
    let physical_orders = table_name(cfg.engine, "orders", ReadSurface::Physical);
    let physical_audit = table_name(cfg.engine, "audit_log", ReadSurface::Physical);

    println!("initialization: inserting seed rows");
    let tx = conn.unchecked_transaction()?;
    let seeded_orders = {
        let mut ins_account = tx.prepare(&format!(
            "INSERT INTO {physical_accounts}
             (id, tenant, balance, status, secret_note, row_label_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        ))?;

        let mut ins_order = tx.prepare(&format!(
            "INSERT INTO {physical_orders}
             (id, tenant, account_id, amount, status, row_label_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        ))?;

        let mut ins_audit = tx.prepare(&format!(
            "INSERT INTO {physical_audit}
             (id, tenant, actor_role, action, ref_id, ts, detail, row_label_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
        ))?;

        let mut seeded_orders = 0_u64;
        let mut oracle_guard = oracle.lock().map_err(|_| "oracle lock poisoned")?;
        for tenant_idx in 0..TENANTS {
            let tenant = tenant_name(tenant_idx);
            for account_offset in 0..ACCOUNTS_PER_TENANT {
                let account_id = account_id_for(tenant_idx, account_offset);
                ins_account.execute(params![
                    account_id,
                    tenant,
                    INITIAL_BALANCE,
                    "open",
                    format!("secret-note-{tenant}-acct-{account_offset:02}"),
                    runtime.labels.tenant_labels[tenant_idx],
                ])?;

                if account_offset % 3 == 0 {
                    let order_id = next_order_id.fetch_add(1, Ordering::Relaxed) as i64;
                    ins_order.execute(params![
                        order_id,
                        tenant,
                        account_id,
                        10 + account_offset as i64,
                        "new",
                        runtime.labels.tenant_labels[tenant_idx],
                    ])?;
                    oracle_guard.record_seed_order(order_id, "new");
                    seeded_orders += 1;
                }

                let audit_id = next_audit_id.fetch_add(1, Ordering::Relaxed) as i64;
                ins_audit.execute(params![
                    audit_id,
                    tenant,
                    "system",
                    "seed_account",
                    account_id,
                    audit_id,
                    format!("seeded account {account_id}"),
                    runtime.labels.tenant_labels[tenant_idx],
                ])?;
                oracle_guard.audit_count += 1;
            }
        }
        seeded_orders
    };
    tx.commit()?;
    println!("initialization: seed transaction committed");
    if cfg.engine.uses_cluster() {
        sync_cluster_keyrings(runtime)?;
    }
    Ok(seeded_orders)
}

fn run_workers(
    cfg: &Config,
    runtime: &Runtime,
    oracle: Arc<Mutex<Oracle>>,
    next_order_id: Arc<AtomicU64>,
    next_transfer_id: Arc<AtomicU64>,
    next_audit_id: Arc<AtomicU64>,
) -> AppResult<WorkerMetrics> {
    let end_at = Instant::now() + cfg.duration;
    let mut joins = Vec::with_capacity(cfg.workers);

    for worker_id in 0..cfg.workers {
        let worker_cfg = cfg.clone();
        let labels = runtime.labels.clone();
        let leader_db_path = runtime.leader_db_path.clone();
        let raft_vfs = if cfg.engine.uses_cluster() {
            Some("evfs_raft_node1".to_string())
        } else {
            None
        };
        let worker_oracle = oracle.clone();
        let worker_next_order_id = next_order_id.clone();
        let worker_next_transfer_id = next_transfer_id.clone();
        let worker_next_audit_id = next_audit_id.clone();

        joins.push(thread::spawn(move || -> AppResult<WorkerMetrics> {
            let spec = worker_spec(worker_id);
            let mut rng = SimpleRng::new(worker_cfg.seed ^ ((worker_id as u64 + 1) * 0x9E37));
            let conn = open_worker_conn(&worker_cfg, &leader_db_path, raft_vfs.as_deref())?;
            configure_worker_conn(&conn)?;

            let mut metrics = WorkerMetrics::default();
            let effective_ramp = if worker_cfg.ramp > worker_cfg.duration {
                Duration::from_secs_f64(worker_cfg.duration.as_secs_f64() / 2.0)
            } else {
                worker_cfg.ramp
            };
            if effective_ramp.as_millis() > 0 {
                let stagger_ms = effective_ramp.as_millis() as u64 * worker_id as u64
                    / worker_cfg.workers as u64;
                thread::sleep(Duration::from_millis(stagger_ms));
            }

            let physical_accounts =
                table_name(worker_cfg.engine, "accounts", ReadSurface::Physical);
            let physical_orders = table_name(worker_cfg.engine, "orders", ReadSurface::Physical);
            let physical_transfers =
                table_name(worker_cfg.engine, "transfers", ReadSurface::Physical);
            let physical_audit = table_name(worker_cfg.engine, "audit_log", ReadSurface::Physical);

            while Instant::now() < end_at {
                let choice = rng.range(100);
                let step = (|| -> AppResult<()> {
                    match spec.role {
                    Role::User if choice < 45 => {
                        let started = Instant::now();
                        let account_id = random_account_id(&mut rng, spec.tenant.expect("user tenant"));
                        let _: Option<i64> = conn
                            .query_row(
                                &format!("SELECT balance FROM {physical_accounts} WHERE id = ?1"),
                                [account_id],
                                |r| r.get(0),
                            )
                            .optional()?;
                        metrics.point_reads += 1;
                        WorkerMetrics::add_latency(&mut metrics.point_read_ns, started);
                    }
                    Role::User if choice < 65 => {
                        let started = Instant::now();
                        let tenant = tenant_name(spec.tenant.expect("user tenant"));
                        let _: i64 = conn.query_row(
                            &format!(
                                "SELECT COALESCE(SUM(amount), 0) FROM {physical_orders}
                                 WHERE tenant = ?1 AND account_id BETWEEN ?2 AND ?3"
                            ),
                            params![tenant, account_id_for(spec.tenant.unwrap(), 0), account_id_for(spec.tenant.unwrap(), ACCOUNTS_PER_TENANT - 1)],
                            |r| r.get(0),
                        )?;
                        metrics.range_reads += 1;
                        WorkerMetrics::add_latency(&mut metrics.range_read_ns, started);
                    }
                    Role::User if choice < 88 => {
                        let started = Instant::now();
                        let tenant_idx = spec.tenant.expect("user tenant");
                        let from_id = random_account_id(&mut rng, tenant_idx);
                        let mut to_id = random_account_id(&mut rng, tenant_idx);
                        if to_id == from_id {
                            to_id = account_id_for(tenant_idx, (account_index_for(from_id) + 1) % ACCOUNTS_PER_TENANT);
                        }
                        let amount = (rng.range(97) + 1) as i64;
                        let ts = worker_next_transfer_id.load(Ordering::Relaxed) as i64;
                        match conn.unchecked_transaction() {
                            Ok(tx) => {
                                let from_balance: i64 = tx.query_row(
                                    &format!("SELECT balance FROM {physical_accounts} WHERE id = ?1"),
                                    [from_id],
                                    |r| r.get(0),
                                )?;
                                if from_balance >= amount {
                                    tx.execute(
                                        &format!(
                                            "UPDATE {physical_accounts}
                                             SET balance = balance - ?1
                                             WHERE id = ?2"
                                        ),
                                        params![amount, from_id],
                                    )?;
                                    tx.execute(
                                        &format!(
                                            "UPDATE {physical_accounts}
                                             SET balance = balance + ?1
                                             WHERE id = ?2"
                                        ),
                                        params![amount, to_id],
                                    )?;
                                    let transfer_id =
                                        worker_next_transfer_id.fetch_add(1, Ordering::Relaxed) as i64;
                                    let audit_id =
                                        worker_next_audit_id.fetch_add(1, Ordering::Relaxed) as i64;
                                    tx.execute(
                                        &format!(
                                            "INSERT INTO {physical_transfers}
                                             (id, tenant, from_account_id, to_account_id, amount, ts, row_label_id)
                                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
                                        ),
                                        params![
                                            transfer_id,
                                            tenant_name(tenant_idx),
                                            from_id,
                                            to_id,
                                            amount,
                                            ts,
                                            labels.tenant_labels[tenant_idx]
                                        ],
                                    )?;
                                    tx.execute(
                                        &format!(
                                            "INSERT INTO {physical_audit}
                                             (id, tenant, actor_role, action, ref_id, ts, detail, row_label_id)
                                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
                                        ),
                                        params![
                                            audit_id,
                                            tenant_name(tenant_idx),
                                            "user",
                                            "transfer",
                                            transfer_id,
                                            ts,
                                            format!("transfer {amount} from {from_id} to {to_id}"),
                                            labels.tenant_labels[tenant_idx]
                                        ],
                                    )?;
                                    tx.commit()?;
                                    let mut guard =
                                        worker_oracle.lock().map_err(|_| "oracle lock poisoned")?;
                                    guard.record_transfer(from_id, to_id, amount);
                                    metrics.transfers_ok += 1;
                                } else {
                                    tx.rollback()?;
                                    metrics.transfers_skipped += 1;
                                }
                            }
                            Err(_) => {
                                metrics.errors += 1;
                            }
                        }
                        WorkerMetrics::add_latency(&mut metrics.transfer_ns, started);
                    }
                    Role::User if choice < 96 => {
                        let started = Instant::now();
                        let tenant_idx = spec.tenant.expect("user tenant");
                        let account_id = random_account_id(&mut rng, tenant_idx);
                        let order_id = worker_next_order_id.fetch_add(1, Ordering::Relaxed) as i64;
                        let audit_id = worker_next_audit_id.fetch_add(1, Ordering::Relaxed) as i64;
                        let amount = (rng.range(180) + 20) as i64;
                        let tx = conn.unchecked_transaction()?;
                        tx.execute(
                            &format!(
                                "INSERT INTO {physical_orders}
                                 (id, tenant, account_id, amount, status, row_label_id)
                                 VALUES (?1, ?2, ?3, ?4, 'new', ?5)"
                            ),
                            params![
                                order_id,
                                tenant_name(tenant_idx),
                                account_id,
                                amount,
                                labels.tenant_labels[tenant_idx]
                            ],
                        )?;
                        tx.execute(
                            &format!(
                                "INSERT INTO {physical_audit}
                                 (id, tenant, actor_role, action, ref_id, ts, detail, row_label_id)
                                 VALUES (?1, ?2, 'user', 'create_order', ?3, ?4, ?5, ?6)"
                            ),
                            params![
                                audit_id,
                                tenant_name(tenant_idx),
                                order_id,
                                order_id,
                                format!("created order {order_id}"),
                                labels.tenant_labels[tenant_idx]
                            ],
                        )?;
                        tx.commit()?;
                        worker_oracle
                            .lock()
                            .map_err(|_| "oracle lock poisoned")?
                            .record_order_create(order_id);
                        metrics.orders_created += 1;
                        WorkerMetrics::add_latency(&mut metrics.order_create_ns, started);
                    }
                    Role::User => {
                        let started = Instant::now();
                        let tenant_idx = spec.tenant.expect("user tenant");
                        let max_order_id = worker_next_order_id.load(Ordering::Relaxed) as i64 - 1;
                        if max_order_id > 0 {
                            let candidate = (rng.range(max_order_id as u64) + 1) as i64;
                            if let Some((from, to)) = transition_for_rng(&mut rng) {
                                let tx = conn.unchecked_transaction()?;
                                let changed = tx.execute(
                                    &format!(
                                        "UPDATE {physical_orders}
                                         SET status = ?1
                                         WHERE id = ?2 AND tenant = ?3 AND status = ?4"
                                    ),
                                    params![to, candidate, tenant_name(tenant_idx), from],
                                )?;
                                if changed == 1 {
                                    let audit_id =
                                        worker_next_audit_id.fetch_add(1, Ordering::Relaxed) as i64;
                                    tx.execute(
                                        &format!(
                                            "INSERT INTO {physical_audit}
                                             (id, tenant, actor_role, action, ref_id, ts, detail, row_label_id)
                                             VALUES (?1, ?2, 'user', 'advance_order', ?3, ?4, ?5, ?6)"
                                        ),
                                        params![
                                            audit_id,
                                            tenant_name(tenant_idx),
                                            candidate,
                                            candidate,
                                            format!("transitioned order {candidate} to {to}"),
                                            labels.tenant_labels[tenant_idx]
                                        ],
                                    )?;
                                    tx.commit()?;
                                    worker_oracle
                                        .lock()
                                        .map_err(|_| "oracle lock poisoned")?
                                        .record_order_transition(candidate, to);
                                    metrics.order_updates += 1;
                                } else {
                                    tx.rollback()?;
                                }
                            }
                        }
                        WorkerMetrics::add_latency(&mut metrics.order_update_ns, started);
                    }
                    _ => {
                        let started = Instant::now();
                        let _: i64 = conn.query_row(
                            &format!(
                                "SELECT COUNT(*) FROM {physical_orders}
                                 WHERE status IN ('new', 'approved', 'settled')"
                            ),
                            [],
                            |r| r.get(0),
                        )?;
                        metrics.admin_scans += 1;
                        WorkerMetrics::add_latency(&mut metrics.admin_scan_ns, started);
                    }
                    }
                    Ok(())
                })();

                if let Err(err) = step {
                    let msg = err.to_string();
                    if msg.contains("locked") || msg.contains("busy") {
                        metrics.errors += 1;
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    return Err(err);
                }
            }

            Ok(metrics)
        }));
    }

    let mut merged = WorkerMetrics::default();
    for join in joins {
        let worker_metrics = join.join().map_err(|_| "worker thread panicked")??;
        merged.merge(&worker_metrics);
    }
    Ok(merged)
}

fn validate_database(
    cfg: &Config,
    runtime: &Runtime,
    oracle: &Arc<Mutex<Oracle>>,
    report: &mut ValidationReport,
) -> AppResult<()> {
    let leader_conn = open_validation_conn(cfg, runtime, true)?;
    let expected = oracle.lock().map_err(|_| "oracle lock poisoned")?;
    let actual = collect_aggregate(&leader_conn, cfg.engine)?;

    let expected_accounts = (TENANTS * ACCOUNTS_PER_TENANT) as i64;
    if actual.account_count != expected_accounts {
        return Err(format!(
            "account count mismatch: expected {expected_accounts}, got {}",
            actual.account_count
        )
        .into());
    }
    report.ok(format!("account count = {}", actual.account_count));

    if actual.total_balance != expected.expected_total_balance() {
        return Err(format!(
            "total balance mismatch: expected {}, got {}",
            expected.expected_total_balance(),
            actual.total_balance
        )
        .into());
    }
    report.ok(format!(
        "total balance conserved at {}",
        actual.total_balance
    ));

    if actual.transfer_count != expected.transfer_count as i64 {
        return Err(format!(
            "transfer count mismatch: expected {}, got {}",
            expected.transfer_count, actual.transfer_count
        )
        .into());
    }
    report.ok(format!("transfer row count = {}", actual.transfer_count));

    if actual.audit_count != expected.audit_count as i64 {
        return Err(format!(
            "audit count mismatch: expected {}, got {}",
            expected.audit_count, actual.audit_count
        )
        .into());
    }
    report.ok(format!("audit row count = {}", actual.audit_count));
    drop(leader_conn);

    let validation_conn = open_validation_conn(cfg, runtime, true)?;
    let negative_balances: i64 = validation_conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM {} WHERE balance < 0",
            table_name(cfg.engine, "accounts", ReadSurface::Physical)
        ),
        [],
        |r| r.get(0),
    )?;
    if negative_balances != 0 {
        return Err(format!("found {negative_balances} negative balances").into());
    }
    report.ok("no negative balances");

    validate_order_states(&validation_conn, cfg.engine, &expected.orders)?;
    report.ok(format!("validated {} order states", expected.orders.len()));

    drop(expected);

    if cfg.engine.uses_evfs() {
        validate_ciphertext(&runtime.leader_db_path)?;
        report.ok("evfs ciphertext sanity check passed");
    }

    if cfg.engine.uses_cluster() {
        validate_cluster(cfg, runtime, actual)?;
        report.ok("raft convergence and follower write rejection passed");
    }

    Ok(())
}

fn run_validation_with_retries(
    cfg: &Config,
    runtime: &Runtime,
    oracle: &Arc<Mutex<Oracle>>,
    report: &mut ValidationReport,
) -> AppResult<()> {
    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    for _ in 0..10 {
        let mut candidate = ValidationReport::default();
        match validate_database(cfg, runtime, oracle, &mut candidate) {
            Ok(()) => {
                *report = candidate;
                return Ok(());
            }
            Err(err) => {
                let msg = err.to_string();
                if msg.contains("locked") || msg.contains("busy") {
                    last_err = Some(err);
                    thread::sleep(Duration::from_millis(250));
                    continue;
                }
                return Err(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| "validation failed".into()))
}

fn validate_order_states(
    conn: &Connection,
    engine: Engine,
    expected_orders: &HashMap<i64, String>,
) -> AppResult<()> {
    let physical_orders = table_name(engine, "orders", ReadSurface::Physical);
    let mut stmt = conn.prepare(&format!(
        "SELECT id, status FROM {physical_orders} ORDER BY id"
    ))?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
    let actual: HashMap<i64, String> = rows.collect::<Result<_, _>>()?;
    if actual != *expected_orders {
        return Err("order state map mismatch".into());
    }
    Ok(())
}

fn validate_ciphertext(db_path: &Path) -> AppResult<()> {
    let raw = fs::read(db_path)?;
    if raw.len() < 16 || &raw[..16] != b"SQLite format 3\0" {
        return Err("sqlite header missing from raw file".into());
    }
    let raw_str = String::from_utf8_lossy(&raw);
    for needle in ["secret-note-", "created order", "transitioned order"] {
        if raw_str.contains(needle) {
            return Err(format!("plaintext marker '{needle}' found in raw encrypted file").into());
        }
    }
    Ok(())
}

fn validate_cluster(cfg: &Config, runtime: &Runtime, leader_actual: Aggregate) -> AppResult<()> {
    wait_for_replica_match(cfg, runtime, leader_actual)?;

    for follower in &runtime.followers {
        let before = collect_aggregate(&open_cluster_replica_conn(cfg, runtime, follower, true)?, cfg.engine)?;
        let follower_conn = open_cluster_replica_raft_conn(follower)?;
        let _ = follower_conn.execute_batch(&format!(
            "BEGIN IMMEDIATE;
             UPDATE {} SET balance = balance + 1 WHERE id = 1;
             COMMIT;",
            table_name(cfg.engine, "accounts", ReadSurface::Physical)
        ));
        let after = collect_aggregate(&open_cluster_replica_conn(cfg, runtime, follower, true)?, cfg.engine)?;
        if !same_aggregate(before, after) {
            return Err(format!(
                "follower {} unexpectedly changed state after a write attempt",
                follower.node_id
            )
            .into());
        }
    }

    Ok(())
}

fn wait_for_replica_match(
    cfg: &Config,
    runtime: &Runtime,
    leader_actual: Aggregate,
) -> AppResult<()> {
    let deadline = Instant::now() + CONVERGENCE_TIMEOUT;
    loop {
        let mut all_match = true;
        for follower in &runtime.followers {
            let conn = open_cluster_replica_conn(cfg, runtime, follower, true)?;
            let agg = collect_aggregate(&conn, cfg.engine)?;
            if !same_aggregate(leader_actual, agg) {
                all_match = false;
                break;
            }
        }
        if all_match {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for followers to match leader aggregates".into());
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn same_aggregate(a: Aggregate, b: Aggregate) -> bool {
    a.account_count == b.account_count
        && a.transfer_count == b.transfer_count
        && a.order_count == b.order_count
        && a.audit_count == b.audit_count
        && a.total_balance == b.total_balance
        && a.transfer_amount_sum == b.transfer_amount_sum
        && a.balance_checksum == b.balance_checksum
}

fn collect_aggregate(conn: &Connection, engine: Engine) -> AppResult<Aggregate> {
    let physical_accounts = table_name(engine, "accounts", ReadSurface::Physical);
    let physical_orders = table_name(engine, "orders", ReadSurface::Physical);
    let physical_transfers = table_name(engine, "transfers", ReadSurface::Physical);
    let physical_audit = table_name(engine, "audit_log", ReadSurface::Physical);

    Ok(Aggregate {
        account_count: conn.query_row(
            &format!("SELECT COUNT(*) FROM {physical_accounts}"),
            [],
            |r| r.get(0),
        )?,
        transfer_count: conn.query_row(
            &format!("SELECT COUNT(*) FROM {physical_transfers}"),
            [],
            |r| r.get(0),
        )?,
        order_count: conn.query_row(
            &format!("SELECT COUNT(*) FROM {physical_orders}"),
            [],
            |r| r.get(0),
        )?,
        audit_count: conn.query_row(
            &format!("SELECT COUNT(*) FROM {physical_audit}"),
            [],
            |r| r.get(0),
        )?,
        total_balance: conn.query_row(
            &format!("SELECT COALESCE(SUM(balance), 0) FROM {physical_accounts}"),
            [],
            |r| r.get(0),
        )?,
        transfer_amount_sum: conn.query_row(
            &format!("SELECT COALESCE(SUM(amount), 0) FROM {physical_transfers}"),
            [],
            |r| r.get(0),
        )?,
        balance_checksum: conn.query_row(
            &format!("SELECT COALESCE(SUM(id * balance), 0) FROM {physical_accounts}"),
            [],
            |r| r.get(0),
        )?,
    })
}

fn create_schema(cfg: &Config, runtime: &Runtime, conn: &Connection) -> AppResult<Labels> {
    if cfg.engine.uses_security() {
        println!("initialization: loading sqlsec extension");
        load_sqlsec_on_conn(conn, &runtime.libs.sqlsec)?;
        println!("initialization: setting admin sqlsec context");
        set_admin_context(conn, runtime.use_shim_syntax)?;
    }

    println!("initialization: creating physical tables");
    let physical_accounts = table_name(cfg.engine, "accounts", ReadSurface::Physical);
    let physical_orders = table_name(cfg.engine, "orders", ReadSurface::Physical);
    let physical_transfers = table_name(cfg.engine, "transfers", ReadSurface::Physical);
    let physical_audit = table_name(cfg.engine, "audit_log", ReadSurface::Physical);

    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {physical_accounts} (
            id INTEGER PRIMARY KEY,
            tenant TEXT NOT NULL,
            balance INTEGER NOT NULL,
            status TEXT NOT NULL,
            secret_note TEXT NOT NULL,
            row_label_id INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_{physical_accounts}_tenant ON {physical_accounts}(tenant);

        CREATE TABLE IF NOT EXISTS {physical_orders} (
            id INTEGER PRIMARY KEY,
            tenant TEXT NOT NULL,
            account_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            status TEXT NOT NULL,
            row_label_id INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_{physical_orders}_tenant ON {physical_orders}(tenant);

        CREATE TABLE IF NOT EXISTS {physical_transfers} (
            id INTEGER PRIMARY KEY,
            tenant TEXT NOT NULL,
            from_account_id INTEGER NOT NULL,
            to_account_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            row_label_id INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_{physical_transfers}_tenant_ts ON {physical_transfers}(tenant, ts);

        CREATE TABLE IF NOT EXISTS {physical_audit} (
            id INTEGER PRIMARY KEY,
            tenant TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            action TEXT NOT NULL,
            ref_id INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            detail TEXT NOT NULL,
            row_label_id INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_{physical_audit}_tenant_ts ON {physical_audit}(tenant, ts);"
    ))?;

    if !cfg.engine.uses_security() {
        println!("initialization: security features disabled for this engine");
        return Ok(Labels {
            tenant_labels: (0..TENANTS).map(|i| i as i64 + 1).collect(),
        });
    }

    println!("initialization: bootstrapping secured metadata");
    bootstrap_security_views(conn, runtime.use_shim_syntax)
}

fn configure_setup_conn(conn: &Connection) -> AppResult<()> {
    conn.busy_timeout(Duration::from_millis(750))?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA temp_store = MEMORY;
         PRAGMA cache_size = -8192;
         PRAGMA page_size = 4096;",
    )?;
    Ok(())
}

fn configure_worker_conn(conn: &Connection) -> AppResult<()> {
    conn.busy_timeout(Duration::from_millis(750))?;
    Ok(())
}

fn load_sqlsec_on_conn(conn: &Connection, sqlsec_path: &Path) -> AppResult<()> {
    unsafe {
        conn.load_extension_enable()?;
        conn.load_extension(sqlsec_path, None::<&str>)?;
        conn.load_extension_disable()?;
    }
    Ok(())
}

fn load_sqlevfs_on_conn(conn: &Connection, sqlevfs_path: &Path) -> AppResult<()> {
    unsafe {
        conn.load_extension_enable()?;
        conn.load_extension(sqlevfs_path, None::<&str>)?;
        conn.load_extension_disable()?;
    }
    Ok(())
}

fn open_writer_conn(cfg: &Config, runtime: &Runtime) -> AppResult<Connection> {
    match cfg.engine {
        Engine::Baseline => Ok(Connection::open(&runtime.leader_db_path)?),
        Engine::Secure => Ok(Connection::open_with_flags_and_vfs(
            &runtime.leader_db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            "evfs",
        )?),
        Engine::Cluster => Ok(Connection::open_with_flags_and_vfs(
            &runtime.leader_db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            "evfs_raft_node1",
        )?),
    }
}

fn open_worker_conn(
    cfg: &Config,
    leader_db_path: &Path,
    raft_vfs: Option<&str>,
) -> AppResult<Connection> {
    Ok(match cfg.engine {
        Engine::Baseline => Connection::open(leader_db_path)?,
        Engine::Secure => Connection::open_with_flags_and_vfs(
            leader_db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            "evfs",
        )?,
        Engine::Cluster => Connection::open_with_flags_and_vfs(
            leader_db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            raft_vfs.ok_or("missing raft vfs for cluster writer")?,
        )?,
    })
}

fn open_validation_conn(cfg: &Config, runtime: &Runtime, read_only: bool) -> AppResult<Connection> {
    let flags = if matches!(cfg.engine, Engine::Cluster) {
        // In cluster mode, passive inspection should open via plain EVFS with
        // read-write flags so SQLite can observe WAL-backed state materialized
        // by replay without re-entering the Raft writer path.
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    } else if read_only {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    };
    let conn = match cfg.engine {
        Engine::Baseline => Connection::open_with_flags(&runtime.leader_db_path, flags)?,
        Engine::Secure => {
            Connection::open_with_flags_and_vfs(&runtime.leader_db_path, flags, "evfs")?
        }
        // In cluster mode, passive validation reads should use plain EVFS so
        // SQLite can observe leader WAL-backed state without re-entering the
        // Raft writer path or relying on autostarted raft VFS state.
        Engine::Cluster => {
            Connection::open_with_flags_and_vfs(&runtime.leader_db_path, flags, "evfs")?
        }
    };
    conn.busy_timeout(Duration::from_millis(750))?;
    Ok(conn)
}

fn open_cluster_replica_conn(
    _cfg: &Config,
    _runtime: &Runtime,
    follower: &NodeInfo,
    _read_only: bool,
) -> AppResult<Connection> {
    // Replica replay materializes committed frames into follower WAL files
    // rather than checkpointing into the main DB immediately, so passive
    // inspection should open the follower via plain EVFS with read-write
    // flags so SQLite can see WAL-backed state.
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;
    let conn = Connection::open_with_flags_and_vfs(&follower.db_path, flags, "evfs")?;
    conn.busy_timeout(Duration::from_millis(750))?;
    Ok(conn)
}

fn open_cluster_replica_raft_conn(follower: &NodeInfo) -> AppResult<Connection> {
    let conn = Connection::open_with_flags_and_vfs(
        &follower.db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        follower.raft_vfs_name.as_str(),
    )?;
    conn.busy_timeout(Duration::from_millis(750))?;
    Ok(conn)
}

fn open_evfs_control_conn(db_path: &Path, libs: &LibPaths) -> AppResult<Connection> {
    println!("initialization: EVFS control open {}", db_path.display());
    let conn = Connection::open_with_flags_and_vfs(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        "evfs",
    )?;
    load_sqlevfs_on_conn(&conn, &libs.sqlevfs)?;
    Ok(conn)
}

fn checkpoint_best_effort(cfg: &Config, runtime: &Runtime) {
    let Ok(conn) = open_writer_conn(cfg, runtime) else {
        return;
    };
    let _ = conn.busy_timeout(Duration::from_millis(750));
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
}

fn register_secure_table(
    conn: &Connection,
    use_shim: bool,
    logical: &str,
    physical: &str,
    table_label: Option<&str>,
) -> AppResult<()> {
    if use_shim {
        let sql = if let Some(label) = table_label {
            format!(
                "REGISTER SECURE TABLE {logical} ON {physical} WITH ROW LABEL row_label_id TABLE LABEL '{label}';"
            )
        } else {
            format!("REGISTER SECURE TABLE {logical} ON {physical} WITH ROW LABEL row_label_id;")
        };
        conn.execute_batch(&sql)?;
    } else {
        let table_label_id = if let Some(label) = table_label {
            Some(conn.query_row("SELECT sec_define_label(?1)", [label], |r| {
                r.get::<_, i64>(0)
            })?)
        } else {
            None
        };
        conn.query_row::<i64, _, _>(
            "SELECT sec_register_table(?1, ?2, 'row_label_id', ?3, NULL)",
            params![logical, physical, table_label_id],
            |r| r.get(0),
        )?;
    }
    Ok(())
}

fn bootstrap_security_views(conn: &Connection, use_shim: bool) -> AppResult<Labels> {
    println!("initialization: applying admin context for secured views");
    set_admin_context(conn, use_shim)?;

    let mut tenant_labels = Vec::with_capacity(TENANTS);
    for tenant_idx in 0..TENANTS {
        let expr = format!("(tenant={}|role=admin|role=ops)", tenant_name(tenant_idx));
        let label_id: i64 = conn.query_row("SELECT sec_define_label(?1)", [expr], |r| r.get(0))?;
        tenant_labels.push(label_id);
    }
    println!(
        "initialization: defined {} tenant labels",
        tenant_labels.len()
    );
    let _ops_admin: i64 = conn.query_row(
        "SELECT sec_define_label('(role=admin|role=ops)')",
        [],
        |r| r.get(0),
    )?;

    println!("initialization: registering secured tables");
    maybe_register_secure_table(conn, use_shim, "accounts", "__sec_accounts", None)?;
    maybe_register_secure_table(conn, use_shim, "orders", "__sec_orders", None)?;
    maybe_register_secure_table(conn, use_shim, "transfers", "__sec_transfers", None)?;
    println!("initialization: applying column security");
    set_column_security(conn, use_shim, "accounts", "secret_note", "role=admin")?;
    println!("initialization: refreshing secured views");
    refresh_views(conn, use_shim)?;

    Ok(Labels { tenant_labels })
}

fn maybe_register_secure_table(
    conn: &Connection,
    use_shim: bool,
    logical: &str,
    physical: &str,
    table_label: Option<&str>,
) -> AppResult<()> {
    let existing = conn
        .query_row(
            "SELECT COUNT(*) FROM sec_tables WHERE logical_table = ?1",
            [logical],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0);
    if existing == 0 {
        register_secure_table(conn, use_shim, logical, physical, table_label)?;
    }
    Ok(())
}

fn set_column_security(
    conn: &Connection,
    use_shim: bool,
    table: &str,
    column: &str,
    read_expr: &str,
) -> AppResult<()> {
    if use_shim {
        conn.execute_batch(&format!(
            "SET COLUMN SECURITY {table}.{column} READ '{read_expr}';"
        ))?;
    } else {
        conn.execute(
            "UPDATE sec_columns
             SET read_label_id = sec_define_label(?1)
             WHERE logical_table = ?2 AND column_name = ?3",
            params![read_expr, table, column],
        )?;
    }
    Ok(())
}

fn refresh_views(conn: &Connection, use_shim: bool) -> AppResult<()> {
    if use_shim {
        conn.execute_batch("REFRESH SECURE VIEWS;")?;
    } else {
        conn.query_row::<i64, _, _>("SELECT sec_refresh_views()", [], |r| r.get(0))?;
    }
    Ok(())
}

fn set_admin_context(conn: &Connection, use_shim: bool) -> AppResult<()> {
    apply_context(conn, use_shim, Role::Admin, None)
}

fn apply_context(
    conn: &Connection,
    use_shim: bool,
    role: Role,
    tenant: Option<usize>,
) -> AppResult<()> {
    if use_shim {
        conn.execute_batch("CLEAR CONTEXT;")?;
        conn.execute_batch(&format!("SET CONTEXT role = '{}';", role.as_str()))?;
        if let Some(tenant_idx) = tenant {
            conn.execute_batch(&format!(
                "SET CONTEXT tenant = '{}';",
                tenant_name(tenant_idx)
            ))?;
        }
    } else {
        conn.query_row::<i64, _, _>("SELECT sec_clear_context()", [], |r| r.get(0))?;
        conn.query_row::<i64, _, _>(
            "SELECT sec_set_attr(?1, ?2)",
            params!["role", role.as_str()],
            |r| r.get(0),
        )?;
        if let Some(tenant_idx) = tenant {
            conn.query_row::<i64, _, _>(
                "SELECT sec_set_attr(?1, ?2)",
                params!["tenant", tenant_name(tenant_idx)],
                |r| r.get(0),
            )?;
        }
        conn.query_row::<i64, _, _>("SELECT sec_refresh_views()", [], |r| r.get(0))?;
    }
    Ok(())
}

fn wait_for_leader(conn: &Connection, node_id: u64, timeout: Duration) -> AppResult<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let status: String = conn.query_row("SELECT evfs_raft_status()", [], |r| r.get(0))?;
        let doc: RaftStatusDoc = serde_json::from_str(&status)?;
        if doc
            .nodes
            .iter()
            .any(|n| n.node_id == node_id && n.is_leader && n.leader_id == Some(node_id))
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for raft leader".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_voters(conn: &Connection, expected: &[u64], timeout: Duration) -> AppResult<()> {
    let deadline = Instant::now() + timeout;
    let mut expected_sorted = expected.to_vec();
    expected_sorted.sort_unstable();
    loop {
        let status: String = conn.query_row("SELECT evfs_raft_status()", [], |r| r.get(0))?;
        let doc: RaftStatusDoc = serde_json::from_str(&status)?;
        if !doc.nodes.is_empty()
            && doc.nodes.iter().all(|n| {
                let mut voters = n.voters.clone();
                voters.sort_unstable();
                voters == expected_sorted
            })
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for raft voter membership".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn worker_spec(worker_id: usize) -> WorkerSpec {
    match worker_id % 6 {
        0 => WorkerSpec {
            role: Role::Admin,
            tenant: None,
        },
        1 => WorkerSpec {
            role: Role::Ops,
            tenant: None,
        },
        _ => WorkerSpec {
            role: Role::User,
            tenant: Some(worker_id % TENANTS),
        },
    }
}

fn random_account_id(rng: &mut SimpleRng, tenant_idx: usize) -> i64 {
    let offset = rng.range(ACCOUNTS_PER_TENANT as u64) as usize;
    account_id_for(tenant_idx, offset)
}

fn account_id_for(tenant_idx: usize, offset: usize) -> i64 {
    (tenant_idx * ACCOUNTS_PER_TENANT + offset + 1) as i64
}

fn account_index_for(account_id: i64) -> usize {
    ((account_id - 1) as usize) % ACCOUNTS_PER_TENANT
}

fn tenant_name(tenant_idx: usize) -> String {
    format!("t{tenant_idx:02}")
}

fn transition_for_rng(rng: &mut SimpleRng) -> Option<(&'static str, &'static str)> {
    match rng.range(3) {
        0 => Some(("new", "approved")),
        1 => Some(("approved", "settled")),
        _ => None,
    }
}

fn table_name(engine: Engine, base: &str, surface: ReadSurface) -> String {
    match (engine, surface) {
        (Engine::Baseline, _) => base.to_string(),
        (_, ReadSurface::Physical) => format!("__sec_{base}"),
    }
}

fn ephemeral_addr() -> AppResult<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr.to_string())
}

fn grpc_uri(listen_addr: &str) -> String {
    format!("http://{listen_addr}")
}

fn evfs_keyring_path(db_path: &Path) -> PathBuf {
    db_path.with_extension("evfs-keyring")
}

fn print_metrics(cfg: &Config, metrics: &WorkerMetrics, elapsed: Duration) {
    let total_ops = metrics.point_reads
        + metrics.range_reads
        + metrics.transfers_ok
        + metrics.transfers_skipped
        + metrics.orders_created
        + metrics.order_updates
        + metrics.admin_scans;

    println!("\nSummary");
    println!("  elapsed: {:.2}s", elapsed.as_secs_f64());
    println!("  engine: {}", cfg.engine);
    println!("  total ops: {}", total_ops);
    println!(
        "  ops/sec: {:.2}",
        total_ops as f64 / elapsed.as_secs_f64().max(0.001)
    );
    println!(
        "  reads: point={} range={} admin_scans={}",
        metrics.point_reads, metrics.range_reads, metrics.admin_scans
    );
    println!(
        "  writes: transfers_ok={} transfers_skipped={} orders_created={} order_updates={}",
        metrics.transfers_ok,
        metrics.transfers_skipped,
        metrics.orders_created,
        metrics.order_updates
    );
    println!(
        "  control: refreshes={} errors={}",
        metrics.refreshes, metrics.errors
    );
    print_latency("point read", metrics.point_reads, metrics.point_read_ns);
    print_latency("range read", metrics.range_reads, metrics.range_read_ns);
    print_latency(
        "transfer",
        metrics.transfers_ok + metrics.transfers_skipped,
        metrics.transfer_ns,
    );
    print_latency(
        "create order",
        metrics.orders_created,
        metrics.order_create_ns,
    );
    print_latency(
        "order update",
        metrics.order_updates,
        metrics.order_update_ns,
    );
    print_latency("admin scan", metrics.admin_scans, metrics.admin_scan_ns);
}

fn print_latency(label: &str, count: u64, total_ns: u128) {
    if count == 0 {
        return;
    }
    let avg_ms = total_ns as f64 / count as f64 / 1_000_000.0;
    println!("  avg {label}: {avg_ms:.3}ms");
}
