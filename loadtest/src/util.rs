use std::{
    io::{self, IsTerminal, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        Arc,
        Mutex,
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::types::{
    ACCOUNTS_PER_TENANT,
    AppResult,
    Config,
    Engine,
    ReadSurface,
    Role,
    SimpleRng,
    TENANTS,
    WorkerMetrics,
    WorkerSpec,
    WorkloadProfile,
};

pub(crate) const RESET: &str = "\x1b[0m";
pub(crate) const BOLD: &str = "\x1b[1m";
pub(crate) const DIM: &str = "\x1b[2m";
pub(crate) const GREEN: &str = "\x1b[32m";
pub(crate) const YELLOW: &str = "\x1b[33m";
pub(crate) const BLUE: &str = "\x1b[34m";
const MAGENTA: &str = "\x1b[35m";
pub(crate) const CYAN: &str = "\x1b[36m";
pub(crate) const RED: &str = "\x1b[31m";

static TRANSIENT_ACTIVE: OnceLock<Mutex<bool>> = OnceLock::new();

pub(crate) fn style(code: &'static str) -> &'static str {
    if io::stdout().is_terminal() { code } else { "" }
}

fn transient_state() -> &'static Mutex<bool> {
    TRANSIENT_ACTIVE.get_or_init(|| Mutex::new(false))
}

pub(crate) fn clear_transient() {
    let Ok(mut active) = transient_state().lock() else {
        return;
    };
    if *active && io::stdout().is_terminal() {
        print!("\r\x1b[2K");
        let _ = io::stdout().flush();
    }
    *active = false;
}

pub(crate) fn transient(msg: impl AsRef<str>) {
    if !io::stdout().is_terminal() {
        return;
    }
    let Ok(mut active) = transient_state().lock() else {
        return;
    };
    print!(
        "\r\x1b[2K{}·{} {}{}{}",
        style(DIM),
        style(RESET),
        style(DIM),
        msg.as_ref(),
        style(RESET)
    );
    let _ = io::stdout().flush();
    *active = true;
}

pub(crate) fn persist(msg: impl AsRef<str>) {
    clear_transient();
    println!("  {}•{} {}", style(CYAN), style(RESET), msg.as_ref());
}

pub(crate) fn worker_spec(profile: WorkloadProfile, worker_id: usize) -> WorkerSpec {
    match profile {
        WorkloadProfile::ReadHeavy => WorkerSpec {
            role: Role::User,
            tenant: Some(worker_id % TENANTS),
        },
        WorkloadProfile::WriteHeavy => match worker_id % 5 {
            0 => WorkerSpec {
                role: Role::Ops,
                tenant: None,
            },
            _ => WorkerSpec {
                role: Role::User,
                tenant: Some(worker_id % TENANTS),
            },
        },
        WorkloadProfile::TransferHeavy => match worker_id % 4 {
            0..=2 => WorkerSpec {
                role: Role::Ops,
                tenant: None,
            },
            _ => WorkerSpec {
                role: Role::User,
                tenant: Some(worker_id % TENANTS),
            },
        },
        WorkloadProfile::ScanHeavy => match worker_id % 4 {
            0..=2 => WorkerSpec {
                role: Role::Admin,
                tenant: None,
            },
            _ => WorkerSpec {
                role: Role::User,
                tenant: Some(worker_id % TENANTS),
            },
        },
        WorkloadProfile::Contention => match worker_id % 4 {
            0 => WorkerSpec {
                role: Role::Ops,
                tenant: None,
            },
            _ => WorkerSpec {
                role: Role::User,
                tenant: Some(0),
            },
        },
        WorkloadProfile::Balanced => match worker_id % 6 {
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
        },
        WorkloadProfile::All => worker_spec(WorkloadProfile::Balanced, worker_id),
    }
}

pub(crate) fn random_account_id(rng: &mut SimpleRng, tenant_idx: usize) -> i64 {
    let offset = rng.range(ACCOUNTS_PER_TENANT as u64) as usize;
    account_id_for(tenant_idx, offset)
}

pub(crate) fn account_id_for(tenant_idx: usize, offset: usize) -> i64 {
    (tenant_idx * ACCOUNTS_PER_TENANT + offset + 1) as i64
}

pub(crate) fn tenant_name(tenant_idx: usize) -> String {
    format!("t{tenant_idx:02}")
}

pub(crate) fn transition_for_rng(rng: &mut SimpleRng) -> Option<(&'static str, &'static str)> {
    match rng.range(3) {
        0 => Some(("new", "approved")),
        1 => Some(("approved", "settled")),
        _ => None,
    }
}

pub(crate) fn table_name(engine: Engine, base: &str, surface: ReadSurface) -> String {
    match (engine, surface) {
        (Engine::Sqlite, _) => base.to_string(),
        (_, ReadSurface::Physical) => format!("__sec_{base}"),
    }
}

pub(crate) fn ephemeral_addr() -> AppResult<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr.to_string())
}

pub(crate) fn grpc_uri(listen_addr: &str) -> String {
    format!("http://{listen_addr}")
}

pub(crate) fn evfs_keyring_path(db_path: &Path) -> PathBuf {
    db_path.with_extension("evfs-keyring")
}

pub(crate) fn print_metrics(
    cfg: &Config,
    metrics: &WorkerMetrics,
    elapsed: Duration,
    workload_elapsed: Duration,
    validation_elapsed: Duration,
) {
    let total_ops = metrics.point_reads
        + metrics.range_reads
        + metrics.transfers_ok
        + metrics.transfers_skipped
        + metrics.orders_created
        + metrics.order_updates
        + metrics.admin_scans;
    let read_ops = metrics.point_reads + metrics.range_reads + metrics.admin_scans;
    let write_ops = metrics.transfers_ok
        + metrics.transfers_skipped
        + metrics.orders_created
        + metrics.order_updates;
    let workload_secs = workload_elapsed.as_secs_f64().max(0.001);

    println!("\n{}{}Summary{}", style(BOLD), style(CYAN), style(RESET));
    println!(
        "  {}elapsed{}: {:.2}s",
        style(DIM),
        style(RESET),
        elapsed.as_secs_f64()
    );
    println!(
        "  {}workload time{}: {:.2}s",
        style(DIM),
        style(RESET),
        workload_elapsed.as_secs_f64()
    );
    if workload_elapsed > cfg.duration {
        println!(
            "  {}workload overrun{}: {:.2}s",
            style(DIM),
            style(RESET),
            (workload_elapsed - cfg.duration).as_secs_f64()
        );
    }
    println!(
        "  {}validation time{}: {:.2}s",
        style(DIM),
        style(RESET),
        validation_elapsed.as_secs_f64()
    );
    println!("  {}engine{}: {}", style(DIM), style(RESET), cfg.engine);
    println!(
        "  {}workload{}: {} ({})",
        style(DIM),
        style(RESET),
        cfg.workload,
        cfg.workload.description()
    );
    println!("  {}total ops{}: {}", style(DIM), style(RESET), total_ops);
    println!(
        "  {}ops/sec{}: {:.2}",
        style(DIM),
        style(RESET),
        total_ops as f64 / workload_secs
    );
    println!(
        "  {}read ops/sec{}: {:.2}",
        style(DIM),
        style(RESET),
        read_ops as f64 / workload_secs
    );
    println!(
        "  {}write ops/sec{}: {:.2}",
        style(DIM),
        style(RESET),
        write_ops as f64 / workload_secs
    );
    println!(
        "  {}reads{}: total={} point={} range={} admin_scans={}",
        style(DIM),
        style(RESET),
        read_ops,
        metrics.point_reads,
        metrics.range_reads,
        metrics.admin_scans
    );
    println!(
        "  {}writes{}: total={} transfers_ok={} transfers_skipped={} orders_created={} order_updates={}",
        style(DIM),
        style(RESET),
        write_ops,
        metrics.transfers_ok,
        metrics.transfers_skipped,
        metrics.orders_created,
        metrics.order_updates
    );
    println!(
        "  {}control{}: refreshes={}",
        style(DIM),
        style(RESET),
        metrics.refreshes
    );
    println!(
        "  {}lock/busy conflicts{}: total={} point_read={} range_read={} transfer_begin={} transfer_body={} create_order={} order_update={} admin_scan={}",
        style(DIM),
        style(RESET),
        metrics.lock_conflicts(),
        metrics.point_read_busy,
        metrics.range_read_busy,
        metrics.transfer_begin_busy,
        metrics.transfer_busy,
        metrics.order_create_busy,
        metrics.order_update_busy,
        metrics.admin_scan_busy
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
    println!("  {}avg {label}{}: {avg_ms:.3}ms", style(DIM), style(RESET));
}

pub(crate) fn banner(cfg: &Config) {
    println!(
        "\n{}{}palisade loadtest{} {}mode={} engine={} workload={} workers={} duration={}s seed={:#x}{}",
        style(BOLD),
        style(MAGENTA),
        style(RESET),
        style(DIM),
        cfg.mode,
        cfg.engine,
        cfg.workload,
        cfg.workers,
        cfg.duration.as_secs(),
        cfg.seed,
        style(RESET)
    );
    println!(
        "{}profile{} {}",
        style(DIM),
        style(RESET),
        cfg.workload.description()
    );
}

pub(crate) fn phase(msg: impl AsRef<str>) {
    clear_transient();
    println!("{}→{} {}", style(BLUE), style(RESET), msg.as_ref());
}

pub(crate) fn success(msg: impl AsRef<str>) {
    clear_transient();
    println!("{}✓{} {}", style(GREEN), style(RESET), msg.as_ref());
}

pub(crate) fn warn(msg: impl AsRef<str>) {
    clear_transient();
    println!("{}!{} {}", style(YELLOW), style(RESET), msg.as_ref());
}

pub(crate) fn fail(msg: impl AsRef<str>) {
    clear_transient();
    eprintln!("{}✗{} {}", style(RED), style(RESET), msg.as_ref());
}

pub(crate) fn print_validation(checks: &[String]) {
    clear_transient();
    println!("\n{}{}Validation{}", style(BOLD), style(CYAN), style(RESET));
    for line in checks {
        println!("  {}{}{}", style(GREEN), line, style(RESET));
    }
}

pub(crate) struct Spinner {
    done: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    label: String,
    animated: bool,
}

impl Spinner {
    pub(crate) fn start(label: impl Into<String>) -> Self {
        let label = label.into();
        let animated = io::stderr().is_terminal();
        if !io::stdout().is_terminal() || !animated {
            phase(&label);
        }
        let done = Arc::new(AtomicBool::new(false));
        let handle = if animated {
            let done_for_thread = done.clone();
            let label_for_thread = label.clone();
            Some(thread::spawn(move || {
                let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
                let mut i = 0usize;
                while !done_for_thread.load(Ordering::Relaxed) {
                    eprint!(
                        "\r{}{}{} {}{}{}",
                        style(CYAN),
                        frames[i % frames.len()],
                        style(RESET),
                        style(DIM),
                        label_for_thread,
                        style(RESET)
                    );
                    let _ = io::stderr().flush();
                    i += 1;
                    thread::sleep(Duration::from_millis(90));
                }
            }))
        } else {
            None
        };
        Self {
            done,
            handle,
            label,
            animated,
        }
    }

    pub(crate) fn finish(mut self, msg: impl AsRef<str>) {
        self.stop();
        success(msg);
    }

    fn stop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if self.animated {
            eprint!("\r\x1b[2K");
            let _ = io::stderr().flush();
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        if self.handle.is_some() {
            self.stop();
            warn(format!("{} interrupted", self.label));
        }
    }
}
