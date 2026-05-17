use std::{
    net::TcpListener,
    path::{Path, PathBuf},
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
};

pub(crate) fn worker_spec(worker_id: usize) -> WorkerSpec {
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
        (Engine::Baseline, _) => base.to_string(),
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

pub(crate) fn print_metrics(cfg: &Config, metrics: &WorkerMetrics, elapsed: Duration) {
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
