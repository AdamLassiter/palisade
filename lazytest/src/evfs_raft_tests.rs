use std::time::{Duration, Instant};

use rusqlite::{Connection, Result};

use crate::helpers::{TestDir, TestRunner};

fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

pub(crate) fn run_evfs_raft_tests(t: &mut TestRunner, mode: &str) -> Result<()> {
    t.section("EVFS Raft SQL Control Plane");

    let tmp = TestDir::new("evfs-raft-");
    let keyfile = tmp.write_keyfile("raft.key", [0xCD; 32]);
    let db_path = tmp.path("raft.db");

    unsafe {
        std::env::set_var("EVFS_KEYFILE", &keyfile);
    }

    let conn = Connection::open(&db_path)?;

    unsafe {
        conn.load_extension_enable()?;
        match conn.load_extension(format!("../sqlevfs/target/{mode}/libsqlevfs"), None::<&str>) {
            Ok(()) => t.ok("loaded sqlevfs extension for raft tests"),
            Err(e) => {
                t.fail("load sqlevfs extension", &e);
                conn.load_extension_disable()?;
                return Ok(());
            }
        }
        conn.load_extension_disable()?;
    }

    let status0: String = conn.query_row("SELECT evfs_raft_status()", [], |r| r.get(0))?;
    if status0.contains("\"nodes\":[]") {
        t.ok("evfs_raft_status reports empty nodes before init");
    } else {
        t.fail(
            "evfs_raft_status pre-init",
            &format!("unexpected status payload: {status0}"),
        );
    }

    let init_msg: String = conn.query_row(
        "SELECT evfs_raft_init(?1, ?2, ?3)",
        rusqlite::params![1i64, "127.0.0.1:0", "{}"],
        |r| r.get(0),
    )?;
    if init_msg.contains("reopen DB with vfs=evfs_raft") {
        t.ok("evfs_raft_init returns activation message");
    } else {
        t.fail("evfs_raft_init message", &init_msg);
    }

    let became_leader = wait_until(Duration::from_secs(5), || {
        let status: Result<String> = conn.query_row("SELECT evfs_raft_status()", [], |r| r.get(0));
        match status {
            Ok(s) => s.contains("\"node_id\":1") && s.contains("\"is_leader\":true"),
            Err(_) => false,
        }
    });
    if became_leader {
        t.ok("single-node raft becomes leader");
    } else {
        t.fail(
            "leader election",
            &"timed out waiting for status to report is_leader=true",
        );
    }

    match conn.query_row::<String, _, _>(
        "SELECT evfs_raft_add_node(?1, ?2, ?3)",
        rusqlite::params![0i64, "http://127.0.0.1:65535", 1i64],
        |r| r.get(0),
    ) {
        Ok(msg) => t.fail("evfs_raft_add_node expected node_id validation error", &msg),
        Err(_) => t.ok("evfs_raft_add_node rejects node_id=0"),
    }

    let stop_msg: String = conn.query_row("SELECT evfs_raft_stop()", [], |r| r.get(0))?;
    t.assert_eq(
        "evfs_raft_stop message",
        &stop_msg,
        &"raft stopped".to_string(),
    );

    let status_after: String = conn.query_row("SELECT evfs_raft_status()", [], |r| r.get(0))?;
    if status_after.contains("\"nodes\":[]") {
        t.ok("evfs_raft_status empty after stop");
    } else {
        t.fail(
            "evfs_raft_status after stop",
            &format!("unexpected status payload: {status_after}"),
        );
    }

    Ok(())
}
