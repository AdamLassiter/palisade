use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use sqlevfs::vfs::consensus::handle::RaftHandle;

use crate::common::{sqlite_api_is_available, wait_until};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_raft_replication_single_node_applies_committed_frame() -> anyhow::Result<()> {
    let applied: Arc<Mutex<Vec<(i64, u32, Vec<u8>)>>> = Arc::new(Mutex::new(Vec::new()));
    let applied_clone = applied.clone();

    let node = RaftHandle::start(
        1,
        HashMap::new(),
        move |wal_offset, page_no, data| {
            applied_clone.lock().expect("apply lock poisoned").push((
                wal_offset,
                page_no,
                data.to_vec(),
            ));
            Ok(())
        },
        None,
        None,
    )
    .await?;

    wait_until(Duration::from_secs(5), || node.is_leader()).await?;

    let offset = 32_i64;
    let page_no = 7_u32;
    let payload = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02];
    node.submit_frame(offset, page_no, payload.clone()).await?;

    wait_until(Duration::from_secs(5), || {
        applied
            .lock()
            .expect("apply lock poisoned")
            .iter()
            .any(|(off, pg, data)| *off == offset && *pg == page_no && *data == payload)
    })
    .await?;

    assert_eq!(node.committed_wal_offset(), offset as u64);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_raft_replication_single_node_commits_in_order() -> anyhow::Result<()> {
    let applied: Arc<Mutex<Vec<(i64, u32, Vec<u8>)>>> = Arc::new(Mutex::new(Vec::new()));
    let applied_clone = applied.clone();

    let node = RaftHandle::start(
        1,
        HashMap::new(),
        move |wal_offset, page_no, data| {
            applied_clone.lock().expect("apply lock poisoned").push((
                wal_offset,
                page_no,
                data.to_vec(),
            ));
            Ok(())
        },
        None,
        None,
    )
    .await?;

    wait_until(Duration::from_secs(5), || node.is_leader()).await?;

    let first = (32_i64, 2_u32, vec![0x01, 0x02, 0x03]);
    let second = (4120_i64, 3_u32, vec![0x0A, 0x0B, 0x0C, 0x0D]);

    node.submit_frame(first.0, first.1, first.2.clone()).await?;
    node.submit_frame(second.0, second.1, second.2.clone())
        .await?;

    wait_until(Duration::from_secs(5), || {
        applied.lock().expect("apply lock poisoned").len() >= 2
    })
    .await?;

    let applied = applied.lock().expect("apply lock poisoned");
    assert_eq!(applied[0], first);
    assert_eq!(applied[1], second);
    assert_eq!(node.committed_wal_offset(), second.0 as u64);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_raft_replication_from_one_instance_to_another() -> anyhow::Result<()> {
    use tokio::sync::mpsc;

    let replica_applied: Arc<Mutex<Vec<(i64, u32, Vec<u8>)>>> = Arc::new(Mutex::new(Vec::new()));
    let replica_applied_clone = replica_applied.clone();

    let replica = RaftHandle::start(
        2,
        HashMap::new(),
        move |wal_offset, page_no, data| {
            replica_applied_clone
                .lock()
                .expect("replica apply lock poisoned")
                .push((wal_offset, page_no, data.to_vec()));
            Ok(())
        },
        None,
        None,
    )
    .await?;

    wait_until(Duration::from_secs(5), || replica.is_leader()).await?;

    let (tx, mut rx) = mpsc::unbounded_channel::<(i64, u32, Vec<u8>)>();
    let replica_for_bridge = replica.clone();
    let bridge = tokio::spawn(async move {
        while let Some((offset, page_no, data)) = rx.recv().await {
            replica_for_bridge
                .submit_frame(offset, page_no, data)
                .await
                .expect("replica submit_frame via bridge should succeed");
        }
    });

    let source = RaftHandle::start(
        1,
        HashMap::new(),
        move |wal_offset, page_no, data| {
            tx.send((wal_offset, page_no, data.to_vec()))
                .expect("bridge channel send should succeed");
            Ok(())
        },
        None,
        None,
    )
    .await?;

    wait_until(Duration::from_secs(5), || source.is_leader()).await?;

    let writes = [
        (32_i64, 5_u32, vec![0xDE, 0xAD, 0xBE, 0xEF]),
        (4120_i64, 6_u32, vec![0xFA, 0xCE, 0xB0, 0x0C]),
        (8208_i64, 7_u32, vec![0x10, 0x20, 0x30]),
    ];

    for (offset, page_no, data) in writes.iter().cloned() {
        source.submit_frame(offset, page_no, data).await?;
    }

    wait_until(Duration::from_secs(5), || {
        replica_applied
            .lock()
            .expect("replica apply lock poisoned")
            .len()
            == writes.len()
    })
    .await?;

    let replica_applied = replica_applied.lock().expect("replica apply lock poisoned");
    assert_eq!(replica_applied.as_slice(), &writes);

    bridge.abort();
    let _ = bridge.await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_sqlite_insert_is_propagated_across_databases_via_raft() -> anyhow::Result<()> {
    if !sqlite_api_is_available() {
        eprintln!("skipping: sqlite extension API pointers are not initialized in this build");
        return Ok(());
    }
    use rusqlite::Connection;
    use tokio::sync::mpsc;

    let temp_dir = tempfile::TempDir::new()?;

    let source_db = temp_dir.path().join("source.db");
    let replica_db = temp_dir.path().join("replica.db");
    let applied_count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let (tx, mut rx) = mpsc::unbounded_channel::<(i64, u32, Vec<u8>)>();

    let replica_applied = applied_count.clone();
    let replica_db_for_apply = replica_db.clone();
    let replica_raft = RaftHandle::start(
        22,
        HashMap::new(),
        move |_wal_offset, _page_no, frame_data| {
            let sql = std::str::from_utf8(frame_data)
                .map_err(|e| anyhow::anyhow!("invalid replicated SQL payload: {e}"))?;
            let conn = Connection::open(&replica_db_for_apply)?;
            conn.execute(sql, [])?;
            *replica_applied.lock().expect("applied count lock poisoned") += 1;
            Ok(())
        },
        None,
        None,
    )
    .await?;
    wait_until(Duration::from_secs(5), || replica_raft.is_leader()).await?;

    let replica_forwarder = replica_raft.clone();
    let bridge = tokio::spawn(async move {
        while let Some((wal_offset, page_no, frame_data)) = rx.recv().await {
            replica_forwarder
                .submit_frame(wal_offset, page_no, frame_data)
                .await
                .expect("replica forward submit_frame failed");
        }
    });

    let source_raft = RaftHandle::start(
        11,
        HashMap::new(),
        move |wal_offset, page_no, frame_data| {
            tx.send((wal_offset, page_no, frame_data.to_vec()))
                .map_err(|e| anyhow::anyhow!("failed to queue frame for replica: {e}"))?;
            Ok(())
        },
        None,
        None,
    )
    .await?;
    wait_until(Duration::from_secs(5), || source_raft.is_leader()).await?;

    let src_conn = Connection::open(&source_db)?;
    src_conn.execute(
        "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, v TEXT)",
        [],
    )?;
    src_conn.execute("DELETE FROM items", [])?;

    {
        let dst_conn = Connection::open(&replica_db)?;
        dst_conn.execute(
            "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, v TEXT)",
            [],
        )?;
        dst_conn.execute("DELETE FROM items", [])?;
        dst_conn.close().map_err(|(_, e)| e)?;
    }

    let inserts = [
        "INSERT INTO items (v) VALUES ('alpha')",
        "INSERT INTO items (v) VALUES ('beta')",
    ];

    for (i, sql) in inserts.iter().enumerate() {
        src_conn.execute(sql, [])?;
        source_raft
            .submit_frame((i + 1) as i64, (i + 1) as u32, sql.as_bytes().to_vec())
            .await?;
    }

    src_conn.close().map_err(|(_, e)| e)?;

    wait_until(Duration::from_secs(10), || {
        *applied_count.lock().expect("applied count lock poisoned") >= inserts.len()
    })
    .await?;

    let verify_conn = Connection::open(&replica_db)?;
    let mut stmt = verify_conn.prepare("SELECT v FROM items ORDER BY id")?;
    let rows: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);
    assert_eq!(rows, vec!["alpha".to_string(), "beta".to_string()]);
    verify_conn.close().map_err(|(_, e)| e)?;

    bridge.abort();
    let _ = bridge.await;

    Ok(())
}
