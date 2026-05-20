use std::{
    collections::HashMap,
    env,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use crate::{
    protocol::{ChildRequest, ChildResponse},
    status::RaftStatusDoc,
    types::{AppResult, FollowerWalSync, LibPaths, NodeConfig},
    util::{ephemeral_addr, evfs_keyring_path, grpc_uri},
};

pub(crate) struct ClusterSupervisor {
    repo_root: PathBuf,
    workspace: PathBuf,
    libs: LibPaths,
    node_cfgs: Vec<NodeConfig>,
    mode: String,
    wal_sync: FollowerWalSync,
    nodes: HashMap<u64, NodeProcess>,
}

impl ClusterSupervisor {
    pub(crate) fn new(
        repo_root: PathBuf,
        workspace: PathBuf,
        libs: LibPaths,
        node_cfgs: Vec<NodeConfig>,
        mode: String,
        wal_sync: FollowerWalSync,
    ) -> Self {
        Self {
            repo_root,
            workspace,
            libs,
            node_cfgs,
            mode,
            wal_sync,
            nodes: HashMap::new(),
        }
    }

    pub(crate) fn start_all(&mut self) -> AppResult<()> {
        for node_id in [1_u64, 2, 3] {
            self.start_node(node_id)?;
        }
        Ok(())
    }

    fn start_node(&mut self, node_id: u64) -> AppResult<()> {
        let cfg = self
            .node_cfgs
            .iter()
            .find(|n| n.node_id == node_id)
            .ok_or_else(|| format!("missing node config {node_id}"))?
            .clone();
        let peers = self
            .node_cfgs
            .iter()
            .filter(|n| n.node_id != node_id)
            .map(|n| (n.node_id, n.rpc_addr.clone()))
            .collect::<HashMap<_, _>>();
        let peers_json = if node_id == 1 {
            "{}".to_string()
        } else {
            serde_json::to_string(&peers)?
        };

        let stdout_log = self.workspace.join(format!("node{node_id}.stdout.log"));
        let stderr_log = self.workspace.join(format!("node{node_id}.stderr.log"));
        let exe = env::current_exe()?;
        let mut child = Command::new(exe)
            .arg("--node")
            .arg("--mode")
            .arg(&self.mode)
            .arg("--node-id")
            .arg(node_id.to_string())
            .arg("--db")
            .arg(&cfg.db_path)
            .arg("--listen")
            .arg(&cfg.listen_addr)
            .arg("--peers")
            .arg(peers_json)
            .arg("--raft-vfs")
            .arg(&cfg.raft_vfs_name)
            .arg("--sqlsec")
            .arg(&self.libs.sqlsec)
            .arg("--sqlevfs")
            .arg(&self.libs.sqlevfs)
            .arg("--wal-sync")
            .arg(self.wal_sync.as_str())
            .current_dir(self.repo_root.join("chaostest"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(File::create(&stderr_log)?))
            .spawn()?;

        let stdout = child.stdout.take().ok_or("child stdout missing")?;
        let stdin = child.stdin.take().ok_or("child stdin missing")?;
        let mut process = NodeProcess {
            node_id,
            child,
            stdin,
            stdout: BufReader::new(stdout),
            stdout_log,
            stderr_log,
        };
        let ready = process.read_response(Duration::from_secs(10))?;
        if !ready.ok {
            return Err(format!("node {node_id} failed to start: {:?}", ready.error).into());
        }
        self.nodes.insert(node_id, process);
        Ok(())
    }

    pub(crate) fn add_followers(&mut self) -> AppResult<()> {
        let followers = self
            .node_cfgs
            .iter()
            .filter(|n| n.node_id != 1)
            .map(|node| (node.node_id, node.rpc_addr.clone()))
            .collect::<Vec<_>>();
        for (node_id, rpc_addr) in followers {
            self.request(
                1,
                ChildRequest::AddNode {
                    node_id,
                    rpc_addr,
                    wait_secs: 10,
                },
            )?;
        }
        self.wait_voters(Duration::from_secs(10))?;
        Ok(())
    }

    pub(crate) fn seed(&mut self, seed: u64) -> AppResult<()> {
        self.request(1, ChildRequest::Seed { seed })?;
        self.sync_keyrings()?;
        Ok(())
    }

    pub(crate) fn sync_keyrings(&self) -> AppResult<()> {
        let leader = &self.node_cfgs[0].db_path;
        let leader_keyring = evfs_keyring_path(leader);
        for follower in self.node_cfgs.iter().skip(1) {
            if leader_keyring.exists() {
                fs::copy(&leader_keyring, evfs_keyring_path(&follower.db_path))?;
            }
        }
        Ok(())
    }

    pub(crate) fn run_workload(
        &mut self,
        duration: Duration,
        workers: usize,
        seed: u64,
    ) -> AppResult<()> {
        let leader = self.current_leader().ok_or("no current Raft leader")?;
        self.request(
            leader,
            ChildRequest::RunWorkload {
                duration_secs: duration.as_secs().max(1),
                workers,
                seed,
            },
        )?;
        self.sync_keyrings()?;
        Ok(())
    }

    pub(crate) fn wait_converged(&mut self, timeout: Duration) -> AppResult<()> {
        let started = Instant::now();
        loop {
            if started.elapsed() > timeout {
                return Err("timed out waiting for follower convergence".into());
            }
            if self.replicas_converged()? {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    pub(crate) fn convergence_diagnostics(&mut self) -> AppResult<String> {
        let leader_offset = if let Some(leader) = self.current_leader() {
            self.status_from(leader)?
                .nodes
                .iter()
                .find(|node| node.is_leader)
                .map(|node| node.committed_wal_offset as i64)
                .unwrap_or(-1)
        } else {
            -1
        };
        let mut parts = vec![format!("leader_offset={leader_offset}")];
        let node_ids = self.nodes.keys().copied().collect::<Vec<_>>();
        for node_id in node_ids {
            let status = self.status_from(node_id)?;
            if let Some(node) = status.nodes.iter().find(|node| node.node_id == node_id) {
                parts.push(format!(
                    "node{} applied={} synced={} materialized={} voters={:?}",
                    node_id,
                    node.replay.last_applied_offset,
                    node.replay.last_wal_synced_offset,
                    node.replay.last_materialized_offset,
                    node.voters
                ));
            } else {
                parts.push(format!("node{node_id} missing from local status"));
            }
        }
        Ok(parts.join(", "))
    }

    fn replicas_converged(&mut self) -> AppResult<bool> {
        let Some(current_leader) = self.current_leader() else {
            return Ok(false);
        };
        let status = self.status_from(current_leader)?;
        let Some(leader) = status.nodes.iter().find(|node| node.is_leader) else {
            return Ok(false);
        };
        let leader_id = leader.node_id;
        let target = leader.committed_wal_offset as i64;

        let follower_ids = self
            .nodes
            .keys()
            .copied()
            .filter(|id| *id != leader_id)
            .collect::<Vec<_>>();
        for node_id in follower_ids {
            let status = self.status_from(node_id)?;
            let Some(node) = status.nodes.iter().find(|node| node.node_id == node_id) else {
                return Ok(false);
            };
            if node.replay.last_applied_offset < target
                || node.replay.last_materialized_offset < target
                || (node.replay.wal_sync_policy != "coalesced"
                    && node.replay.last_wal_synced_offset < target)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn wait_voters(&mut self, timeout: Duration) -> AppResult<()> {
        let started = Instant::now();
        loop {
            let status = self.status_from(1)?;
            if status
                .nodes
                .iter()
                .any(|node| node.is_leader && node.voters == vec![1, 2, 3])
            {
                return Ok(());
            }
            if started.elapsed() > timeout {
                return Err("timed out waiting for voters [1,2,3]".into());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn current_leader(&mut self) -> Option<u64> {
        let ids = self.nodes.keys().copied().collect::<Vec<_>>();
        for id in ids {
            if let Ok(status) = self.status_from(id)
                && let Some(node) = status.nodes.iter().find(|node| node.is_leader)
            {
                return Some(node.node_id);
            }
        }
        None
    }

    pub(crate) fn wait_leader(&mut self, timeout: Duration) -> AppResult<u64> {
        let started = Instant::now();
        loop {
            if let Some(leader) = self.current_leader() {
                return Ok(leader);
            }
            if started.elapsed() > timeout {
                return Err("timed out waiting for Raft leader".into());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn status_from(&mut self, node_id: u64) -> AppResult<RaftStatusDoc> {
        let response = self.request(node_id, ChildRequest::Status)?;
        let value = response.result.ok_or("status response missing result")?;
        Ok(serde_json::from_value(value)?)
    }

    pub(crate) fn validate_all(&mut self) -> AppResult<()> {
        let leader = self.current_leader().ok_or("no current Raft leader")?;
        self.request(leader, ChildRequest::ValidateLocal)?;
        let node_ids = self.nodes.keys().copied().collect::<Vec<_>>();
        for node_id in node_ids {
            if node_id != leader {
                self.request(node_id, ChildRequest::ValidateLocal)?;
                self.request(node_id, ChildRequest::ProbeFollowerWrite)?;
            }
        }
        Ok(())
    }

    pub(crate) fn kill(&mut self, node_id: u64) -> AppResult<()> {
        if let Some(mut node) = self.nodes.remove(&node_id) {
            node.child.kill()?;
            let _ = node.child.wait();
        }
        Ok(())
    }

    pub(crate) fn kill_all(&mut self) {
        let ids = self.nodes.keys().copied().collect::<Vec<_>>();
        for id in ids {
            let _ = self.kill(id);
        }
    }

    pub(crate) fn restart(&mut self, node_id: u64) -> AppResult<()> {
        if node_id != 1 {
            let listen_addr = ephemeral_addr()?;
            let rpc_addr = grpc_uri(&listen_addr);
            let cfg = self
                .node_cfgs
                .iter_mut()
                .find(|node| node.node_id == node_id)
                .ok_or_else(|| format!("missing node config {node_id}"))?;
            cfg.listen_addr = listen_addr;
            cfg.rpc_addr = rpc_addr;
        }
        self.start_node(node_id)?;
        if node_id != 1 {
            let rpc_addr = self
                .node_cfgs
                .iter()
                .find(|node| node.node_id == node_id)
                .map(|node| node.rpc_addr.clone())
                .ok_or_else(|| format!("missing node config {node_id}"))?;
            let leader = self.current_leader().unwrap_or(1);
            match self.request(
                leader,
                ChildRequest::AddNode {
                    node_id,
                    rpc_addr,
                    wait_secs: 10,
                },
            ) {
                Ok(_) => {}
                Err(err) if err.to_string().contains("already") => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    pub(crate) fn restart_all(&mut self) -> AppResult<()> {
        for id in [1_u64, 2, 3] {
            self.start_node(id)?;
        }
        Ok(())
    }

    pub(crate) fn shutdown_all(&mut self) {
        let ids = self.nodes.keys().copied().collect::<Vec<_>>();
        for id in ids {
            let _ = self.request(id, ChildRequest::Shutdown);
            if let Some(mut node) = self.nodes.remove(&id) {
                let _ = node.child.wait();
            }
        }
    }

    fn request(&mut self, node_id: u64, request: ChildRequest) -> AppResult<ChildResponse> {
        let node = self
            .nodes
            .get_mut(&node_id)
            .ok_or_else(|| format!("node {node_id} is not running"))?;
        node.request(request)
    }
}

impl Drop for ClusterSupervisor {
    fn drop(&mut self) {
        self.shutdown_all();
    }
}

struct NodeProcess {
    node_id: u64,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
}

impl NodeProcess {
    fn request(&mut self, request: ChildRequest) -> AppResult<ChildResponse> {
        writeln!(self.stdin, "{}", serde_json::to_string(&request)?)?;
        self.stdin.flush()?;
        let response = self.read_response(Duration::from_secs(30))?;
        if response.ok {
            Ok(response)
        } else {
            Err(format!(
                "node {} command failed: {} (stdout_log={} stderr_log={})",
                self.node_id,
                response.error.unwrap_or_else(|| "unknown".to_string()),
                self.stdout_log.display(),
                self.stderr_log.display()
            )
            .into())
        }
    }

    fn read_response(&mut self, timeout: Duration) -> AppResult<ChildResponse> {
        let started = Instant::now();
        loop {
            let mut line = String::new();
            let bytes = self.stdout.read_line(&mut line)?;
            if bytes == 0 {
                if let Some(status) = self.child.try_wait()? {
                    return Err(format!(
                        "node {} exited with {status} before producing a response (stdout_log={} stderr_log={})",
                        self.node_id,
                        self.stdout_log.display(),
                        self.stderr_log.display()
                    )
                    .into());
                }
                if started.elapsed() > timeout {
                    return Err(format!("node {} produced no response", self.node_id).into());
                }
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            if line.trim().is_empty() {
                continue;
            }
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.stdout_log)?
                .write_all(line.as_bytes())?;
            let response = serde_json::from_str::<ChildResponse>(line.trim())?;
            return Ok(response);
        }
    }
}
