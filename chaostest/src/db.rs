use std::path::Path;

use crate::{
    types::{AppResult, NodeConfig},
    util::{ephemeral_addr, grpc_uri},
};

pub(crate) fn make_node_configs(workspace: &Path) -> AppResult<Vec<NodeConfig>> {
    let a1 = ephemeral_addr()?;
    let a2 = ephemeral_addr()?;
    let a3 = ephemeral_addr()?;
    Ok(vec![
        NodeConfig {
            node_id: 1,
            db_path: workspace.join("leader.db"),
            listen_addr: a1.clone(),
            rpc_addr: grpc_uri(&a1),
            raft_vfs_name: "chaos_raft_node1".to_string(),
        },
        NodeConfig {
            node_id: 2,
            db_path: workspace.join("node2.db"),
            listen_addr: a2.clone(),
            rpc_addr: grpc_uri(&a2),
            raft_vfs_name: "chaos_raft_node2".to_string(),
        },
        NodeConfig {
            node_id: 3,
            db_path: workspace.join("node3.db"),
            listen_addr: a3.clone(),
            rpc_addr: grpc_uri(&a3),
            raft_vfs_name: "chaos_raft_node3".to_string(),
        },
    ])
}
