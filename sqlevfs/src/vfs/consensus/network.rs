use std::collections::HashMap;

use anyhow::Result;
use openraft::{
    BasicNode,
    EntryPayload,
    Vote,
    error::{InstallSnapshotError, NetworkError, RPCError, RaftError},
    network::{RPCOption, RaftNetwork, RaftNetworkFactory},
    raft::{
        AppendEntriesRequest,
        AppendEntriesResponse,
        InstallSnapshotRequest,
        InstallSnapshotResponse,
        VoteResponse,
    },
};
use tonic::transport::Channel;

use crate::vfs::consensus::{
    NodeId,
    RaftConfig,
    proto::{self, raft_service_client::RaftServiceClient},
};

/// Per-target network instance vended by [`ReplicaNetwork`].
pub struct ReplicaNetwork {
    /// Peer address map: NodeId -> gRPC endpoint.
    peers: HashMap<NodeId, String>,
}

impl ReplicaNetwork {
    pub fn new(peers: HashMap<NodeId, String>) -> Self {
        Self { peers }
    }
}

impl RaftNetworkFactory<RaftConfig> for ReplicaNetwork {
    type Network = PeerNetwork;

    async fn new_client(&mut self, target: NodeId, _node: &BasicNode) -> Self::Network {
        let addr = self.peers.get(&target).cloned().unwrap_or_default();
        PeerNetwork { addr, target }
    }
}

/// Thin client wrapper: sends one AppendEntries RPC to a single peer.
///
/// openraft calls [`RaftNetwork`] to forward RPCs when this node is
/// the leader.
pub struct PeerClient {
    client: RaftServiceClient<Channel>,
    target: NodeId,
}

impl PeerClient {
    pub async fn connect(addr: &str, target: NodeId) -> Result<Self> {
        let client = RaftServiceClient::connect(addr.to_owned()).await?;
        Ok(Self { client, target })
    }
}

pub struct PeerNetwork {
    addr: String,
    target: NodeId,
}

impl RaftNetwork<RaftConfig> for PeerNetwork {
    async fn append_entries(
        &mut self,
        req: AppendEntriesRequest<RaftConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        use openraft::error::RPCError;

        let mut client = RaftServiceClient::connect(self.addr.clone())
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;

        let entries: Vec<proto::LogEntry> = req
            .entries
            .into_iter()
            .filter_map(|e| {
                if let EntryPayload::Normal(ref frame) = e.payload {
                    Some(proto::LogEntry {
                        index: e.log_id.index,
                        term: e.log_id.leader_id.term,
                        frame: Some(proto::WalFrame {
                            wal_offset: frame.wal_offset,
                            data: frame.data.clone(),
                            page_no: frame.page_no,
                        }),
                    })
                } else {
                    None
                }
            })
            .collect();

        let grpc_req = proto::AppendEntriesRequest {
            term: req.vote.leader_id.term,
            leader_id: req.vote.leader_id.voted_for().unwrap_or(0),
            prev_log_index: req.prev_log_id.map(|l| l.index).unwrap_or(0),
            prev_log_term: req.prev_log_id.map(|l| l.leader_id.term).unwrap_or(0),
            entries,
            leader_commit: req.leader_commit.map(|l| l.index).unwrap_or(0),
        };

        let resp = client
            .append_entries(grpc_req)
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?
            .into_inner();

        // Reconstruct an AppendEntriesResponse from the proto fields.
        if resp.success {
            Ok(AppendEntriesResponse::Success)
        } else {
            Ok(AppendEntriesResponse::HigherVote(Vote::new_committed(
                resp.term,
                self.target,
            )))
        }
    }

    async fn vote(
        &mut self,
        req: openraft::raft::VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        use openraft::error::RPCError;

        let mut client = RaftServiceClient::connect(self.addr.clone())
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;

        let grpc_req = proto::VoteRequest {
            term: req.vote.leader_id.term,
            candidate_id: req.vote.leader_id.voted_for().unwrap_or(0),
            last_log_index: req.last_log_id.map(|l| l.index).unwrap_or(0),
            last_log_term: req.last_log_id.map(|l| l.leader_id.term).unwrap_or(0),
        };

        let resp = client
            .request_vote(grpc_req)
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?
            .into_inner();

        Ok(VoteResponse {
            vote: Vote::new(resp.term, self.target),
            vote_granted: resp.vote_granted,
            last_log_id: None,
        })
    }

    async fn install_snapshot(
        &mut self,
        req: InstallSnapshotRequest<RaftConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        use openraft::error::RPCError;

        let mut client = RaftServiceClient::connect(self.addr.clone())
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;

        let grpc_req = proto::InstallSnapshotRequest {
            term: req.vote.leader_id.term,
            leader_id: req.vote.leader_id.voted_for().unwrap_or(0),
            metadata: Some(proto::SnapshotMetadata {
                last_included_index: req.meta.last_log_id.map(|l| l.index).unwrap_or(0),
                last_included_term: req.meta.last_log_id.map(|l| l.leader_id.term).unwrap_or(0),
            }),
            chunk: req.data,
            chunk_offset: req.offset,
            done: req.done,
        };

        let resp = client
            .install_snapshot(grpc_req)
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?
            .into_inner();

        Ok(InstallSnapshotResponse {
            vote: Vote::new_committed(resp.term, self.target),
        })
    }
}
