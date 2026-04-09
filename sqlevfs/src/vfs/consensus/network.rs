use std::{collections::HashMap, time::Duration};

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
use tokio::time::sleep;
use tonic::transport::Channel;

use crate::vfs::consensus::{
    NodeId,
    RaftConfig,
    proto::{self, raft_service_client::RaftServiceClient},
    wal::WalRecord,
};

const TAG_BLANK: i64 = i64::MIN;
const TAG_MEMBERSHIP: i64 = i64::MIN + 1;

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

    async fn new_client(&mut self, target: NodeId, node: &BasicNode) -> Self::Network {
        let addr = self
            .peers
            .get(&target)
            .cloned()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| node.addr.clone());
        if !addr.is_empty() {
            self.peers.insert(target, addr.clone());
        }
        PeerNetwork {
            addr,
            target,
            client: None,
        }
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

    pub fn target(&self) -> NodeId {
        self.target
    }

    pub fn inner(&mut self) -> &mut RaftServiceClient<Channel> {
        &mut self.client
    }
}

pub struct PeerNetwork {
    addr: String,
    target: NodeId,
    client: Option<RaftServiceClient<Channel>>,
}

impl PeerNetwork {
    async fn connect_client(
        &self,
    ) -> Result<RaftServiceClient<Channel>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        RaftServiceClient::connect(self.addr.clone())
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))
    }

    async fn ensure_client(
        &mut self,
    ) -> Result<&mut RaftServiceClient<Channel>, RPCError<NodeId, BasicNode, RaftError<NodeId>>>
    {
        if self.client.is_none() {
            self.client = Some(self.connect_client().await?);
        }

        Ok(self.client.as_mut().expect("client should exist"))
    }
}

impl RaftNetwork<RaftConfig> for PeerNetwork {
    async fn append_entries(
        &mut self,
        req: AppendEntriesRequest<RaftConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let mut entries = Vec::with_capacity(req.entries.len());
        for e in req.entries {
            match e.payload {
                EntryPayload::Normal(record) => entries.push(proto::LogEntry {
                    index: e.log_id.index,
                    term: e.log_id.leader_id.term,
                    record: Some(match record {
                        WalRecord::Header { data } => proto::WalRecord {
                            kind: 1,
                            wal_offset: 0,
                            data,
                            page_no: 0,
                        },
                        WalRecord::Frame {
                            wal_offset,
                            data,
                            page_no,
                        } => proto::WalRecord {
                            kind: 0,
                            wal_offset,
                            data,
                            page_no,
                        },
                    }),
                }),
                EntryPayload::Blank => entries.push(proto::LogEntry {
                    index: e.log_id.index,
                    term: e.log_id.leader_id.term,
                    record: Some(proto::WalRecord {
                        kind: 2,
                        wal_offset: TAG_BLANK,
                        data: Vec::new(),
                        page_no: 0,
                    }),
                }),
                EntryPayload::Membership(membership) => {
                    let encoded = serde_json::to_vec(&membership).map_err(|err| {
                        let io = std::io::Error::other(format!(
                            "failed to encode membership entry: {err}"
                        ));
                        RPCError::Network(NetworkError::new(&io))
                    })?;

                    entries.push(proto::LogEntry {
                        index: e.log_id.index,
                        term: e.log_id.leader_id.term,
                        record: Some(proto::WalRecord {
                            kind: 3,
                            wal_offset: TAG_MEMBERSHIP,
                            data: encoded,
                            page_no: 0,
                        }),
                    });
                }
            }
        }

        let grpc_req = proto::AppendEntriesRequest {
            term: req.vote.leader_id.term,
            leader_id: req.vote.leader_id.voted_for().unwrap_or(0),
            prev_log_index: req.prev_log_id.map(|l| l.index).unwrap_or(0),
            prev_log_term: req.prev_log_id.map(|l| l.leader_id.term).unwrap_or(0),
            entries,
            leader_commit: req.leader_commit.map(|l| l.index).unwrap_or(0),
        };

        let mut last_err: Option<RPCError<NodeId, BasicNode, RaftError<NodeId>>> = None;
        let mut resp = None;
        for attempt in 0..3 {
            let call = self
                .ensure_client()
                .await?
                .append_entries(grpc_req.clone())
                .await;

            match call {
                Ok(r) => {
                    resp = Some(r.into_inner());
                    break;
                }
                Err(e) => {
                    self.client = None;
                    last_err = Some(RPCError::Network(NetworkError::new(&e)));
                    if attempt < 2 {
                        sleep(Duration::from_millis(50 * (1 << attempt))).await;
                    }
                }
            }
        }

        let resp = match resp {
            Some(r) => r,
            None => {
                return Err(last_err.unwrap_or_else(|| {
                    let err = std::io::Error::other("append_entries failed without response");
                    RPCError::Network(NetworkError::new(&err))
                }));
            }
        };

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
        let grpc_req = proto::VoteRequest {
            term: req.vote.leader_id.term,
            candidate_id: req.vote.leader_id.voted_for().unwrap_or(0),
            last_log_index: req.last_log_id.map(|l| l.index).unwrap_or(0),
            last_log_term: req.last_log_id.map(|l| l.leader_id.term).unwrap_or(0),
        };

        let mut last_err: Option<RPCError<NodeId, BasicNode, RaftError<NodeId>>> = None;
        let mut resp = None;
        for attempt in 0..3 {
            let call = self.ensure_client().await?.request_vote(grpc_req).await;
            match call {
                Ok(r) => {
                    resp = Some(r.into_inner());
                    break;
                }
                Err(e) => {
                    self.client = None;
                    last_err = Some(RPCError::Network(NetworkError::new(&e)));
                    if attempt < 2 {
                        sleep(Duration::from_millis(50 * (1 << attempt))).await;
                    }
                }
            }
        }

        let resp = match resp {
            Some(r) => r,
            None => {
                return Err(last_err.unwrap_or_else(|| {
                    let err = std::io::Error::other("request_vote failed without response");
                    RPCError::Network(NetworkError::new(&err))
                }));
            }
        };

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

        let mut last_err: Option<
            RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
        > = None;
        let mut resp = None;
        for attempt in 0..3 {
            if self.client.is_none() {
                self.client = Some(
                    RaftServiceClient::connect(self.addr.clone())
                        .await
                        .map_err(|e| RPCError::Network(NetworkError::new(&e)))?,
                );
            }

            let call = self
                .client
                .as_mut()
                .expect("client should exist")
                .install_snapshot(grpc_req.clone())
                .await;

            match call {
                Ok(r) => {
                    resp = Some(r.into_inner());
                    break;
                }
                Err(e) => {
                    self.client = None;
                    last_err = Some(RPCError::Network(NetworkError::new(&e)));
                    if attempt < 2 {
                        sleep(Duration::from_millis(50 * (1 << attempt))).await;
                    }
                }
            }
        }

        let resp = match resp {
            Some(r) => r,
            None => {
                return Err(last_err.unwrap_or_else(|| {
                    let err = std::io::Error::other("install_snapshot failed without response");
                    RPCError::Network(NetworkError::new(&err))
                }));
            }
        };

        Ok(InstallSnapshotResponse {
            vote: Vote::new_committed(resp.term, self.target),
        })
    }
}
