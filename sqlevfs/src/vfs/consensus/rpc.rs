use anyhow::{Context, Result};
use openraft::{
    CommittedLeaderId,
    Entry,
    EntryPayload,
    LogId,
    SnapshotMeta,
    StoredMembership,
    Vote,
    raft::{AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest},
};
use tonic::{Request, Response, Status, transport::Server};

use crate::vfs::consensus::{
    NodeId,
    RaftConfig,
    RaftNode,
    proto::{
        self,
        raft_service_server::{RaftService, RaftServiceServer},
    },
    wal::WalFrameEntry,
};

const TAG_BLANK: i64 = i64::MIN;
const TAG_MEMBERSHIP: i64 = i64::MIN + 1;

// -- gRPC service implementation --------------------------------------

pub struct RaftGrpcService {
    raft: super::RaftNode,
}

impl RaftGrpcService {
    pub fn new(raft: RaftNode) -> Self {
        Self { raft }
    }
}

#[tonic::async_trait]
impl RaftService for RaftGrpcService {
    async fn request_vote(
        &self,
        request: Request<proto::VoteRequest>,
    ) -> Result<Response<proto::VoteResponse>, Status> {
        let req = request.into_inner();
        let vote_req = openraft::raft::VoteRequest {
            vote: Vote::new(req.term, req.candidate_id),
            last_log_id: if req.last_log_index > 0 {
                Some(LogId::new(
                    CommittedLeaderId::new(req.last_log_term, req.candidate_id),
                    req.last_log_index,
                ))
            } else {
                None
            },
        };

        match self.raft.vote(vote_req).await {
            Ok(resp) => Ok(Response::new(proto::VoteResponse {
                // In openraft 0.9, Vote has a public `leader_id.term` field.
                term: resp.vote.leader_id.term,
                vote_granted: resp.vote_granted,
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn append_entries(
        &self,
        request: Request<proto::AppendEntriesRequest>,
    ) -> Result<Response<proto::AppendEntriesResponse>, Status> {
        let req = request.into_inner();

        let entries: Vec<Entry<RaftConfig>> = req
            .entries
            .into_iter()
            .map(|e| {
                let frame = e
                    .frame
                    .ok_or_else(|| Status::invalid_argument("append_entries: missing frame"))?;

                let payload = if frame.wal_offset == TAG_BLANK && frame.page_no == 0 {
                    EntryPayload::Blank
                } else if frame.wal_offset == TAG_MEMBERSHIP && frame.page_no == 0 {
                    let membership: openraft::Membership<NodeId, openraft::BasicNode> =
                        serde_json::from_slice(&frame.data).map_err(|err| {
                            Status::invalid_argument(format!(
                                "append_entries: invalid membership payload: {err}"
                            ))
                        })?;
                    EntryPayload::Membership(membership)
                } else {
                    EntryPayload::Normal(WalFrameEntry {
                        wal_offset: frame.wal_offset,
                        page_no: frame.page_no,
                        data: frame.data,
                    })
                };

                Ok(Entry {
                    log_id: LogId::new(CommittedLeaderId::new(e.term, req.leader_id), e.index),
                    payload,
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;

        let raft_req = AppendEntriesRequest {
            vote: Vote::new_committed(req.term, req.leader_id),
            prev_log_id: if req.prev_log_index > 0 {
                Some(LogId::new(
                    CommittedLeaderId::new(req.prev_log_term, req.leader_id),
                    req.prev_log_index,
                ))
            } else {
                None
            },
            entries,
            leader_commit: if req.leader_commit > 0 {
                Some(LogId::new(
                    CommittedLeaderId::new(req.term, req.leader_id),
                    req.leader_commit,
                ))
            } else {
                None
            },
        };

        match self.raft.append_entries(raft_req).await {
            Ok(resp) => {
                // openraft 0.9: AppendEntriesResponse is an enum.
                // Extract term from the contained vote.
                let (term, success, conflict_index) = match &resp {
                    AppendEntriesResponse::Success => (0u64, true, 0u64),
                    AppendEntriesResponse::PartialSuccess(ps) => {
                        let term = ps.map(|l| l.leader_id.term).unwrap_or(0);
                        (term, true, 0u64)
                    }
                    AppendEntriesResponse::Conflict => (0u64, false, 0u64),
                    AppendEntriesResponse::HigherVote(vote) => (vote.leader_id.term, false, 0u64),
                };
                Ok(Response::new(proto::AppendEntriesResponse {
                    term,
                    success,
                    conflict_index,
                }))
            }
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn install_snapshot(
        &self,
        request: Request<proto::InstallSnapshotRequest>,
    ) -> Result<Response<proto::InstallSnapshotResponse>, Status> {
        let req = request.into_inner();
        let meta = req.metadata.unwrap_or_default();

        let snapshot_meta = SnapshotMeta {
            last_log_id: Some(LogId::new(
                CommittedLeaderId::new(meta.last_included_term, req.leader_id),
                meta.last_included_index,
            )),
            last_membership: StoredMembership::default(),
            snapshot_id: format!("snap-{}", meta.last_included_index),
        };

        let raft_req = InstallSnapshotRequest {
            vote: Vote::new_committed(req.term, req.leader_id),
            meta: snapshot_meta,
            offset: req.chunk_offset,
            data: req.chunk,
            done: req.done,
        };

        match self.raft.install_snapshot(raft_req).await {
            Ok(resp) => Ok(Response::new(proto::InstallSnapshotResponse {
                term: resp.vote.leader_id.term,
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }
}

/// Spawn the gRPC server for inbound Raft RPCs.
///
/// Call once after [`RaftHandle::start`].
pub async fn serve_grpc(raft: RaftNode, listen_addr: std::net::SocketAddr) -> Result<()> {
    let svc = RaftServiceServer::new(RaftGrpcService::new(raft));
    Server::builder()
        .add_service(svc)
        .serve(listen_addr)
        .await
        .context("gRPC server error")
}
