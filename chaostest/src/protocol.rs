use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub(crate) enum ChildRequest {
    Status,
    AddNode {
        node_id: u64,
        rpc_addr: String,
        wait_secs: u64,
    },
    Seed {
        seed: u64,
    },
    RunWorkload {
        duration_secs: u64,
        workers: usize,
        seed: u64,
    },
    ValidateLocal,
    ProbeFollowerWrite,
    Checkpoint,
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ChildResponse {
    pub(crate) ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

impl ChildResponse {
    pub(crate) fn ok(result: impl Serialize) -> Self {
        Self {
            ok: true,
            result: Some(serde_json::to_value(result).unwrap_or(serde_json::Value::Null)),
            error: None,
        }
    }

    pub(crate) fn err(err: impl ToString) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(err.to_string()),
        }
    }
}
