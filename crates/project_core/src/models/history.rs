use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;


#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum HistoryAction {
    Create,
    Update,
    Delete,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct History {
    pub id: Uuid,
    pub node_id: Uuid,
    pub user_id: Uuid,
    pub action: HistoryAction,
    pub field: String,
    pub old_value: Option<Value>,
    pub new_value: Option<Value>,
    pub creation: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CipherHistory {
    pub id: Uuid,
    pub ciphertext: Vec<u8>,
}