use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;


#[derive(Debug, Serialize, Deserialize)]
pub enum HistoryAction {
    Create,
    Update,
    Delete,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct History {
    pub id: String,
    pub node_id: i64,
    pub user_id: i64,
    pub action: HistoryAction,
    pub field: String,
    pub old_value: Option<Value>,
    pub new_value: Option<Value>,
    pub creation: DateTime<Utc>,
}