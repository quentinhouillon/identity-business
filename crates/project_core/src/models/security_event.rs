use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum Criticality {
    Low,
    Medium,
    High,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: i64,
    pub node_id: i64,
    pub title: String,
    pub criticality: Criticality,
    pub is_resolved: bool,
    pub resolved_at: Option<DateTime<Utc>>,
    pub creation: DateTime<Utc>,
}