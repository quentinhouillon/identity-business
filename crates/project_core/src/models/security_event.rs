use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Criticality {
    Low,
    Medium,
    High,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityEvent {
    pub id: Uuid,
    pub node_id: Uuid,
    pub title: String,
    pub criticality: Criticality,
    pub is_resolved: bool,
    pub resolved_at: Option<DateTime<Utc>>,
    pub creation: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CipherSecurityEvent {
    pub id: Uuid,
    pub ciphertext: Vec<u8>,
}