use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Identifier {
    Email,
    Phone,
    OAuth,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Edge {
    pub id: Uuid,
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub node_type: Identifier,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CypherEdge {
    pub id: Uuid,
    pub password_expires_at: Option<DateTime<Utc>>,
    pub ciphertext: Vec<u8>,
}