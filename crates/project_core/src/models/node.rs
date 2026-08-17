use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub platform: String,
    pub username: String,
    pub password: [u8; 32],
    pub salt: Vec<u8>,
    pub node_type: Identifier,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Identifier {
    Account,
    Email,
    Phone,
    OAuth,
}