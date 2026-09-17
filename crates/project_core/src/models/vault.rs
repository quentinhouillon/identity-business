use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vault {
    pub id: Uuid,
    pub name: String,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultMemberRole {
    #[serde(rename = "owner")]
    Owner,
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "write")]
    Write,
    #[serde(rename = "read")]
    Read,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaultMember {
    pub id: Uuid,
    pub user_id: Uuid,
    pub vault_id: Uuid,
    pub role: VaultMemberRole,
    pub encrypted_vault_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
}