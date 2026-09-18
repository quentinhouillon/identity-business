use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Node {
    pub id: Uuid,
    pub platform: String,
    pub username: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub password_expires_at: Option<DateTime<Utc>>,
    pub totp: Totp,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CipherNode {
    pub id: Uuid,
    pub password_expires_at: Option<DateTime<Utc>>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Totp {
    pub secret: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u32
}