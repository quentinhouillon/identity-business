use std::{collections::HashMap};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::{Edge, History, Node, SecurityEvent};

#[derive(Debug, Serialize, Deserialize)]
pub struct Vault {
    pub nodes: HashMap<String, Node>,
    pub edges: HashMap<String, Edge>,
    pub events: HashMap<String, SecurityEvent>,
    pub history: HashMap<String, History>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedVault {
    pub id: String,
    pub vault: Vec<u8>,
    pub last_scan: String,
    pub creation: DateTime<Utc>,
    pub modification: DateTime<Utc>,
}