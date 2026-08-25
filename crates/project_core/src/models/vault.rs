use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use super::{
    Edge,
    History,
    Node,
    SecurityEvent,
    CypherNode,
    CypherEdge,
    CipherHistory,
    CipherSecurityEvent
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vault {
    pub nodes: HashMap<Uuid, Node>,
    pub edges: HashMap<Uuid, Edge>,
    pub history: HashMap<Uuid, History>,
    pub events: HashMap<Uuid, SecurityEvent>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaultResponse {
    pub nodes: Vec<CypherNode>,
    pub edges: Vec<CypherEdge>,
    pub history: Vec<CipherHistory>,
    pub events: Vec<CipherSecurityEvent>,
}