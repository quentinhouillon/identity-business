use std::collections::HashMap;

use crate::models::{Edge, History, Node, SecurityEvent};


pub struct Vault {
    nodes: HashMap<String, Node>,
    edges: Vec<Edge>,
    events: Vec<SecurityEvent>,
    history: Vec<History>,
}