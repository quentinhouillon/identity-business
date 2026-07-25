use std::collections::HashMap;


pub struct Vault {
    nodes: HashMap<String, Node>,
    edges: Vec<Edge>,
    events: Vec<CriticalEvent>,
    history: Vec<History>,
}