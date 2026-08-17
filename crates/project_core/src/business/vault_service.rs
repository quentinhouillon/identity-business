use std::collections::HashMap;
use crate::{crypto::{crypto::{decrypt_vault, encrypt_vault}}, models::{Edge, EncryptedVault, History, Node, SecurityEvent, Vault}};

impl Vault {
    pub fn new(
        encrypted_vault: EncryptedVault,
        master_password: &str,
        user_salt: &[u8],
    ) -> Result<Self, CryptoError> {

        let vault =
            decrypt_vault(
                &encrypted_vault,
                master_password.as_bytes(),
                user_salt,
            )?;

        Ok(Self {
            nodes: vault.nodes,
            edges: vault.edges,
            history: vault.history,
            events: vault.events,
        })
    }

    pub fn encrypt(
        &self,
        id: String,
        master_password: &str,
        user_salt: &[u8],
        encrypted_vault: Option<&EncryptedVault>,
    ) -> Result<EncryptedVault, CryptoError> {

        encrypt_vault(
            id,
            self,
            master_password.as_bytes(),
            user_salt,
            encrypted_vault,
        )
    }

    pub fn get_nodes(&self) -> &HashMap<String, Node> {
        &self.nodes
    }

    pub fn get_node(&self, id: &str) -> Option<&Node> {
        self.nodes.get(id)
    }

    pub fn post_node(&mut self, node: Node) -> &mut Self {
        self.nodes.insert(node.id.clone(), node);
        self
    }

    pub fn put_node(&mut self, node: Node) -> Option<&mut Self> {
        if self.nodes.contains_key(&node.id) {
            self.nodes.insert(node.id.clone(), node);
            Some(self)
        } else {
            None
        }
    }

    pub fn delete_node(&mut self, id: &str) -> Option<Node> {
        self.nodes.remove(id)
    }

    pub fn get_edges(&self) -> &HashMap<String, Edge> {
        &self.edges
    }

    pub fn get_edge(&self, id: &str) -> Option<&Edge> {
        self.edges.get(id)
    }

    pub fn post_edge(&mut self, edge: Edge) -> &mut Self {
        self.edges.insert(edge.id.clone(), edge);
        self
    }

    pub fn put_edge(&mut self, edge: Edge) -> Option<&mut Self> {
        if self.edges.contains_key(&edge.id) {
            self.edges.insert(edge.id.clone(), edge);
            Some(self)
        } else {
            None
        }
    }

    pub fn delete_edge(&mut self, id: &str) -> Option<Edge> {
        self.edges.remove(id)
    }

    pub fn get_history(&self) -> &HashMap<String, History> {
        &self.history
    }

    pub fn post_history(&mut self, history: History) -> &mut Self {
        self.history.insert(history.id.clone(), history);
        self
    }

    pub fn get_events(&self) -> &HashMap<String, SecurityEvent> {
        &self.events
    }

    pub fn post_event(&mut self, event: SecurityEvent) -> &mut Self {
        self.events.insert(event.id.clone(), event);
        self
    }
}
