use std::collections::HashMap;

use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

use crate::{
    business::{
        api_service::ApiService,
        vault_error::VaultError,
    },
    crypto::{
        crypto::{decrypt, encrypt},
        key::derive_master_key,
    },
    models::{
        CipherHistory,
        CipherSecurityEvent,
        CypherEdge,
        CypherNode,
        Edge,
        History,
        HistoryAction,
        Node,
        SecurityEvent,
        Vault,
        VaultResponse,
    },
};

pub struct VaultService {
    vault: Vault,
    user_id: Uuid,
    master_key: [u8; 32],
    api: ApiService,
}

impl VaultService {
    // ============================================================
    // INITIALISATION
    // ============================================================

    pub async fn new(
        user_id: Uuid,
        master_password: &str,
        user_salt: &[u8],
        api: ApiService,
        token: Option<&str>,
    ) -> Result<Self, VaultError> {

        let master_key =
            derive_master_key(
                master_password.as_bytes(),
                user_salt,
            )?;

        let headers =
            Self::auth_headers(token);

        let data: VaultResponse =
            api
                .get(
                    &format!("/users/{}/vault", user_id),
                    headers,
                )
                .await?;

        let nodes =
            Self::decrypt_nodes(
                &master_key,
                data.nodes,
            )?;

        let edges =
            Self::decrypt_edges(
                &master_key,
                data.edges,
            )?;

        let history =
            Self::decrypt_history(
                &master_key,
                data.history,
            )?;

        let events =
            Self::decrypt_events(
                &master_key,
                data.events,
            )?;

        let vault =
            Vault {
                nodes,
                edges,
                history,
                events,
            };

        Ok(Self {
            vault,
            user_id,
            master_key,
            api,
        })
    }

    // ============================================================
    // VAULT
    // ============================================================

    pub fn get_vault(&self) -> &Vault {
        &self.vault
    }

    // ============================================================
    // NODES
    // ============================================================

    pub fn get_nodes(
        &self,
    ) -> &HashMap<Uuid, Node> {
        &self.vault.nodes
    }

    pub fn get_node(
        &self,
        id: Uuid,
    ) -> Option<&Node> {
        self.vault.nodes.get(&id)
    }

    pub async fn post_node(
        &mut self,
        node: Node,
        token: Option<&str>,
    ) -> Result<(), VaultError> {

        let encrypted =
            self.encrypt_node(&node)?;

        self.api
            .post::<CypherNode, _>(
                "/nodes",
                &encrypted,
                Self::auth_headers(token),
            )
            .await?;

        self.vault.nodes.insert(
            node.id,
            node,
        );

        Ok(())
    }

    pub async fn put_node(
        &mut self,
        node: Node,
        token: Option<&str>,
    ) -> Result<(), VaultError> {

        let old_node =
            self.vault
                .nodes
                .get(&node.id)
                .ok_or(VaultError::NodeNotFound)?
                .clone();

        let histories =
            self.create_node_history(
                &old_node,
                &node,
            )?;

        let encrypted_node =
            self.encrypt_node(&node)?;

        let headers =
            Self::auth_headers(token);

        // --------------------------------------------------------
        // Mise à jour du Node
        // --------------------------------------------------------

        self.api
            .put::<CypherNode, _>(
                &format!("/nodes/{}", node.id),
                &encrypted_node,
                headers.clone(),
            )
            .await?;

        // --------------------------------------------------------
        // Création de l'historique
        // --------------------------------------------------------

        for history in histories {

            let encrypted_history =
                self.encrypt_history(&history)?;

            self.api
                .post::<CipherHistory, _>(
                    "/history",
                    &encrypted_history,
                    headers.clone(),
                )
                .await?;

            self.vault.history.insert(
                history.id,
                history,
            );
        }

        // --------------------------------------------------------
        // Mise à jour locale
        // --------------------------------------------------------

        self.vault.nodes.insert(
            node.id,
            node,
        );

        Ok(())
    }

    pub async fn delete_node(
        &mut self,
        id: Uuid,
        token: Option<&str>,
    ) -> Result<(), VaultError> {

        let node =
            self.vault
                .nodes
                .get(&id)
                .ok_or(VaultError::NodeNotFound)?
                .clone();

        let headers =
            Self::auth_headers(token);

        // --------------------------------------------------------
        // Suppression du Node
        // --------------------------------------------------------

        self.api
            .delete::<Value>(
                &format!("/nodes/{}", id),
                headers.clone(),
            )
            .await?;

        // --------------------------------------------------------
        // Création de l'historique
        // --------------------------------------------------------

        let history =
            History {
                id: Uuid::new_v4(),
                node_id: node.id,
                user_id: self.user_id,
                action: HistoryAction::Delete,
                field: "node".to_string(),
                old_value: Some(
                    serde_json::to_value(&node)
                        .map_err(
                            |_| VaultError::Serialization
                        )?,
                ),
                new_value: None,
                creation: Utc::now(),
            };

        let encrypted_history =
            self.encrypt_history(&history)?;

        self.api
            .post::<CipherHistory, _>(
                "/history",
                &encrypted_history,
                headers,
            )
            .await?;

        self.vault.history.insert(
            history.id,
            history,
        );

        // --------------------------------------------------------
        // Suppression locale
        // --------------------------------------------------------

        self.vault.nodes.remove(&id);

        Ok(())
    }

    // ============================================================
    // EDGES
    // ============================================================

    pub fn get_edges(
        &self,
    ) -> &HashMap<Uuid, Edge> {
        &self.vault.edges
    }

    pub fn get_edge(
        &self,
        id: Uuid,
    ) -> Option<&Edge> {
        self.vault.edges.get(&id)
    }

    pub async fn post_edge(
        &mut self,
        edge: Edge,
        token: Option<&str>,
    ) -> Result<(), VaultError> {

        let encrypted =
            self.encrypt_edge(&edge)?;

        self.api
            .post::<CypherEdge, _>(
                "/edges",
                &encrypted,
                Self::auth_headers(token),
            )
            .await?;

        self.vault.edges.insert(
            edge.id,
            edge,
        );

        Ok(())
    }

    pub async fn put_edge(
        &mut self,
        edge: Edge,
        token: Option<&str>,
    ) -> Result<(), VaultError> {

        if !self.vault.edges.contains_key(&edge.id) {
            return Err(VaultError::EdgeNotFound);
        }

        let encrypted =
            self.encrypt_edge(&edge)?;

        self.api
            .put::<CypherEdge, _>(
                &format!("/edges/{}", edge.id),
                &encrypted,
                Self::auth_headers(token),
            )
            .await?;

        self.vault.edges.insert(
            edge.id,
            edge,
        );

        Ok(())
    }

    pub async fn delete_edge(
        &mut self,
        id: Uuid,
        token: Option<&str>,
    ) -> Result<(), VaultError> {

        if !self.vault.edges.contains_key(&id) {
            return Err(VaultError::EdgeNotFound);
        }

        self.api
            .delete::<Value>(
                &format!("/edges/{}", id),
                Self::auth_headers(token),
            )
            .await?;

        self.vault.edges.remove(&id);

        Ok(())
    }

    // ============================================================
    // HISTORY
    // ============================================================

    pub fn get_history(
        &self,
    ) -> &HashMap<Uuid, History> {
        &self.vault.history
    }

    // ============================================================
    // EVENTS
    // ============================================================

    pub fn get_events(
        &self,
    ) -> &HashMap<Uuid, SecurityEvent> {
        &self.vault.events
    }

    // ============================================================
    // CRYPTO - NODE
    // ============================================================

    fn encrypt_node(
        &self,
        node: &Node,
    ) -> Result<CypherNode, VaultError> {

        let serialized =
            serde_json::to_vec(node)
                .map_err(
                    |_| VaultError::Serialization
                )?;

        let ciphertext =
            encrypt(
                &self.master_key,
                &serialized,
            )?;

        Ok(CypherNode {
            id: node.id,
            password_expires_at:
                node.password_expires_at,
            ciphertext,
        })
    }

    // ============================================================
    // CRYPTO - EDGE
    // ============================================================

    fn encrypt_edge(
        &self,
        edge: &Edge,
    ) -> Result<CypherEdge, VaultError> {

        let serialized =
            serde_json::to_vec(edge)
                .map_err(
                    |_| VaultError::Serialization
                )?;

        let ciphertext =
            encrypt(
                &self.master_key,
                &serialized,
            )?;

        Ok(CypherEdge {
            id: edge.id,
            password_expires_at: None,
            ciphertext,
        })
    }

    // ============================================================
    // CRYPTO - HISTORY
    // ============================================================

    fn encrypt_history(
        &self,
        history: &History,
    ) -> Result<CipherHistory, VaultError> {

        let serialized =
            serde_json::to_vec(history)
                .map_err(
                    |_| VaultError::Serialization
                )?;

        let ciphertext =
            encrypt(
                &self.master_key,
                &serialized,
            )?;

        Ok(CipherHistory {
            id: history.id,
            ciphertext,
        })
    }

    // ============================================================
    // CRYPTO - EVENT
    // ============================================================

    fn encrypt_event(
        &self,
        event: &SecurityEvent,
    ) -> Result<CipherSecurityEvent, VaultError> {

        let serialized =
            serde_json::to_vec(event)
                .map_err(
                    |_| VaultError::Serialization
                )?;

        let ciphertext =
            encrypt(
                &self.master_key,
                &serialized,
            )?;

        Ok(CipherSecurityEvent {
            id: event.id,
            ciphertext,
        })
    }

    // ============================================================
    // DECRYPTION - NODES
    // ============================================================

    fn decrypt_nodes(
        master_key: &[u8; 32],
        nodes: Vec<CypherNode>,
    ) -> Result<HashMap<Uuid, Node>, VaultError> {

        let mut result =
            HashMap::new();

        for encrypted_node in nodes {

            let serialized =
                decrypt(
                    master_key,
                    &encrypted_node.ciphertext,
                )?;

            let node: Node =
                serde_json::from_slice(&serialized)
                    .map_err(
                        |_| VaultError::Serialization
                    )?;

            result.insert(
                node.id,
                node,
            );
        }

        Ok(result)
    }

    // ============================================================
    // DECRYPTION - EDGES
    // ============================================================

    fn decrypt_edges(
        master_key: &[u8; 32],
        edges: Vec<CypherEdge>,
    ) -> Result<HashMap<Uuid, Edge>, VaultError> {

        let mut result =
            HashMap::new();

        for encrypted_edge in edges {

            let serialized =
                decrypt(
                    master_key,
                    &encrypted_edge.ciphertext,
                )?;

            let edge: Edge =
                serde_json::from_slice(&serialized)
                    .map_err(
                        |_| VaultError::Serialization
                    )?;

            result.insert(
                edge.id,
                edge,
            );
        }

        Ok(result)
    }

    // ============================================================
    // DECRYPTION - HISTORY
    // ============================================================

    fn decrypt_history(
        master_key: &[u8; 32],
        history: Vec<CipherHistory>,
    ) -> Result<HashMap<Uuid, History>, VaultError> {

        let mut result =
            HashMap::new();

        for encrypted_history in history {

            let serialized =
                decrypt(
                    master_key,
                    &encrypted_history.ciphertext,
                )?;

            let item: History =
                serde_json::from_slice(&serialized)
                    .map_err(
                        |_| VaultError::Serialization
                    )?;

            result.insert(
                item.id,
                item,
            );
        }

        Ok(result)
    }

    // ============================================================
    // DECRYPTION - EVENTS
    // ============================================================

    fn decrypt_events(
        master_key: &[u8; 32],
        events: Vec<CipherSecurityEvent>,
    ) -> Result<HashMap<Uuid, SecurityEvent>, VaultError> {

        let mut result =
            HashMap::new();

        for encrypted_event in events {

            let serialized =
                decrypt(
                    master_key,
                    &encrypted_event.ciphertext,
                )?;

            let event: SecurityEvent =
                serde_json::from_slice(&serialized)
                    .map_err(
                        |_| VaultError::Serialization
                    )?;

            result.insert(
                event.id,
                event,
            );
        }

        Ok(result)
    }

    // ============================================================
    // HISTORY GENERATION
    // ============================================================

    fn create_node_history(
        &self,
        old_node: &Node,
        new_node: &Node,
    ) -> Result<Vec<History>, VaultError> {

        let old =
            serde_json::to_value(old_node)
                .map_err(
                    |_| VaultError::Serialization
                )?;

        let new =
            serde_json::to_value(new_node)
                .map_err(
                    |_| VaultError::Serialization
                )?;

        let old_object =
            old.as_object()
                .ok_or(VaultError::Serialization)?;

        let new_object =
            new.as_object()
                .ok_or(VaultError::Serialization)?;

        let mut histories =
            Vec::new();

        for field in new_object.keys() {

            let old_value =
                old_object.get(field);

            let new_value =
                new_object.get(field);

            if old_value != new_value {

                histories.push(
                    History {
                        id: Uuid::new_v4(),
                        node_id: new_node.id,
                        user_id: self.user_id,
                        action: HistoryAction::Update,
                        field: field.clone(),
                        old_value: old_value.cloned(),
                        new_value: new_value.cloned(),
                        creation: Utc::now(),
                    }
                );
            }
        }

        Ok(histories)
    }

    // ============================================================
    // AUTH
    // ============================================================

    fn auth_headers(
        token: Option<&str>,
    ) -> Option<Vec<(&str, &str)>> {

        token.map(|token| {
            vec![
                ("Authorization", token),
            ]
        })
    }
}