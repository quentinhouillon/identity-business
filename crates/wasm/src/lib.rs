use std::collections::HashSet;

use serde_json::Value;
use uuid::Uuid;
use wasm_bindgen::prelude::*;

use project_core::{
    business::{
        graph_services::{dfs, spof},
        have_i_been_pwned_service,
    },
    crypto::{crypto, key, totp},
    models::{Edge, Node},
};

#[wasm_bindgen]
pub async fn check_passwords_wasm(passwords: Vec<String>) -> Result<JsValue, JsValue> {
    let results = have_i_been_pwned_service::check_passwords(passwords)
        .await
        .map_err(|error| JsValue::from_str(&error.to_string()))?;

    serde_wasm_bindgen::to_value(&results).map_err(|error| JsValue::from_str(&error.to_string()))
}

#[wasm_bindgen]
pub fn dfs_wasm(edges_json: &str, start_id: &str) -> Result<JsValue, JsValue> {
    let edges: Vec<Edge> =
        serde_json::from_str(edges_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let start_id = Uuid::parse_str(start_id).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut visited = HashSet::new();

    dfs(&edges, &start_id, &mut visited);

    Ok(serde_wasm_bindgen::to_value(&visited).map_err(|e| JsValue::from_str(&e.to_string()))?)
}

#[wasm_bindgen]
pub fn spof_wasm(edges_json: &str, start_id: &str) -> Result<JsValue, JsValue> {
    let edges: Vec<Edge> =
        serde_json::from_str(edges_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let start_id = Uuid::parse_str(start_id).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let spofs = spof(&edges, &[start_id]);

    let result: Vec<String> = spofs.into_iter().map(|id| id.to_string()).collect();

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn encrypt_wasm(key: &[u8], nonce: &[u8], value: JsValue) -> Result<JsValue, JsValue> {
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| JsValue::from_str("Key must be exactly 32 bytes"))?;

    let nonce: [u8; 24] = nonce
        .try_into()
        .map_err(|_| JsValue::from_str("nonce must be exactly 24 bytes"))?;

    let data: Value =
        serde_wasm_bindgen::from_value(value).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let json = serde_json::to_vec(&data).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let encrypted =
        crypto::encrypt(&key, &nonce, &json).map_err(|e| JsValue::from_str(&e.to_string()))?;

    serde_wasm_bindgen::to_value(&encrypted).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn decrypt_wasm(key: &[u8], nonce: &[u8], value: JsValue) -> Result<JsValue, JsValue> {
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| JsValue::from_str("Key must be exactly 32 bytes"))?;

    let nonce: [u8; 24] = nonce
        .try_into()
        .map_err(|_| JsValue::from_str("nonce must be exactly 24 bytes"))?;

    let data: Value =
        serde_wasm_bindgen::from_value(value).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let json = serde_json::to_vec(&data).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let decrypted =
        crypto::decrypt(&key, &nonce, &json).map_err(|e| JsValue::from_str(&e.to_string()))?;

    serde_wasm_bindgen::to_value(&decrypted).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn derive_master_key_wasm(master_password: &[u8], salt: &[u8]) -> Result<Vec<u8>, JsValue> {
    let key = key::derive_master_key(master_password, salt)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(key.to_vec())
}

#[wasm_bindgen]
pub fn generate_vault_key_wasm() -> Vec<u8> {
    key::generate_vault_key().to_vec()
}

#[wasm_bindgen]
pub fn get_totp_code(node: JsValue, timestamp: u64) -> Result<String, JsValue> {
    let node: Node =
        serde_wasm_bindgen::from_value(node).map_err(|e| JsValue::from_str(&e.to_string()))?;

    totp::generate_code(&node.totp, timestamp).map_err(|e| JsValue::from_str(&e.to_string()))
}
