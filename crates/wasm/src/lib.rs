use std::collections::HashSet;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use project_core::import_export::json::{
    export_json as core_export_json,
    import_json as core_import_json,
};
use uuid::Uuid;
use wasm_bindgen::prelude::*;

use project_core::{
    business::{
        graph_services::{dfs, spof},
        have_i_been_pwned_service,
    },
    crypto::{crypto, key, totp},
    models::{Edge, History, Node, Vault},
};

fn decode_key(key: &str) -> Result<[u8; 32], JsValue> {
    STANDARD
        .decode(key)
        .map_err(|_| JsValue::from_str("Invalid Base64 key"))?
        .try_into()
        .map_err(|_| JsValue::from_str("Key must decode to exactly 32 bytes"))
}

fn decode_nonce(nonce: &str) -> Result<[u8; 24], JsValue> {
    STANDARD
        .decode(nonce)
        .map_err(|_| JsValue::from_str("Invalid Base64 nonce"))?
        .try_into()
        .map_err(|_| JsValue::from_str("Nonce must decode to exactly 24 bytes"))
}

fn decode_base64(value: &str) -> Result<Vec<u8>, JsValue> {
    STANDARD
        .decode(value)
        .map_err(|_| JsValue::from_str("Invalid Base64 data"))
}

fn encode_base64(value: &[u8]) -> String {
    STANDARD.encode(value)
}

#[wasm_bindgen]
pub async fn check_passwords_wasm(
    passwords: Vec<String>,
) -> Result<JsValue, JsValue> {
    let results = have_i_been_pwned_service::check_passwords(passwords)
        .await
        .map_err(|error| JsValue::from_str(&error.to_string()))?;

    serde_wasm_bindgen::to_value(&results)
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

#[wasm_bindgen]
pub fn dfs_wasm(
    edges_json: &str,
    start_id: &str,
) -> Result<JsValue, JsValue> {
    let edges: Vec<Edge> =
        serde_json::from_str(edges_json)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let start_id =
        Uuid::parse_str(start_id)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut visited = HashSet::new();

    dfs(&edges, &start_id, &mut visited);

    serde_wasm_bindgen::to_value(&visited)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn spof_wasm(
    edges_json: &str,
    start_id: &str,
) -> Result<JsValue, JsValue> {
    let edges: Vec<Edge> =
        serde_json::from_str(edges_json)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let start_id =
        Uuid::parse_str(start_id)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let spofs = spof(&edges, &[start_id]);

    let result: Vec<String> =
        spofs.into_iter().map(|id| id.to_string()).collect();

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn encrypt_wasm(
    key: &str,
    nonce: &str,
    value: &str,
) -> Result<String, JsValue> {
    let key = decode_key(key)?;
    let nonce = decode_nonce(nonce)?;
    let data = decode_base64(value)?;

    let encrypted =
        crypto::encrypt(&key, &nonce, &data)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(encode_base64(&encrypted))
}

#[wasm_bindgen]
pub fn decrypt_wasm(
    key: &str,
    nonce: &str,
    value: &str,
) -> Result<String, JsValue> {
    let key = decode_key(key)?;
    let nonce = decode_nonce(nonce)?;
    let encrypted = decode_base64(value)?;

    let decrypted =
        crypto::decrypt(&key, &nonce, &encrypted)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(encode_base64(&decrypted))
}

#[wasm_bindgen]
pub fn derive_master_key_wasm(
    master_password: &str,
    salt: &str,
) -> Result<String, JsValue> {
    let master_password = decode_base64(master_password)?;
    let salt = decode_base64(salt)?;

    let key =
        key::derive_master_key(&master_password, &salt)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(encode_base64(&key))
}

#[wasm_bindgen]
pub fn generate_vault_key_wasm() -> String {
    let key = key::generate_vault_key();

    encode_base64(&key)
}

#[wasm_bindgen]
pub fn generate_asymmetric_keypair_wasm()
    -> Result<JsValue, JsValue>
{
    let (private_key, public_key) =
        key::generate_asymmetric_keypair()
            .map_err(|error| JsValue::from_str(&error.to_string()))?;

    let result = serde_json::json!({
        "privateKey": encode_base64(&private_key),
        "publicKey": encode_base64(&public_key),
    });

    serde_wasm_bindgen::to_value(&result)
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

#[wasm_bindgen]
pub fn get_totp_code(
    node: JsValue,
    timestamp: u64,
) -> Result<String, JsValue> {
    let node: Node =
        serde_wasm_bindgen::from_value(node)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

    totp::generate_code(&node.totp, timestamp)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn export_json(
    vault: JsValue,
    nodes: JsValue,
    edges: JsValue,
    history: JsValue,
) -> Result<String, JsValue> {
    let vault: Vault =
        serde_wasm_bindgen::from_value(vault)
            .map_err(|err| JsValue::from_str(&err.to_string()))?;

    let nodes: Vec<Node> =
        serde_wasm_bindgen::from_value(nodes)
            .map_err(|err| JsValue::from_str(&err.to_string()))?;

    let edges: Vec<Edge> =
        serde_wasm_bindgen::from_value(edges)
            .map_err(|err| JsValue::from_str(&err.to_string()))?;

    let history: Vec<History> =
        serde_wasm_bindgen::from_value(history)
            .map_err(|err| JsValue::from_str(&err.to_string()))?;

    let data =
        core_export_json(&vault, &nodes, &edges, &history)
            .map_err(|err| JsValue::from_str(&err.to_string()))?;

    Ok(encode_base64(&data))
}

#[wasm_bindgen]
pub fn import_json(data: &str) -> Result<JsValue, JsValue> {
    let data = decode_base64(data)?;

    let bundle =
        core_import_json(&data)
            .map_err(|err| JsValue::from_str(&format!("{err:?}")))?;

    serde_wasm_bindgen::to_value(&bundle)
        .map_err(|err| JsValue::from_str(&err.to_string()))
}