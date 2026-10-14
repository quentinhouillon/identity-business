pub mod helper;

use std::collections::HashSet;

use helper::{decode_base64, decode_key, decode_uuid, encode_base64, js_error};

use project_core::import_export::json::{
    export_json as core_export_json,
    import_json as core_import_json,
};
use project_core::{
    business::{
        graph_services::{dfs, spof},
        have_i_been_pwned_service,
    },
    crypto::{crypto, key, totp},
    models::{Edge, History, Node, Vault},
};
use serde::Serialize;
use uuid::Uuid;
use wasm_bindgen::prelude::*;


#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyPairOut {
    private_key: String,
    public_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountKeysOut {
    enc_key: String,
    auth_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KdfParamsOut {
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
}

fn account_keys_to_js(keys: &key::AccountKeys) -> Result<JsValue, JsValue> {
    let out = AccountKeysOut {
        enc_key: encode_base64(&keys.enc_key[..]),
        auth_key: encode_base64(&keys.auth_key[..]),
    };

    serde_wasm_bindgen::to_value(&out).map_err(js_error)
}

/* -------------------------------------------------------------------------- */
/* Password breach check                                                      */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub async fn check_passwords_wasm(
    passwords: Vec<String>,
) -> Result<JsValue, JsValue> {
    let results = have_i_been_pwned_service::check_passwords(passwords)
        .await
        .map_err(js_error)?;

    serde_wasm_bindgen::to_value(&results).map_err(js_error)
}

/* -------------------------------------------------------------------------- */
/* Graph algorithms                                                           */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub fn dfs_wasm(
    edges_json: &str,
    start_id: &str,
) -> Result<JsValue, JsValue> {
    let edges: Vec<Edge> = serde_json::from_str(edges_json).map_err(js_error)?;
    let start_id = Uuid::parse_str(start_id).map_err(js_error)?;

    let mut visited = HashSet::new();

    dfs(&edges, &start_id, &mut visited);

    serde_wasm_bindgen::to_value(&visited).map_err(js_error)
}

#[wasm_bindgen]
pub fn spof_wasm(
    edges_json: &str,
    start_id: &str,
) -> Result<JsValue, JsValue> {
    let edges: Vec<Edge> = serde_json::from_str(edges_json).map_err(js_error)?;
    let start_id = Uuid::parse_str(start_id).map_err(js_error)?;

    let result: Vec<String> = spof(&edges, &[start_id])
        .into_iter()
        .map(|id| id.to_string())
        .collect();

    serde_wasm_bindgen::to_value(&result).map_err(js_error)
}

/* -------------------------------------------------------------------------- */
/* Generic Vault data encryption                                               */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub fn encrypt_wasm(
    key: &str,
    message_type: u8,
    vault_id: &str,
    object_id: &str,
    value: &str,
) -> Result<String, JsValue> {
    let key = decode_key(key)?;
    let vault_id = decode_uuid(vault_id, "vault_id")?;
    let object_id = decode_uuid(object_id, "object_id")?;
    let plaintext = decode_base64(value)?;

    let encrypted = crypto::encrypt_data(
        &key,
        message_type,
        &vault_id,
        &object_id,
        &plaintext,
    )
    .map_err(js_error)?;

    Ok(encode_base64(&encrypted))
}

#[wasm_bindgen]
pub fn decrypt_wasm(
    key: &str,
    message_type: u8,
    vault_id: &str,
    object_id: &str,
    value: &str,
) -> Result<String, JsValue> {
    let key = decode_key(key)?;
    let vault_id = decode_uuid(vault_id, "vault_id")?;
    let object_id = decode_uuid(object_id, "object_id")?;
    let encrypted = decode_base64(value)?;

    let plaintext = crypto::decrypt_data(
        &key,
        message_type,
        &vault_id,
        &object_id,
        &encrypted,
    )
    .map_err(js_error)?;

    Ok(encode_base64(&plaintext))
}

/* -------------------------------------------------------------------------- */
/* Account keys (password -> enc_key + auth_key)                               */
/* -------------------------------------------------------------------------- */

/// Salt aléatoire (inscription et changement de mot de passe).
#[wasm_bindgen]
pub fn generate_salt_wasm() -> Result<String, JsValue> {
    let salt = key::generate_salt().map_err(js_error)?;

    Ok(encode_base64(&salt))
}

/// Paramètres Argon2 par défaut, pour l'inscription.
#[wasm_bindgen]
pub fn default_kdf_params_wasm() -> Result<JsValue, JsValue> {
    let kdf = key::KdfParams::default();

    serde_wasm_bindgen::to_value(&KdfParamsOut {
        memory_kib: kdf.memory_kib,
        iterations: kdf.iterations,
        lanes: kdf.lanes,
    })
    .map_err(js_error)
}

/// Mot de passe + salt + paramètres de /prelogin -> { encKey, authKey }.
///
/// - `master_password` : texte brut (normalisez-le en NFKC côté JS avant l'appel).
/// - `salt`            : base64, tel que renvoyé par /prelogin.
/// - `encKey` reste dans le client, `authKey` part vers /login ou /register.
///
/// Argon2 est lourd : appelez cette fonction depuis un Web Worker.
#[wasm_bindgen]
pub fn derive_account_keys_wasm(
    master_password: &str,
    salt: &str,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
) -> Result<JsValue, JsValue> {
    let salt = decode_base64(salt)?;

    let kdf = key::KdfParams {
        memory_kib,
        iterations,
        lanes,
    };

    let keys = key::derive_account_keys(master_password.as_bytes(), &salt, kdf)
        .map_err(js_error)?;

    account_keys_to_js(&keys)
}

/* -------------------------------------------------------------------------- */
/* Recovery key                                                                */
/* -------------------------------------------------------------------------- */

/// Clé de récupération (256 bits), à afficher une seule fois.
#[wasm_bindgen]
pub fn generate_recovery_key_wasm() -> Result<String, JsValue> {
    let recovery_key = key::generate_recovery_key().map_err(js_error)?;

    Ok(encode_base64(&recovery_key[..]))
}

/// recovery_key -> { encKey, authKey }
/// (authKey = `recovery_auth_key` envoyé au serveur, encKey chiffre la copie
/// de secours de la clé privée).
#[wasm_bindgen]
pub fn derive_recovery_keys_wasm(recovery_key: &str) -> Result<JsValue, JsValue> {
    let recovery_key = decode_key(recovery_key)?;

    let keys = key::derive_recovery_keys(&recovery_key).map_err(js_error)?;

    account_keys_to_js(&keys)
}

/* -------------------------------------------------------------------------- */
/* Vault key                                                                   */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub fn generate_vault_key_wasm() -> Result<String, JsValue> {
    let vault_key = key::generate_vault_key().map_err(js_error)?;

    Ok(encode_base64(&vault_key))
}

/* -------------------------------------------------------------------------- */
/* X25519 key pair                                                             */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub fn generate_asymmetric_keypair_wasm() -> Result<JsValue, JsValue> {
    let (private_key, public_key) =
        key::generate_asymmetric_keypair().map_err(js_error)?;

    let out = KeyPairOut {
        private_key: encode_base64(&private_key),
        public_key: encode_base64(&public_key),
    };

    serde_wasm_bindgen::to_value(&out).map_err(js_error)
}

/* -------------------------------------------------------------------------- */
/* Vault key wrapping                                                          */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub fn encrypt_vault_key_wasm(
    recipient_public_key: &str,
    vault_id: &str,
    user_id: &str,
    vault_key: &str,
) -> Result<String, JsValue> {
    let recipient_public_key = decode_key(recipient_public_key)?;
    let vault_id = decode_uuid(vault_id, "vault_id")?;
    let user_id = decode_uuid(user_id, "user_id")?;
    let vault_key = decode_key(vault_key)?;

    let encrypted = crypto::encrypt_vault_key(
        &recipient_public_key,
        &vault_id,
        &user_id,
        &vault_key,
    )
    .map_err(js_error)?;

    Ok(encode_base64(&encrypted))
}

#[wasm_bindgen]
pub fn decrypt_vault_key_wasm(
    private_key: &str,
    vault_id: &str,
    user_id: &str,
    encrypted_vault_key: &str,
) -> Result<String, JsValue> {
    let private_key = decode_key(private_key)?;
    let vault_id = decode_uuid(vault_id, "vault_id")?;
    let user_id = decode_uuid(user_id, "user_id")?;
    let encrypted_vault_key = decode_base64(encrypted_vault_key)?;

    let vault_key = crypto::decrypt_vault_key(
        &private_key,
        &vault_id,
        &user_id,
        &encrypted_vault_key,
    )
    .map_err(js_error)?;

    Ok(encode_base64(&vault_key))
}

/* -------------------------------------------------------------------------- */
/* Private key encryption                                                     */
/* -------------------------------------------------------------------------- */

/// `enc_key` = `encKey` de derive_account_keys_wasm (mot de passe),
/// ou `encKey` de derive_recovery_keys_wasm (copie de secours).
#[wasm_bindgen]
pub fn encrypt_private_key_wasm(
    enc_key: &str,
    private_key: &str,
) -> Result<String, JsValue> {
    let enc_key = decode_key(enc_key)?;
    let private_key = decode_key(private_key)?;

    let encrypted =
        crypto::encrypt_private_key(&enc_key, &private_key).map_err(js_error)?;

    Ok(encode_base64(&encrypted))
}

#[wasm_bindgen]
pub fn decrypt_private_key_wasm(
    enc_key: &str,
    encrypted_private_key: &str,
) -> Result<String, JsValue> {
    let enc_key = decode_key(enc_key)?;
    let encrypted_private_key = decode_base64(encrypted_private_key)?;

    let private_key =
        crypto::decrypt_private_key(&enc_key, &encrypted_private_key)
            .map_err(js_error)?;

    Ok(encode_base64(&private_key))
}

/* -------------------------------------------------------------------------- */
/* TOTP                                                                        */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub fn get_totp_code(
    node: JsValue,
    timestamp: u64,
) -> Result<String, JsValue> {
    let node: Node = serde_wasm_bindgen::from_value(node).map_err(js_error)?;

    totp::generate_code(&node.totp, timestamp).map_err(js_error)
}

/* -------------------------------------------------------------------------- */
/* Import / export                                                             */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub fn export_json(
    vault: JsValue,
    nodes: JsValue,
    edges: JsValue,
    history: JsValue,
) -> Result<String, JsValue> {
    let vault: Vault = serde_wasm_bindgen::from_value(vault).map_err(js_error)?;
    let nodes: Vec<Node> = serde_wasm_bindgen::from_value(nodes).map_err(js_error)?;
    let edges: Vec<Edge> = serde_wasm_bindgen::from_value(edges).map_err(js_error)?;
    let history: Vec<History> =
        serde_wasm_bindgen::from_value(history).map_err(js_error)?;

    let data = core_export_json(&vault, &nodes, &edges, &history)
        .map_err(js_error)?;

    Ok(encode_base64(&data))
}

#[wasm_bindgen]
pub fn import_json(data: &str) -> Result<JsValue, JsValue> {
    let data = decode_base64(data)?;

    let bundle = core_import_json(&data)
        .map_err(|error| js_error(format!("{error:?}")))?;

    serde_wasm_bindgen::to_value(&bundle).map_err(js_error)
}