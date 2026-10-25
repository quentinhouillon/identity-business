pub mod helper;

use std::collections::HashSet;

use helper::{
    crypto_error, decode_base64, decode_key, decode_signature, decode_uuid, encode_base64,
    encode_uuid, js_error,
};

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
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wasm_bindgen::prelude::*;

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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicIdentityOut {
    user_id: String,
    x25519_public: String,
    ed25519_public: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicIdentityIn {
    user_id: String,
    x25519_public: String,
    ed25519_public: String,
    signature: String,
}

fn account_keys_to_js(keys: &key::AccountKeys) -> Result<JsValue, JsValue> {
    let out = AccountKeysOut {
        enc_key: encode_base64(&keys.enc_key[..]),
        auth_key: encode_base64(&keys.auth_key[..]),
    };

    serde_wasm_bindgen::to_value(&out).map_err(js_error)
}

fn read_public_identity(value: JsValue) -> Result<key::PublicIdentity, JsValue> {
    let input: PublicIdentityIn = serde_wasm_bindgen::from_value(value).map_err(js_error)?;

    Ok(key::PublicIdentity {
        user_id: decode_uuid(&input.user_id, "user_id")?.to_vec(),
        x25519_public: decode_key(&input.x25519_public)?,
        ed25519_public: decode_key(&input.ed25519_public)?,
        signature: decode_signature(&input.signature)?,
    })
}

fn public_identity_to_js(identity: &key::PublicIdentity) -> Result<JsValue, JsValue> {
    let out = PublicIdentityOut {
        user_id: encode_uuid(&identity.user_id)?,
        x25519_public: encode_base64(&identity.x25519_public),
        ed25519_public: encode_base64(&identity.ed25519_public),
        signature: encode_base64(&identity.signature),
    };

    serde_wasm_bindgen::to_value(&out).map_err(js_error)
}

/* -------------------------------------------------------------------------- */
/* Password breach check                                                     */
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
/* Graph algorithms                                                          */
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
/* Vault data encryption                                                      */
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

    let encrypted = crypto::encrypt_data(&key, message_type, &vault_id, &object_id, &plaintext)
        .map_err(crypto_error)?;

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

    let plaintext = crypto::decrypt_data(&key, message_type, &vault_id, &object_id, &encrypted)
        .map_err(crypto_error)?;

    Ok(encode_base64(&plaintext))
}

/* -------------------------------------------------------------------------- */
/* Account keys (password -> enc_key + auth_key)                              */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub fn generate_salt_wasm() -> Result<String, JsValue> {
    let salt = key::generate_salt().map_err(crypto_error)?;

    Ok(encode_base64(&salt))
}

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

/// Password + salt + /prelogin parameters -> { encKey, authKey }.
/// Normalize the password to NFKC in JS first. Argon2 is heavy: call this from
/// a Web Worker.
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
        .map_err(crypto_error)?;

    account_keys_to_js(&keys)
}

/* -------------------------------------------------------------------------- */
/* Recovery key                                                               */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub fn generate_recovery_key_wasm() -> Result<String, JsValue> {
    let recovery_key = key::generate_recovery_key().map_err(crypto_error)?;

    Ok(encode_base64(&recovery_key[..]))
}

/// recovery_key -> { encKey, authKey }
#[wasm_bindgen]
pub fn derive_recovery_keys_wasm(recovery_key: &str) -> Result<JsValue, JsValue> {
    let recovery_key = decode_key(recovery_key)?;

    let keys = key::derive_recovery_keys(&recovery_key).map_err(crypto_error)?;

    account_keys_to_js(&keys)
}

/* -------------------------------------------------------------------------- */
/* Vault key                                                                  */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub fn generate_vault_key_wasm() -> Result<String, JsValue> {
    let vault_key = key::generate_vault_key().map_err(crypto_error)?;

    Ok(encode_base64(&vault_key[..]))
}

/* -------------------------------------------------------------------------- */
/* Identity (X25519 + Ed25519)                                                */
/* -------------------------------------------------------------------------- */

/// Handle to the private identity. Secrets stay inside WASM memory.
/// Call `.free()` from JS when done to wipe them.
#[wasm_bindgen]
pub struct Identity {
    inner: key::IdentityKeys,
}

#[wasm_bindgen]
impl Identity {
    pub fn x25519_public(&self) -> String {
        encode_base64(&self.inner.x25519_public)
    }

    pub fn ed25519_public(&self) -> String {
        encode_base64(&self.inner.ed25519_public)
    }

    /// Signed binding { userId, x25519Public, ed25519Public, signature }
    /// to send to the server at registration.
    pub fn public_identity(&self, user_id: &str) -> Result<JsValue, JsValue> {
        let user_id = decode_uuid(user_id, "user_id")?;

        let public =
            key::PublicIdentity::sign(&self.inner, &user_id).map_err(crypto_error)?;

        public_identity_to_js(&public)
    }
}

/// A peer identity that passed `verify_peer_identity_wasm`.
#[wasm_bindgen]
pub struct PeerIdentity {
    inner: key::VerifiedIdentity,
    status: key::TrustStatus,
}

#[wasm_bindgen]
impl PeerIdentity {
    pub fn user_id(&self) -> Result<String, JsValue> {
        encode_uuid(self.inner.user_id())
    }

    pub fn x25519_public(&self) -> String {
        encode_base64(self.inner.x25519_public())
    }

    /// Store this value to pin the peer.
    pub fn ed25519_public(&self) -> String {
        encode_base64(self.inner.ed25519_public())
    }

    /// "pinned" or "first_use".
    pub fn status(&self) -> String {
        match self.status {
            key::TrustStatus::Pinned => "pinned".to_string(),
            key::TrustStatus::FirstUse => "first_use".to_string(),
        }
    }
}

#[wasm_bindgen]
pub fn generate_identity_wasm() -> Result<Identity, JsValue> {
    let inner = key::IdentityKeys::generate().map_err(crypto_error)?;

    Ok(Identity { inner })
}

/// Encrypts the private keys with `enc_key` (password or recovery).
#[wasm_bindgen]
pub fn encrypt_identity_wasm(
    identity: &Identity,
    enc_key: &str,
    user_id: &str,
) -> Result<String, JsValue> {
    let enc_key = decode_key(enc_key)?;
    let user_id = decode_uuid(user_id, "user_id")?;

    let encrypted = crypto::encrypt_identity(&enc_key, &identity.inner, &user_id)
        .map_err(crypto_error)?;

    Ok(encode_base64(&encrypted))
}

/// `own_identity` must come from local storage, not from a fresh server reply.
/// Expected shape: { userId, x25519Public, ed25519Public, signature }.
#[wasm_bindgen]
pub fn decrypt_identity_wasm(
    enc_key: &str,
    own_identity: JsValue,
    encrypted_identity: &str,
) -> Result<Identity, JsValue> {
    let enc_key = decode_key(enc_key)?;
    let own_identity = read_public_identity(own_identity)?;
    let encrypted = decode_base64(encrypted_identity)?;

    let inner = crypto::decrypt_identity(&enc_key, &own_identity, &encrypted)
        .map_err(crypto_error)?;

    Ok(Identity { inner })
}

/// Verifies a public identity received from the server.
/// Throws IDENTITY_MISMATCH, INVALID_SIGNATURE or IDENTITY_KEY_CHANGED.
#[wasm_bindgen]
pub fn verify_peer_identity_wasm(
    received: JsValue,
    expected_user_id: &str,
    pinned_ed25519: Option<String>,
) -> Result<PeerIdentity, JsValue> {
    let received = read_public_identity(received)?;
    let expected_user_id = decode_uuid(expected_user_id, "user_id")?;
    let pinned = pinned_ed25519.as_deref().map(decode_key).transpose()?;

    let (inner, status) =
        key::verify_peer_identity(&received, &expected_user_id, pinned.as_ref())
            .map_err(crypto_error)?;

    Ok(PeerIdentity { inner, status })
}

/// Own identity as a verified peer, needed to wrap a Vault key for yourself.
#[wasm_bindgen]
pub fn self_peer_wasm(identity: &Identity, user_id: &str) -> Result<PeerIdentity, JsValue> {
    let user_id = decode_uuid(user_id, "user_id")?;

    let public = key::PublicIdentity::sign(&identity.inner, &user_id).map_err(crypto_error)?;

    let (inner, status) = key::verify_peer_identity(
        &public,
        &user_id,
        Some(&identity.inner.ed25519_public),
    )
    .map_err(crypto_error)?;

    Ok(PeerIdentity { inner, status })
}

/// Fingerprint to compare out of band.
#[wasm_bindgen]
pub fn fingerprint_wasm(public_identity: JsValue) -> Result<String, JsValue> {
    let public = read_public_identity(public_identity)?;

    public.fingerprint().map_err(crypto_error)
}

/* -------------------------------------------------------------------------- */
/* Vault key sharing                                                          */
/* -------------------------------------------------------------------------- */

/// Returns the Base64 blob to store next to vault_id, sender_id and recipient_id.
#[wasm_bindgen]
pub fn encrypt_vault_key_wasm(
    sender: &Identity,
    sender_id: &str,
    recipient: &PeerIdentity,
    vault_id: &str,
    vault_key: &str,
) -> Result<String, JsValue> {
    let sender_id = decode_uuid(sender_id, "sender_id")?;
    let vault_id = decode_uuid(vault_id, "vault_id")?;
    let vault_key = decode_key(vault_key)?;

    let wrapped = crypto::encrypt_vault_key(
        &sender.inner,
        &sender_id,
        &recipient.inner,
        &vault_id,
        &vault_key,
    )
    .map_err(crypto_error)?;

    Ok(encode_base64(&wrapped.to_bytes()))
}

#[wasm_bindgen]
pub fn decrypt_vault_key_wasm(
    recipient: &Identity,
    recipient_id: &str,
    sender: &PeerIdentity,
    vault_id: &str,
    wrapped_vault_key: &str,
) -> Result<String, JsValue> {
    let recipient_id = decode_uuid(recipient_id, "recipient_id")?;
    let vault_id = decode_uuid(vault_id, "vault_id")?;
    let bytes = decode_base64(wrapped_vault_key)?;

    let wrapped = crypto::WrappedVaultKey::from_bytes(
        &vault_id,
        sender.inner.user_id(),
        &recipient_id,
        &bytes,
    )
    .map_err(crypto_error)?;

    let vault_key = crypto::decrypt_vault_key(
        &recipient.inner,
        &recipient_id,
        &sender.inner,
        &wrapped,
        &vault_id,
    )
    .map_err(crypto_error)?;

    Ok(encode_base64(&vault_key[..]))
}

/* -------------------------------------------------------------------------- */
/* TOTP                                                                       */
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
/* Import / export                                                            */
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

    let data = core_export_json(&vault, &nodes, &edges, &history).map_err(js_error)?;

    Ok(encode_base64(&data))
}

#[wasm_bindgen]
pub fn import_json(data: &str) -> Result<JsValue, JsValue> {
    let data = decode_base64(data)?;

    let bundle = core_import_json(&data)
        .map_err(|error| js_error(format!("{error:?}")))?;

    serde_wasm_bindgen::to_value(&bundle).map_err(js_error)
}