pub mod helper;

use std::collections::HashSet;
use helper::{decode_base64, decode_key, decode_uuid, encode_base64};

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

/* -------------------------------------------------------------------------- */
/* Password breach check                                                      */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub async fn check_passwords_wasm(
    passwords: Vec<String>,
) -> Result<JsValue, JsValue> {
    let results =
        have_i_been_pwned_service::check_passwords(passwords)
            .await
            .map_err(|error| {
                JsValue::from_str(&error.to_string())
            })?;

    serde_wasm_bindgen::to_value(&results)
        .map_err(|error| {
            JsValue::from_str(&error.to_string())
        })
}

/* -------------------------------------------------------------------------- */
/* Graph algorithms                                                           */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub fn dfs_wasm(
    edges_json: &str,
    start_id: &str,
) -> Result<JsValue, JsValue> {
    let edges: Vec<Edge> =
        serde_json::from_str(edges_json)
            .map_err(|error| {
                JsValue::from_str(&error.to_string())
            })?;

    let start_id =
        Uuid::parse_str(start_id)
            .map_err(|error| {
                JsValue::from_str(&error.to_string())
            })?;

    let mut visited = HashSet::new();

    dfs(
        &edges,
        &start_id,
        &mut visited,
    );

    serde_wasm_bindgen::to_value(&visited)
        .map_err(|error| {
            JsValue::from_str(&error.to_string())
        })
}

#[wasm_bindgen]
pub fn spof_wasm(
    edges_json: &str,
    start_id: &str,
) -> Result<JsValue, JsValue> {
    let edges: Vec<Edge> =
        serde_json::from_str(edges_json)
            .map_err(|error| {
                JsValue::from_str(&error.to_string())
            })?;

    let start_id =
        Uuid::parse_str(start_id)
            .map_err(|error| {
                JsValue::from_str(&error.to_string())
            })?;

    let spofs = spof(
        &edges,
        &[start_id],
    );

    let result: Vec<String> =
        spofs
            .into_iter()
            .map(|id| id.to_string())
            .collect();

    serde_wasm_bindgen::to_value(&result)
        .map_err(|error| {
            JsValue::from_str(&error.to_string())
        })
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

    let vault_id =
        decode_uuid(vault_id, "vault_id")?;

    let object_id =
        decode_uuid(object_id, "object_id")?;

    let plaintext =
        decode_base64(value)?;

    let encrypted =
        crypto::encrypt_data(
            &key,
            message_type,
            &vault_id,
            &object_id,
            &plaintext,
        )
        .map_err(|error| {
            JsValue::from_str(
                &error.to_string(),
            )
        })?;

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

    let vault_id =
        decode_uuid(vault_id, "vault_id")?;

    let object_id =
        decode_uuid(object_id, "object_id")?;

    let encrypted =
        decode_base64(value)?;

    let plaintext =
        crypto::decrypt_data(
            &key,
            message_type,
            &vault_id,
            &object_id,
            &encrypted,
        )
        .map_err(|error| {
            JsValue::from_str(
                &error.to_string(),
            )
        })?;

    Ok(encode_base64(&plaintext))
}

/* -------------------------------------------------------------------------- */
/* Master key derivation                                                       */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub fn derive_master_key_wasm(
    master_password: &str,
    salt: &str,
) -> Result<String, JsValue> {
    let master_password =
        decode_base64(master_password)?;

    let salt =
        decode_base64(salt)?;

    let master_key =
        key::derive_master_key(
            &master_password,
            &salt,
        )
        .map_err(|error| {
            JsValue::from_str(
                &error.to_string(),
            )
        })?;

    Ok(encode_base64(&master_key))
}

/* -------------------------------------------------------------------------- */
/* Vault key                                                                   */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub fn generate_vault_key_wasm()
    -> Result<String, JsValue>
{
    let vault_key =
        key::generate_vault_key()
            .map_err(|error| {
                JsValue::from_str(
                    &error.to_string(),
                )
            })?;

    Ok(encode_base64(&vault_key))
}

/* -------------------------------------------------------------------------- */
/* X25519 key pair                                                             */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub fn generate_asymmetric_keypair_wasm()
    -> Result<JsValue, JsValue>
{
    let (private_key, public_key) =
        key::generate_asymmetric_keypair()
            .map_err(|error| {
                JsValue::from_str(
                    &error.to_string(),
                )
            })?;

    let result = serde_json::json!({
        "privateKey": encode_base64(&private_key),
        "publicKey": encode_base64(&public_key),
    });

    serde_wasm_bindgen::to_value(&result)
        .map_err(|error| {
            JsValue::from_str(
                &error.to_string(),
            )
        })
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
    let recipient_public_key =
        decode_key(recipient_public_key)?;

    let vault_id =
        decode_uuid(vault_id, "vault_id")?;

    let user_id =
        decode_uuid(user_id, "user_id")?;

    let vault_key =
        decode_key(vault_key)?;

    let encrypted =
        crypto::encrypt_vault_key(
            &recipient_public_key,
            &vault_id,
            &user_id,
            &vault_key,
        )
        .map_err(|error| {
            JsValue::from_str(
                &error.to_string(),
            )
        })?;

    Ok(encode_base64(&encrypted))
}

#[wasm_bindgen]
pub fn decrypt_vault_key_wasm(
    private_key: &str,
    vault_id: &str,
    user_id: &str,
    encrypted_vault_key: &str,
) -> Result<String, JsValue> {
    let private_key =
        decode_key(private_key)?;

    let vault_id =
        decode_uuid(vault_id, "vault_id")?;

    let user_id =
        decode_uuid(user_id, "user_id")?;

    let encrypted_vault_key =
        decode_base64(encrypted_vault_key)?;

    let vault_key =
        crypto::decrypt_vault_key(
            &private_key,
            &vault_id,
            &user_id,
            &encrypted_vault_key,
        )
        .map_err(|error| {
            JsValue::from_str(
                &error.to_string(),
            )
        })?;

    Ok(encode_base64(&vault_key))
}

/* -------------------------------------------------------------------------- */
/* Private key encryption                                                     */
/* -------------------------------------------------------------------------- */

#[wasm_bindgen]
pub fn encrypt_private_key_wasm(
    master_key: &str,
    user_id: &str,
    private_key: &str,
) -> Result<String, JsValue> {
    let master_key =
        decode_key(master_key)?;

    let user_id =
        decode_uuid(user_id, "user_id")?;

    let private_key =
        decode_key(private_key)?;

    let encrypted =
        crypto::encrypt_private_key(
            &master_key,
            &user_id,
            &private_key,
        )
        .map_err(|error| {
            JsValue::from_str(
                &error.to_string(),
            )
        })?;

    Ok(encode_base64(&encrypted))
}

#[wasm_bindgen]
pub fn decrypt_private_key_wasm(
    master_key: &str,
    user_id: &str,
    encrypted_private_key: &str,
) -> Result<String, JsValue> {
    let master_key =
        decode_key(master_key)?;

    let user_id =
        decode_uuid(user_id, "user_id")?;

    let encrypted_private_key =
        decode_base64(
            encrypted_private_key,
        )?;

    let private_key =
        crypto::decrypt_private_key(
            &master_key,
            &user_id,
            &encrypted_private_key,
        )
        .map_err(|error| {
            JsValue::from_str(
                &error.to_string(),
            )
        })?;

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
    let node: Node =
        serde_wasm_bindgen::from_value(node)
            .map_err(|error| {
                JsValue::from_str(
                    &error.to_string(),
                )
            })?;

    totp::generate_code(
        &node.totp,
        timestamp,
    )
    .map_err(|error| {
        JsValue::from_str(
            &error.to_string(),
        )
    })
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
    let vault: Vault =
        serde_wasm_bindgen::from_value(vault)
            .map_err(|error| {
                JsValue::from_str(
                    &error.to_string(),
                )
            })?;

    let nodes: Vec<Node> =
        serde_wasm_bindgen::from_value(nodes)
            .map_err(|error| {
                JsValue::from_str(
                    &error.to_string(),
                )
            })?;

    let edges: Vec<Edge> =
        serde_wasm_bindgen::from_value(edges)
            .map_err(|error| {
                JsValue::from_str(
                    &error.to_string(),
                )
            })?;

    let history: Vec<History> =
        serde_wasm_bindgen::from_value(history)
            .map_err(|error| {
                JsValue::from_str(
                    &error.to_string(),
                )
            })?;

    let data =
        core_export_json(
            &vault,
            &nodes,
            &edges,
            &history,
        )
        .map_err(|error| {
            JsValue::from_str(
                &error.to_string(),
            )
        })?;

    Ok(encode_base64(&data))
}

#[wasm_bindgen]
pub fn import_json(
    data: &str,
) -> Result<JsValue, JsValue> {
    let data =
        decode_base64(data)?;

    let bundle =
        core_import_json(&data)
            .map_err(|error| {
                JsValue::from_str(
                    &format!("{error:?}"),
                )
            })?;

    serde_wasm_bindgen::to_value(&bundle)
        .map_err(|error| {
            JsValue::from_str(
                &error.to_string(),
            )
        })
}
