use base64::{engine::general_purpose::STANDARD, Engine as _};

use project_core::crypto::crypto_error::CryptoError;
use serde::Serialize;
use uuid::Uuid;
use wasm_bindgen::JsValue;

/* -------------------------------------------------------------------------- */
/* Errors: every error thrown to JS is { code, message }                       */
/* -------------------------------------------------------------------------- */

#[derive(Serialize)]
struct JsErrorOut<'a> {
    code: &'a str,
    message: String,
}

fn to_js_error(code: &str, message: String) -> JsValue {
    serde_wasm_bindgen::to_value(&JsErrorOut {
        code,
        message: message.clone(),
    })
    .unwrap_or_else(|_| JsValue::from_str(&message))
}

pub fn js_error(error: impl ToString) -> JsValue {
    to_js_error("ERROR", error.to_string())
}

pub fn input_error(message: &str) -> JsValue {
    to_js_error("INVALID_INPUT", message.to_string())
}

pub fn crypto_error(error: CryptoError) -> JsValue {
    to_js_error(error.code(), error.to_string())
}

/* -------------------------------------------------------------------------- */
/* Decoding / encoding                                                         */
/* -------------------------------------------------------------------------- */

pub fn decode_base64(value: &str) -> Result<Vec<u8>, JsValue> {
    STANDARD
        .decode(value)
        .map_err(|_| input_error("Invalid Base64 data"))
}

pub fn encode_base64(value: &[u8]) -> String {
    STANDARD.encode(value)
}

fn decode_fixed<const N: usize>(value: &str, name: &str) -> Result<[u8; N], JsValue> {
    STANDARD
        .decode(value)
        .map_err(|_| input_error(&format!("Invalid Base64 {name}")))?
        .try_into()
        .map_err(|_| input_error(&format!("{name} must decode to exactly {N} bytes")))
}

pub fn decode_key(value: &str) -> Result<[u8; 32], JsValue> {
    decode_fixed::<32>(value, "key")
}

pub fn decode_signature(value: &str) -> Result<[u8; 64], JsValue> {
    decode_fixed::<64>(value, "signature")
}

pub fn decode_uuid(value: &str, field: &str) -> Result<[u8; 16], JsValue> {
    let uuid = Uuid::parse_str(value).map_err(|_| input_error(&format!("Invalid {field} UUID")))?;

    Ok(*uuid.as_bytes())
}

pub fn encode_uuid(bytes: &[u8]) -> Result<String, JsValue> {
    Uuid::from_slice(bytes)
        .map(|uuid| uuid.to_string())
        .map_err(|_| input_error("Invalid UUID bytes"))
}