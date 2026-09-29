use base64::{engine::general_purpose::STANDARD, Engine as _};

use uuid::Uuid;
use wasm_bindgen::JsValue;

pub fn decode_key(value: &str) -> Result<[u8; 32], JsValue> {
    STANDARD
        .decode(value)
        .map_err(|_| JsValue::from_str("Invalid Base64 key"))?
        .try_into()
        .map_err(|_| {
            JsValue::from_str("Key must decode to exactly 32 bytes")
        })
}

pub fn decode_base64(value: &str) -> Result<Vec<u8>, JsValue> {
    STANDARD
        .decode(value)
        .map_err(|_| JsValue::from_str("Invalid Base64 data"))
}

pub fn encode_base64(value: &[u8]) -> String {
    STANDARD.encode(value)
}

pub fn decode_uuid(
    value: &str,
    field: &str,
) -> Result<[u8; 16], JsValue> {
    let uuid = Uuid::parse_str(value)
        .map_err(|_| {
            JsValue::from_str(
                &format!("Invalid {field} UUID"),
            )
        })?;

    Ok(*uuid.as_bytes())
}