use wasm_bindgen::prelude::*;

use project_core::models::{Vault, EncryptedVault};

#[wasm_bindgen]
pub struct WasmVault {
    vault: Vault,
}

#[wasm_bindgen]
impl WasmVault {
    #[wasm_bindgen(constructor)]
    pub fn new(
        encrypted_vault: JsValue,
        master_password: &str,
        user_salt: &[u8],
    ) -> Result<WasmVault, JsValue> {
        let encrypted_vault: EncryptedVault =
            serde_wasm_bindgen::from_value(encrypted_vault)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let vault = Vault::new(
            encrypted_vault,
            master_password,
            user_salt,
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(Self { vault })
    }

    pub fn encrypt(
        &self,
        id: String,
        master_password: &str,
        user_salt: &[u8],
        encrypted_vault: Option<JsValue>,
    ) -> Result<JsValue, JsValue> {
        let encrypted_vault = encrypted_vault
            .map(|value| {
                serde_wasm_bindgen::from_value::<EncryptedVault>(value)
                    .map_err(|e| JsValue::from_str(&e.to_string()))
            })
            .transpose()?;

        let encrypted = self
            .vault
            .encrypt(
                id,
                master_password,
                user_salt,
                encrypted_vault.as_ref(),
            )
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        serde_wasm_bindgen::to_value(&encrypted)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn get_nodes(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(
            self.vault.get_nodes()
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn get_node(&self, id: &str) -> Result<JsValue, JsValue> {
        let node = self
            .vault
            .get_node(id)
            .ok_or_else(|| JsValue::from_str("Node not found"))?;

        serde_wasm_bindgen::to_value(node)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn post_node(&mut self, node: JsValue) -> Result<(), JsValue> {
        let node = serde_wasm_bindgen::from_value(node)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        self.vault.post_node(node);

        Ok(())
    }

    pub fn put_node(&mut self, node: JsValue) -> Result<bool, JsValue> {
        let node = serde_wasm_bindgen::from_value(node)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(self.vault.put_node(node).is_some())
    }

    pub fn delete_node(&mut self, id: &str) -> bool {
        self.vault.delete_node(id).is_some()
    }

    pub fn get_edges(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(
            self.vault.get_edges()
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn get_edge(&self, id: &str) -> Result<JsValue, JsValue> {
        let edge = self
            .vault
            .get_edge(id)
            .ok_or_else(|| JsValue::from_str("Edge not found"))?;

        serde_wasm_bindgen::to_value(edge)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn post_edge(&mut self, edge: JsValue) -> Result<(), JsValue> {
        let edge = serde_wasm_bindgen::from_value(edge)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        self.vault.post_edge(edge);

        Ok(())
    }

    pub fn put_edge(&mut self, edge: JsValue) -> Result<bool, JsValue> {
        let edge = serde_wasm_bindgen::from_value(edge)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(self.vault.put_edge(edge).is_some())
    }

    pub fn delete_edge(&mut self, id: &str) -> bool {
        self.vault.delete_edge(id).is_some()
    }

    pub fn get_history(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(
            self.vault.get_history()
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn post_history(&mut self, history: JsValue) -> Result<(), JsValue> {
        let history = serde_wasm_bindgen::from_value(history)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        self.vault.post_history(history);

        Ok(())
    }

    pub fn get_events(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(
            self.vault.get_events()
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn post_event(&mut self, event: JsValue) -> Result<(), JsValue> {
        let event = serde_wasm_bindgen::from_value(event)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        self.vault.post_event(event);

        Ok(())
    }
}