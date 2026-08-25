use std::{
    cell::RefCell,
    rc::Rc,
};

use uuid::Uuid;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{future_to_promise, js_sys};

use project_core::{
    business::{
        api_service::ApiService,
        vault_service::VaultService,
    },
    models::{
        Edge,
        Node,
    },
};

#[wasm_bindgen]
pub struct WasmVault {
    service: Rc<RefCell<Option<VaultService>>>,
}

#[wasm_bindgen]
impl WasmVault {
#[wasm_bindgen]
    pub fn new(
        user_id: String,
        master_password: String,
        user_salt: Vec<u8>,
        token: Option<String>,
    ) -> js_sys::Promise {

        future_to_promise(async move {

            let user_id =
                Uuid::parse_str(&user_id)
                    .map_err(|e| {
                        JsValue::from_str(
                            &format!(
                                "Invalid user UUID: {}",
                                e
                            )
                        )
                    })?;

            let api =
                ApiService::new();

            let service =
                VaultService::new(
                    user_id,
                    &master_password,
                    &user_salt,
                    api,
                    token.as_deref(),
                )
                .await
                .map_err(|e| {
                    JsValue::from_str(
                        &e.to_string()
                    )
                })?;

            Ok(
                JsValue::from(
                    WasmVault {
                        service: Rc::new(
                            RefCell::new(
                                Some(service)
                            )
                        ),
                    }
                )
            )
        })
    }

    // ============================================================
    // VAULT
    // ============================================================

    pub fn get_vault(
        &self,
    ) -> Result<JsValue, JsValue> {

        let service =
            self.service
                .borrow();

        let service =
            service
                .as_ref()
                .ok_or_else(|| {
                    JsValue::from_str(
                        "Vault service unavailable"
                    )
                })?;

        serde_wasm_bindgen::to_value(
            service.get_vault()
        )
        .map_err(|e| {
            JsValue::from_str(
                &e.to_string()
            )
        })
    }

    // ============================================================
    // NODES
    // ============================================================

    pub fn get_nodes(
        &self,
    ) -> Result<JsValue, JsValue> {

        let service =
            self.service
                .borrow();

        let service =
            service
                .as_ref()
                .ok_or_else(|| {
                    JsValue::from_str(
                        "Vault service unavailable"
                    )
                })?;

        serde_wasm_bindgen::to_value(
            service.get_nodes()
        )
        .map_err(|e| {
            JsValue::from_str(
                &e.to_string()
            )
        })
    }

    pub fn get_node(
        &self,
        id: String,
    ) -> Result<JsValue, JsValue> {

        let id =
            Uuid::parse_str(&id)
                .map_err(|e| {
                    JsValue::from_str(
                        &format!(
                            "Invalid node UUID: {}",
                            e
                        )
                    )
                })?;

        let service =
            self.service
                .borrow();

        let service =
            service
                .as_ref()
                .ok_or_else(|| {
                    JsValue::from_str(
                        "Vault service unavailable"
                    )
                })?;

        let node =
            service
                .get_node(id)
                .ok_or_else(|| {
                    JsValue::from_str(
                        "Node not found"
                    )
                })?;

        serde_wasm_bindgen::to_value(node)
            .map_err(|e| {
                JsValue::from_str(
                    &e.to_string()
                )
            })
    }

    pub fn post_node(
        &mut self,
        node: JsValue,
        token: Option<String>,
    ) -> js_sys::Promise {

        let node: Node =
            match serde_wasm_bindgen::from_value(node) {

                Ok(node) => node,

                Err(e) => {
                    return future_to_promise(
                        async move {
                            Err(
                                JsValue::from_str(
                                    &e.to_string()
                                )
                            )
                        }
                    );
                }
            };

        let service =
            Rc::clone(&self.service);

        future_to_promise(async move {

            let mut vault_service =
                service
                    .borrow_mut()
                    .take()
                    .ok_or_else(|| {
                        JsValue::from_str(
                            "Vault service unavailable"
                        )
                    })?;

            let result =
                vault_service
                    .post_node(
                        node,
                        token.as_deref(),
                    )
                    .await;

            service
                .borrow_mut()
                .replace(vault_service);

            result.map_err(|e| {
                JsValue::from_str(
                    &e.to_string()
                )
            })?;

            Ok(JsValue::UNDEFINED)
        })
    }

    pub fn put_node(
        &mut self,
        node: JsValue,
        token: Option<String>,
    ) -> js_sys::Promise {

        let node: Node =
            match serde_wasm_bindgen::from_value(node) {

                Ok(node) => node,

                Err(e) => {
                    return future_to_promise(
                        async move {
                            Err(
                                JsValue::from_str(
                                    &e.to_string()
                                )
                            )
                        }
                    );
                }
            };

        let service =
            Rc::clone(&self.service);

        future_to_promise(async move {

            let mut vault_service =
                service
                    .borrow_mut()
                    .take()
                    .ok_or_else(|| {
                        JsValue::from_str(
                            "Vault service unavailable"
                        )
                    })?;

            let result =
                vault_service
                    .put_node(
                        node,
                        token.as_deref(),
                    )
                    .await;

            service
                .borrow_mut()
                .replace(vault_service);

            result.map_err(|e| {
                JsValue::from_str(
                    &e.to_string()
                )
            })?;

            Ok(JsValue::UNDEFINED)
        })
    }

    pub fn delete_node(
        &mut self,
        id: String,
        token: Option<String>,
    ) -> js_sys::Promise {

        let id =
            match Uuid::parse_str(&id) {

                Ok(id) => id,

                Err(e) => {
                    return future_to_promise(
                        async move {
                            Err(
                                JsValue::from_str(
                                    &format!(
                                        "Invalid node UUID: {}",
                                        e
                                    )
                                )
                            )
                        }
                    );
                }
            };

        let service =
            Rc::clone(&self.service);

        future_to_promise(async move {

            let mut vault_service =
                service
                    .borrow_mut()
                    .take()
                    .ok_or_else(|| {
                        JsValue::from_str(
                            "Vault service unavailable"
                        )
                    })?;

            let result =
                vault_service
                    .delete_node(
                        id,
                        token.as_deref(),
                    )
                    .await;

            service
                .borrow_mut()
                .replace(vault_service);

            result.map_err(|e| {
                JsValue::from_str(
                    &e.to_string()
                )
            })?;

            Ok(JsValue::UNDEFINED)
        })
    }

    // ============================================================
    // EDGES
    // ============================================================

    pub fn get_edges(
        &self,
    ) -> Result<JsValue, JsValue> {

        let service =
            self.service
                .borrow();

        let service =
            service
                .as_ref()
                .ok_or_else(|| {
                    JsValue::from_str(
                        "Vault service unavailable"
                    )
                })?;

        serde_wasm_bindgen::to_value(
            service.get_edges()
        )
        .map_err(|e| {
            JsValue::from_str(
                &e.to_string()
            )
        })
    }

    pub fn get_edge(
        &self,
        id: String,
    ) -> Result<JsValue, JsValue> {

        let id =
            Uuid::parse_str(&id)
                .map_err(|e| {
                    JsValue::from_str(
                        &format!(
                            "Invalid edge UUID: {}",
                            e
                        )
                    )
                })?;

        let service =
            self.service
                .borrow();

        let service =
            service
                .as_ref()
                .ok_or_else(|| {
                    JsValue::from_str(
                        "Vault service unavailable"
                    )
                })?;

        let edge =
            service
                .get_edge(id)
                .ok_or_else(|| {
                    JsValue::from_str(
                        "Edge not found"
                    )
                })?;

        serde_wasm_bindgen::to_value(edge)
            .map_err(|e| {
                JsValue::from_str(
                    &e.to_string()
                )
            })
    }

    pub fn post_edge(
        &mut self,
        edge: JsValue,
        token: Option<String>,
    ) -> js_sys::Promise {

        let edge: Edge =
            match serde_wasm_bindgen::from_value(edge) {

                Ok(edge) => edge,

                Err(e) => {
                    return future_to_promise(
                        async move {
                            Err(
                                JsValue::from_str(
                                    &e.to_string()
                                )
                            )
                        }
                    );
                }
            };

        let service =
            Rc::clone(&self.service);

        future_to_promise(async move {

            let mut vault_service =
                service
                    .borrow_mut()
                    .take()
                    .ok_or_else(|| {
                        JsValue::from_str(
                            "Vault service unavailable"
                        )
                    })?;

            let result =
                vault_service
                    .post_edge(
                        edge,
                        token.as_deref(),
                    )
                    .await;

            service
                .borrow_mut()
                .replace(vault_service);

            result.map_err(|e| {
                JsValue::from_str(
                    &e.to_string()
                )
            })?;

            Ok(JsValue::UNDEFINED)
        })
    }

    pub fn put_edge(
        &mut self,
        edge: JsValue,
        token: Option<String>,
    ) -> js_sys::Promise {

        let edge: Edge =
            match serde_wasm_bindgen::from_value(edge) {

                Ok(edge) => edge,

                Err(e) => {
                    return future_to_promise(
                        async move {
                            Err(
                                JsValue::from_str(
                                    &e.to_string()
                                )
                            )
                        }
                    );
                }
            };

        let service =
            Rc::clone(&self.service);

        future_to_promise(async move {

            let mut vault_service =
                service
                    .borrow_mut()
                    .take()
                    .ok_or_else(|| {
                        JsValue::from_str(
                            "Vault service unavailable"
                        )
                    })?;

            let result =
                vault_service
                    .put_edge(
                        edge,
                        token.as_deref(),
                    )
                    .await;

            service
                .borrow_mut()
                .replace(vault_service);

            result.map_err(|e| {
                JsValue::from_str(
                    &e.to_string()
                )
            })?;

            Ok(JsValue::UNDEFINED)
        })
    }

    pub fn delete_edge(
        &mut self,
        id: String,
        token: Option<String>,
    ) -> js_sys::Promise {

        let id =
            match Uuid::parse_str(&id) {

                Ok(id) => id,

                Err(e) => {
                    return future_to_promise(
                        async move {
                            Err(
                                JsValue::from_str(
                                    &format!(
                                        "Invalid edge UUID: {}",
                                        e
                                    )
                                )
                            )
                        }
                    );
                }
            };

        let service =
            Rc::clone(&self.service);

        future_to_promise(async move {

            let mut vault_service =
                service
                    .borrow_mut()
                    .take()
                    .ok_or_else(|| {
                        JsValue::from_str(
                            "Vault service unavailable"
                        )
                    })?;

            let result =
                vault_service
                    .delete_edge(
                        id,
                        token.as_deref(),
                    )
                    .await;

            service
                .borrow_mut()
                .replace(vault_service);

            result.map_err(|e| {
                JsValue::from_str(
                    &e.to_string()
                )
            })?;

            Ok(JsValue::UNDEFINED)
        })
    }

    // ============================================================
    // HISTORY
    // ============================================================

    pub fn get_history(
        &self,
    ) -> Result<JsValue, JsValue> {

        let service =
            self.service
                .borrow();

        let service =
            service
                .as_ref()
                .ok_or_else(|| {
                    JsValue::from_str(
                        "Vault service unavailable"
                    )
                })?;

        serde_wasm_bindgen::to_value(
            service.get_history()
        )
        .map_err(|e| {
            JsValue::from_str(
                &e.to_string()
            )
        })
    }

    // ============================================================
    // EVENTS
    // ============================================================

    pub fn get_events(
        &self,
    ) -> Result<JsValue, JsValue> {

        let service =
            self.service
                .borrow();

        let service =
            service
                .as_ref()
                .ok_or_else(|| {
                    JsValue::from_str(
                        "Vault service unavailable"
                    )
                })?;

        serde_wasm_bindgen::to_value(
            service.get_events()
        )
        .map_err(|e| {
            JsValue::from_str(
                &e.to_string()
            )
        })
    }
}

// ================================================================
// CONFIGURATION
// ================================================================

#[wasm_bindgen]
pub fn set_base_url(
    base_url: String,
) {
    project_core::config::set_base_url(
        base_url
    );
}