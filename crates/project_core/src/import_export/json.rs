use serde::{Deserialize, Serialize};

use crate::models::history::History;
use crate::models::node::Node;
use crate::models::vault::Vault;
use crate::models::Edge;

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportBundle {
    pub format: String,
    pub version: u32,
    pub vault: Vault,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub history: Vec<History>,
}

#[derive(Debug)]
pub enum ImportError {
    InvalidJson(serde_json::Error),
    InvalidFormat(String),
    UnsupportedVersion(u32),
}

pub fn export_json(
    vault: &Vault,
    nodes: &[Node],
    edges: &[Edge],
    history: &[History],
) -> Result<Vec<u8>, serde_json::Error> {
    let bundle = ExportBundle {
        format: "Lair-export".to_string(),
        version: 1,
        vault: vault.clone(),
        nodes: nodes.to_vec(),
        edges: edges.to_vec(),
        history: history.to_vec(),
    };

    serde_json::to_vec_pretty(&bundle)
}

pub fn import_json(data: &[u8]) -> Result<ExportBundle, ImportError> {
    let bundle: ExportBundle =
        serde_json::from_slice(data)
            .map_err(ImportError::InvalidJson)?;

    if bundle.format != "Lair-export" {
        return Err(ImportError::InvalidFormat(bundle.format));
    }

    match bundle.version {
        1 => Ok(bundle),
        version => Err(ImportError::UnsupportedVersion(version)),
    }
}