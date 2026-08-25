use crate::crypto::crypto_error::CryptoError;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("API error: {0}")]
    Api(#[from] reqwest::Error),

    #[error("Serialization failed")]
    Serialization,

    #[error("Node not found")]
    NodeNotFound,

    #[error("Edge not found")]
    EdgeNotFound,

    #[error("Invalid node id")]
    InvalidNodeId,
}
