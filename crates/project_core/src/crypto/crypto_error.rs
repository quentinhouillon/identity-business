#[derive(Debug, thiserror::Error)]
pub enum CryptoError {

    #[error("Invalid encryption key")]
    InvalidKey,

    #[error("Serialization failed")]
    SerializationFailed,

    #[error("Deserialization failed")]
    DeserializationFailed,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Key Derivation Failed")]
    KeyDerivationFailed,
}