#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
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

    #[error("Key derivation failed")]
    KeyDerivationFailed,

    #[error("Key generation failed")]
    KeyGenerationFailed,

    #[error("Unsupported version")]
    UnsupportedVersion,

    #[error("Invalid salt")]
    InvalidSalt,

    #[error("Unsupported message type")]
    UnsupportedMessageType,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Identity does not match the expected user or keys")]
    IdentityMismatch,

    #[error("Identity key has changed")]
    IdentityKeyChanged,
}

impl CryptoError {
    /// Stable identifier for the JS side; never change existing values.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidKey => "INVALID_KEY",
            Self::SerializationFailed => "SERIALIZATION_FAILED",
            Self::DeserializationFailed => "DESERIALIZATION_FAILED",
            Self::EncryptionFailed => "ENCRYPTION_FAILED",
            Self::DecryptionFailed => "DECRYPTION_FAILED",
            Self::KeyDerivationFailed => "KEY_DERIVATION_FAILED",
            Self::KeyGenerationFailed => "KEY_GENERATION_FAILED",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::InvalidSalt => "INVALID_SALT",
            Self::UnsupportedMessageType => "UNSUPPORTED_MESSAGE_TYPE",
            Self::InvalidSignature => "INVALID_SIGNATURE",
            Self::IdentityMismatch => "IDENTITY_MISMATCH",
            Self::IdentityKeyChanged => "IDENTITY_KEY_CHANGED",
        }
    }
}