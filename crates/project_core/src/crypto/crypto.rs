use argon2::password_hash::SaltString;
use chrono::Utc;
use orion::aead;

use crate::models::{Vault, EncryptedVault};
use crate::crypto::crypto_error::CryptoError;


pub fn encrypt_vault(
    id: String,
    vault: &Vault,
    key: &[u8; 32],
) -> Result<EncryptedVault, CryptoError> {

    // Vault -> JSON bytes
    let serialized_vault =
        serde_json::to_vec(vault)
            .map_err(|_| CryptoError::SerializationFailed)?;


    // Orion Key
    let secret_key =
        aead::SecretKey::from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?;


    // encryption
    let encrypted =
        aead::seal(
            &secret_key,
            &serialized_vault
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;


    Ok(
        EncryptedVault {
            id,
            vault: encrypted,
            last_scan: Utc::now()
                .to_rfc3339(),
            creation: Utc::now(),
            modification: Utc::now(),
        }
    )
}

pub fn decrypt_vault(
    encrypted_vault: &EncryptedVault,
    key: &[u8;32],
) -> Result<Vault, CryptoError> {

    let secret_key =
        aead::SecretKey::from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?;

    let decrypted =
        aead::open(
            &secret_key,
            &encrypted_vault.vault
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let vault =
        serde_json::from_slice::<Vault>(&decrypted)
            .map_err(|_| CryptoError::DeserializationFailed)?;

    Ok(vault)
}

pub fn encrypt_password(
    password: String,
    key: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {

    // Orion Key
    let secret_key =
        aead::SecretKey::from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?;


    // encryption
    let encrypted =
        aead::seal(
            &secret_key,
            &password.as_bytes()
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;


    Ok(encrypted)
}

pub fn decrypt_password(
    encrypted_password: Vec<u8>,
    key: &[u8;32],
) -> Result<String, CryptoError> {

    let secret_key =
        aead::SecretKey::from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?;

    let decrypted =
        aead::open(
            &secret_key,
            &encrypted_password
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(String::from_utf8(decrypted).unwrap())
}