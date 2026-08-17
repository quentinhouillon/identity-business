use argon2::password_hash::SaltString;
use chrono::Utc;
use orion::aead;

use crate::models::{Vault, EncryptedVault};
use crate::crypto::crypto_error::CryptoError;

pub fn encrypt_vault_key(
    vault_key: &[u8; 32],
    master_key: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    let secret_key =
        aead::SecretKey::from_slice(master_key)
            .map_err(|_| CryptoError::InvalidKey)?;

    aead::seal(
        &secret_key,
        vault_key,
    )
    .map_err(|_| CryptoError::EncryptionFailed)
}

pub fn decrypt_vault_key(
    encrypted_key: &[u8],
    master_key: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let secret_key =
        aead::SecretKey::from_slice(master_key)
            .map_err(|_| CryptoError::InvalidKey)?;

    let decrypted =
        aead::open(
            &secret_key,
            encrypted_key,
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    decrypted
        .try_into()
        .map_err(|_| CryptoError::InvalidKey)
}

pub fn encrypt_vault(
    id: String,
    vault: &Vault,
    master_password: &[u8],
    user_salt: &[u8],
    existing_vault: Option<&EncryptedVault>,
) -> Result<EncryptedVault, CryptoError> {
    let master_key =
        derive_master_key(
            master_password,
            user_salt,
        )?;

    let (vault_key, encrypted_key, creation) =
        match existing_vault {
            // Existing Vault
            Some(encrypted_vault) => {

                let vault_key =
                    decrypt_vault_key(
                        &encrypted_vault.encrypted_key,
                        &master_key,
                    )?;

                (
                    vault_key,
                    encrypted_vault.encrypted_key.clone(),
                    encrypted_vault.creation,
                )
            }

            // New Vault
            None => {
                let vault_key =
                    generate_vault_key();

                let encrypted_key =
                    encrypt_vault_key(
                        &vault_key,
                        &master_key,
                    )?;

                (
                    vault_key,
                    encrypted_key,
                    Utc::now(),
                )
            }
        };

    let serialized_vault =
        serde_json::to_vec(vault)
            .map_err(|_| CryptoError::SerializationFailed)?;


    let secret_key =
        aead::SecretKey::from_slice(&vault_key)
            .map_err(|_| CryptoError::InvalidKey)?;

    let content =
        aead::seal(
            &secret_key,
            &serialized_vault,
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;


    let now = Utc::now();

    Ok(EncryptedVault {
        id,
        content,
        encrypted_key,
        last_scan: now.to_rfc3339(),
        creation,
        modification: now,
    })
}

pub fn decrypt_vault(
    encrypted_vault: &EncryptedVault,
    master_password: &[u8],
    user_salt: &[u8],
) -> Result<Vault, CryptoError> {
    // 1. Master Password -> Master Key
    let master_key =
        derive_master_key(
            master_password,
            user_salt,
        )?;

    // 2. Master Key -> Vault Key
    let vault_key =
        decrypt_vault_key(
            &encrypted_vault.encrypted_key,
            &master_key,
        )?;

    // 3. Vault Key -> Vault
    let secret_key =
        aead::SecretKey::from_slice(&vault_key)
            .map_err(|_| CryptoError::InvalidKey)?;

    let decrypted =
        aead::open(
            &secret_key,
            &encrypted_vault.content,
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // 4. JSON -> Vault
    serde_json::from_slice::<Vault>(&decrypted)
        .map_err(|_| CryptoError::DeserializationFailed)
}