use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::{rngs::SysRng, TryRng};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::crypto_error::CryptoError;

pub const PROTOCOL_NAME: &[u8] = b"MYAPP-VAULT";
pub const PROTOCOL_VERSION: u8 = 1;

pub const KEY_SIZE: usize = 32;
pub const SALT_SIZE: usize = 16;

const X25519_WRAP_CONTEXT: &[u8] = b"x25519-vault-key-wrap";

/// Derives a 32-byte key from the user's password.
///
/// This key must only be used to protect the user's X25519 private key.
/// The password itself must never be used directly as an encryption key.
pub fn derive_master_key(
    master_password: &[u8],
    salt: &[u8],
) -> Result<[u8; 32], CryptoError> {
    if salt.len() < SALT_SIZE {
        return Err(CryptoError::InvalidSalt);
    }

    let params = Params::new(
        64 * 1024, // 64 MiB memory
        3,         // 3 iterations
        1,         // 1 lane
        Some(KEY_SIZE),
    )
    .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    );

    let mut master_key = [0u8; KEY_SIZE];

    argon2
        .hash_password_into(
            master_password,
            salt,
            &mut master_key,
        )
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(master_key)
}

/// Generates a cryptographically random Vault key.
///
/// The Vault key is the symmetric key used to encrypt Vault data.
pub fn generate_vault_key() -> Result<[u8; KEY_SIZE], CryptoError> {
    let mut key = [0u8; KEY_SIZE];

    SysRng
        .try_fill_bytes(&mut key)
        .map_err(|_| CryptoError::KeyGenerationFailed)?;

    Ok(key)
}

/// Generates an X25519 key pair.
///
/// The private key must remain client-side.
/// Only the public key should be sent to the backend.
pub fn generate_asymmetric_keypair(
) -> Result<([u8; KEY_SIZE], [u8; KEY_SIZE]), CryptoError> {
    let mut private_bytes = [0u8; KEY_SIZE];

    SysRng
        .try_fill_bytes(&mut private_bytes)
        .map_err(|_| CryptoError::KeyGenerationFailed)?;

    let private_key = StaticSecret::from(private_bytes);
    let public_key = PublicKey::from(&private_key);

    Ok((
        private_key.to_bytes(),
        public_key.to_bytes(),
    ))
}

/// Derives an AEAD key from an X25519 shared secret.
///
/// The raw X25519 shared secret must never be used directly as an
/// application encryption key. HKDF provides key separation and
/// protocol-level domain separation.
pub fn derive_x25519_aead_key(
    shared_secret: &[u8; KEY_SIZE],
    vault_id: &[u8],
    user_id: &[u8],
) -> Result<[u8; KEY_SIZE], CryptoError> {
    if shared_secret.iter().all(|&byte| byte == 0) {
        return Err(CryptoError::KeyDerivationFailed);
    }

    let hkdf = Hkdf::<Sha256>::new(
        Some(PROTOCOL_NAME),
        shared_secret,
    );

    let mut key = [0u8; KEY_SIZE];

    let mut info = Vec::with_capacity(
        X25519_WRAP_CONTEXT.len()
            + 1
            + 1
            + vault_id.len()
            + user_id.len(),
    );

    info.extend_from_slice(X25519_WRAP_CONTEXT);

    // Protocol version.
    info.push(PROTOCOL_VERSION);

    // Cryptographic purpose identifier.
    info.push(0x01);

    // Bind the derived key to the Vault and recipient.
    info.extend_from_slice(vault_id);
    info.extend_from_slice(user_id);

    hkdf
        .expand(&info, &mut key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(key)
}