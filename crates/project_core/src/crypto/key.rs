use argon2::{
    Argon2,
    Algorithm,
    Params,
    Version,
};

use crate::crypto::crypto_error::CryptoError;

use ed25519_dalek::SigningKey;
use rand::{rngs::SysRng, TryRng};

pub fn derive_master_key(
    master_password: &[u8],
    salt: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let params = Params::new(
        64 * 1024, // 64 MiB memory
        3,         // 3 iterations
        1,         // parallelism
        Some(32),  // 32 bytes
    )
    .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    );

    let mut master_key = [0u8; 32];

    argon2
        .hash_password_into(
            master_password,
            salt,
            &mut master_key,
        )
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(master_key)
}

pub fn generate_vault_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut key)
        .map_err(|_| CryptoError::KeyGenerationFailed).unwrap();
    key
}

pub fn generate_asymmetric_keypair() -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let mut private_key = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut private_key)
        .map_err(|_| CryptoError::KeyGenerationFailed)?;

    let signing_key = SigningKey::from_bytes(&private_key);
    let public_key = signing_key.verifying_key().to_bytes();

    Ok((private_key, public_key))
}

