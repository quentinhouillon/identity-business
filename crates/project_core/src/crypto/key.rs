use argon2::{
    Argon2,
    Algorithm,
    Params,
    Version,
};

use crate::crypto::crypto_error::CryptoError;

use rand::{rngs::OsRng, RngCore};

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
    OsRng.fill_bytes(&mut key);
    key
}