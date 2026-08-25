use orion::aead;
use crate::crypto::crypto_error::CryptoError;


pub fn encrypt(
    key: &[u8; 32],
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {

    let secret_key =
        aead::SecretKey::from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?;

    aead::seal(
        &secret_key,
        data,
    )
    .map_err(|_| CryptoError::EncryptionFailed)
}

pub fn decrypt(
    key: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {

    let secret_key =
        aead::SecretKey::from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?;

    aead::open(
        &secret_key,
        ciphertext,
    )
    .map_err(|_| CryptoError::DecryptionFailed)
}