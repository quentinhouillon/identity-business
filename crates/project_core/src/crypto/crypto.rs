use orion::hazardous::aead::xchacha20poly1305;
use crate::crypto::crypto_error::CryptoError;

pub fn encrypt(key: &[u8; 32], nonce: &[u8; 24], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let secret_key =
        xchacha20poly1305::SecretKey::from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?;

    let nonce =
        xchacha20poly1305::Nonce::from(*nonce);

    // XChaCha20-Poly1305 add 16 bytes to tag
    let mut ciphertext = vec![0u8; data.len() + 16];

    xchacha20poly1305::seal(
        &secret_key,
        &nonce,
        data,
        None,
        &mut ciphertext,
    )
    .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(ciphertext)
}

pub fn decrypt(key: &[u8; 32], nonce: &[u8; 24], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let secret_key =
        xchacha20poly1305::SecretKey::from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?;

    let nonce =
        xchacha20poly1305::Nonce::from(*nonce);

    if ciphertext.len() < 16 {
        return Err(CryptoError::DecryptionFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len() - 16];

    xchacha20poly1305::open(
        &secret_key,
        &nonce,
        ciphertext,
        None,
        &mut plaintext,
    )
    .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext)
}