use crate::crypto::{
    crypto_error::CryptoError,
    key::{
        derive_x25519_aead_key,
        PROTOCOL_NAME,
        PROTOCOL_VERSION,
    },
};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
    XNonce,
};

use rand::{rngs::SysRng, TryRng};
use x25519_dalek::{PublicKey, StaticSecret};

pub const TYPE_VAULT_KEY_WRAP: u8 = 0x01;
pub const TYPE_NODE: u8 = 0x02;
pub const TYPE_EDGE: u8 = 0x03;
pub const TYPE_HISTORY: u8 = 0x04;
pub const TYPE_SECURITY_EVENT: u8 = 0x05;

const PRIVATE_KEY_TYPE: u8 = 0x06;

const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;
const KEY_SIZE: usize = 32;

const MIN_DATA_SIZE: usize =
    1 + NONCE_SIZE + TAG_SIZE;

const MIN_VAULT_KEY_SIZE: usize =
    1 + KEY_SIZE + NONCE_SIZE + TAG_SIZE;

const MIN_PRIVATE_KEY_SIZE: usize =
    1 + NONCE_SIZE + KEY_SIZE + TAG_SIZE;


/// Checks whether the message type belongs to the current protocol.
fn is_valid_message_type(message_type: u8) -> bool {
    matches!(
        message_type,
        TYPE_VAULT_KEY_WRAP
            | TYPE_NODE
            | TYPE_EDGE
            | TYPE_HISTORY
            | TYPE_SECURITY_EVENT
            | PRIVATE_KEY_TYPE
    )
}


/// Builds authenticated additional data.
///
/// The AAD is not secret.
/// It binds the ciphertext to its protocol, type, Vault and object.
fn build_aad(
    version: u8,
    message_type: u8,
    vault_id: &[u8],
    object_id: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        PROTOCOL_NAME.len()
            + 2
            + 4
            + vault_id.len()
            + object_id.len(),
    );

    aad.extend_from_slice(PROTOCOL_NAME);

    // Protocol version.
    aad.push(version);

    // Message type.
    aad.push(message_type);

    // Explicit lengths avoid ambiguous concatenation.
    aad.extend_from_slice(
        &(vault_id.len() as u32).to_be_bytes(),
    );

    aad.extend_from_slice(vault_id);

    aad.extend_from_slice(
        &(object_id.len() as u32).to_be_bytes(),
    );

    aad.extend_from_slice(object_id);

    aad
}


/// Generates a cryptographically random XChaCha20 nonce.
fn generate_nonce() -> Result<[u8; NONCE_SIZE], CryptoError> {
    let mut nonce = [0u8; NONCE_SIZE];

    SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(nonce)
}


/// Encrypts arbitrary Vault data.
///
/// Output format:
///
///     version (1 byte)
///     nonce   (24 bytes)
///     ciphertext + Poly1305 tag
///
/// The message type, Vault ID and object ID are authenticated through AAD.
pub fn encrypt_data(
    key: &[u8; KEY_SIZE],
    message_type: u8,
    vault_id: &[u8],
    object_id: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if !is_valid_message_type(message_type)
        || message_type == TYPE_VAULT_KEY_WRAP
        || message_type == PRIVATE_KEY_TYPE
    {
        return Err(CryptoError::UnsupportedMessageType);
    }

    let cipher =
        XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?;

    let nonce_bytes = generate_nonce()?;
    let nonce = XNonce::from(nonce_bytes);

    let aad = build_aad(
        PROTOCOL_VERSION,
        message_type,
        vault_id,
        object_id,
    );

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut output = Vec::with_capacity(
        1 + NONCE_SIZE + ciphertext.len(),
    );

    output.push(PROTOCOL_VERSION);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}


/// Decrypts arbitrary Vault data.
///
/// The expected message type is supplied by the caller and is never
/// taken from the ciphertext itself.
pub fn decrypt_data(
    key: &[u8; KEY_SIZE],
    expected_type: u8,
    vault_id: &[u8],
    object_id: &[u8],
    encrypted: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if !is_valid_message_type(expected_type)
        || expected_type == TYPE_VAULT_KEY_WRAP
        || expected_type == PRIVATE_KEY_TYPE
    {
        return Err(CryptoError::UnsupportedMessageType);
    }

    if encrypted.len() < MIN_DATA_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }

    let version = encrypted[0];

    if version != PROTOCOL_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }

    let nonce_bytes: [u8; NONCE_SIZE] =
        encrypted[1..1 + NONCE_SIZE]
            .try_into()
            .map_err(|_| CryptoError::DecryptionFailed)?;

    let ciphertext =
        &encrypted[1 + NONCE_SIZE..];

    let nonce = XNonce::from(nonce_bytes);

    let aad = build_aad(
        version,
        expected_type,
        vault_id,
        object_id,
    );

    let cipher =
        XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?;

    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}


/// Encrypts a Vault key for a specific recipient.
///
/// The recipient only needs their X25519 private key to recover the
/// Vault key.
///
/// Output format:
///
///     version                 (1 byte)
///     ephemeral public key    (32 bytes)
///     nonce                   (24 bytes)
///     ciphertext + tag        (48 bytes for a 32-byte Vault key)
pub fn encrypt_vault_key(
    recipient_public_key: &[u8; KEY_SIZE],
    vault_id: &[u8],
    user_id: &[u8],
    vault_key: &[u8; KEY_SIZE],
) -> Result<Vec<u8>, CryptoError> {
    let recipient_public =
        PublicKey::from(*recipient_public_key);

    // Generate a fresh ephemeral X25519 key pair.
    let mut ephemeral_bytes = [0u8; KEY_SIZE];

    SysRng
        .try_fill_bytes(&mut ephemeral_bytes)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let ephemeral_secret =
        StaticSecret::from(ephemeral_bytes);

    let ephemeral_public =
        PublicKey::from(&ephemeral_secret);

    let shared_secret =
        ephemeral_secret.diffie_hellman(
            &recipient_public,
        );

    // Reject invalid all-zero X25519 shared secrets.
    if shared_secret
        .as_bytes()
        .iter()
        .all(|&byte| byte == 0)
    {
        return Err(CryptoError::EncryptionFailed);
    }

    let encryption_key =
        derive_x25519_aead_key(
            shared_secret.as_bytes(),
            vault_id,
            user_id,
        )?;

    let cipher =
        XChaCha20Poly1305::new_from_slice(
            &encryption_key,
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let nonce_bytes = generate_nonce()?;
    let nonce = XNonce::from(nonce_bytes);

    let aad = build_aad(
        PROTOCOL_VERSION,
        TYPE_VAULT_KEY_WRAP,
        vault_id,
        user_id,
    );

    let encrypted = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: vault_key,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut output = Vec::with_capacity(
        1 + KEY_SIZE + NONCE_SIZE + encrypted.len(),
    );

    output.push(PROTOCOL_VERSION);

    output.extend_from_slice(
        ephemeral_public.as_bytes(),
    );

    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&encrypted);

    Ok(output)
}


/// Decrypts a Vault key using the recipient's X25519 private key.
pub fn decrypt_vault_key(
    private_key: &[u8; KEY_SIZE],
    vault_id: &[u8],
    user_id: &[u8],
    encrypted: &[u8],
) -> Result<[u8; KEY_SIZE], CryptoError> {
    if encrypted.len() < MIN_VAULT_KEY_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }

    let version = encrypted[0];

    if version != PROTOCOL_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }

    let ephemeral_public =
        PublicKey::from(
            <[u8; KEY_SIZE]>::try_from(
                &encrypted[1..33],
            )
            .map_err(|_| CryptoError::DecryptionFailed)?,
        );

    let nonce_bytes =
        <[u8; NONCE_SIZE]>::try_from(
            &encrypted[33..57],
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let ciphertext = &encrypted[57..];

    let recipient_private =
        StaticSecret::from(*private_key);

    let shared_secret =
        recipient_private.diffie_hellman(
            &ephemeral_public,
        );

    if shared_secret
        .as_bytes()
        .iter()
        .all(|&byte| byte == 0)
    {
        return Err(CryptoError::DecryptionFailed);
    }

    let encryption_key =
        crate::crypto::key::derive_x25519_aead_key(
            shared_secret.as_bytes(),
            vault_id,
            user_id,
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let cipher =
        XChaCha20Poly1305::new_from_slice(
            &encryption_key,
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let nonce = XNonce::from(nonce_bytes);

    let aad = build_aad(
        version,
        TYPE_VAULT_KEY_WRAP,
        vault_id,
        user_id,
    );

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    plaintext
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed)
}


/// Encrypts the user's X25519 private key using a key derived from
/// their password with Argon2id.
///
/// Output format:
///
///     version
///     nonce
///     encrypted private key + Poly1305 tag
pub fn encrypt_private_key(
    master_key: &[u8; KEY_SIZE],
    user_id: &[u8],
    private_key: &[u8; KEY_SIZE],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(master_key)
            .map_err(|_| CryptoError::InvalidKey)?;

    let nonce_bytes = generate_nonce()?;
    let nonce = XNonce::from(nonce_bytes);

    let aad = build_aad(
        PROTOCOL_VERSION,
        PRIVATE_KEY_TYPE,
        &[],
        user_id,
    );

    let encrypted = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: private_key,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut output = Vec::with_capacity(
        1 + NONCE_SIZE + encrypted.len(),
    );

    output.push(PROTOCOL_VERSION);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&encrypted);

    Ok(output)
}


/// Decrypts the user's X25519 private key using the key derived
/// from their password.
pub fn decrypt_private_key(
    master_key: &[u8; KEY_SIZE],
    user_id: &[u8],
    encrypted: &[u8],
) -> Result<[u8; KEY_SIZE], CryptoError> {
    if encrypted.len() < MIN_PRIVATE_KEY_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }

    let version = encrypted[0];

    if version != PROTOCOL_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }

    let nonce_bytes =
        <[u8; NONCE_SIZE]>::try_from(
            &encrypted[1..25],
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let ciphertext = &encrypted[25..];

    let nonce = XNonce::from(nonce_bytes);

    let cipher =
        XChaCha20Poly1305::new_from_slice(master_key)
            .map_err(|_| CryptoError::InvalidKey)?;

    let aad = build_aad(
        version,
        PRIVATE_KEY_TYPE,
        &[],
        user_id,
    );

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    plaintext
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed)
}