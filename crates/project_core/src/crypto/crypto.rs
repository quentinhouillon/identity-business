use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{TryRng, rngs::SysRng};
use zeroize::Zeroizing;

use crate::crypto::{
    crypto_error::CryptoError,
    key::{
        IdentityKeys, KEY_SIZE, PROTOCOL_NAME, PROTOCOL_VERSION, PublicIdentity, SIGNATURE_SIZE,
        VerifiedIdentity, derive_x25519_aead_key, encode, generate_ephemeral_keypair,
        verify_signature, x25519_shared_secret,
    },
};

pub const TYPE_NODE: u8 = 0x02;
pub const TYPE_EDGE: u8 = 0x03;
pub const TYPE_HISTORY: u8 = 0x04;
pub const TYPE_SECURITY_EVENT: u8 = 0x05;

const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;

// version + nonce + tag
const MIN_DATA_SIZE: usize = 1 + NONCE_SIZE + TAG_SIZE;

// version + nonce + (x25519 private || ed25519 seed) + tag
pub const IDENTITY_BLOB_SIZE: usize = 1 + NONCE_SIZE + KEY_SIZE * 2 + TAG_SIZE;

// version + ephemeral public + nonce + signature + (vault key + tag)
pub const WRAPPED_VAULT_KEY_SIZE: usize =
    1 + KEY_SIZE + NONCE_SIZE + SIGNATURE_SIZE + KEY_SIZE + TAG_SIZE;

const IDENTITY_BLOB_CONTEXT: &[u8] = b"LAIR-VAULT/identity-private-blob/v1";
const WRAP_AAD_CONTEXT: &[u8] = b"LAIR-VAULT/wrap-aad/v1";
const WRAP_SIGNATURE_CONTEXT: &[u8] = b"LAIR-VAULT/wrap-signature/v1";

// ---------------------------------------------------------------------------
// AEAD primitives
// ---------------------------------------------------------------------------

fn generate_nonce() -> Result<[u8; NONCE_SIZE], CryptoError> {
    let mut nonce = [0u8; NONCE_SIZE];

    SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(nonce)
}

fn to_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CryptoError> {
    <[u8; N]>::try_from(bytes).map_err(|_| CryptoError::DecryptionFailed)
}

fn aead_seal(
    key: &[u8; KEY_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; NONCE_SIZE], Vec<u8>), CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;

    let nonce_bytes = generate_nonce()?;
    let nonce = XNonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok((nonce_bytes, ciphertext))
}

fn aead_open(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce = XNonce::from(*nonce);

    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::DecryptionFailed)
}

// ---------------------------------------------------------------------------
// Vault data (nodes, edges, history, security events)
// ---------------------------------------------------------------------------

fn is_valid_message_type(message_type: u8) -> bool {
    matches!(
        message_type,
        TYPE_NODE | TYPE_EDGE | TYPE_HISTORY | TYPE_SECURITY_EVENT
    )
}

/// Binds the ciphertext to protocol, version, type, Vault and object.
fn build_aad(version: u8, message_type: u8, vault_id: &[u8], object_id: &[u8]) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(PROTOCOL_NAME.len() + 2 + 8 + vault_id.len() + object_id.len());

    aad.extend_from_slice(PROTOCOL_NAME);
    aad.push(version);
    aad.push(message_type);

    aad.extend_from_slice(&(vault_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(vault_id);

    aad.extend_from_slice(&(object_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(object_id);

    aad
}

/// Output: version (1) || nonce (24) || ciphertext + tag.
pub fn encrypt_data(
    key: &[u8; KEY_SIZE],
    message_type: u8,
    vault_id: &[u8],
    object_id: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if !is_valid_message_type(message_type) {
        return Err(CryptoError::UnsupportedMessageType);
    }

    let aad = build_aad(PROTOCOL_VERSION, message_type, vault_id, object_id);
    let (nonce, ciphertext) = aead_seal(key, plaintext, &aad)?;

    let mut output = Vec::with_capacity(1 + NONCE_SIZE + ciphertext.len());
    output.push(PROTOCOL_VERSION);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// The expected type comes from the caller, never from the ciphertext.
pub fn decrypt_data(
    key: &[u8; KEY_SIZE],
    expected_type: u8,
    vault_id: &[u8],
    object_id: &[u8],
    encrypted: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if !is_valid_message_type(expected_type) {
        return Err(CryptoError::UnsupportedMessageType);
    }

    if encrypted.len() < MIN_DATA_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }

    let version = encrypted[0];

    if version != PROTOCOL_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }

    let nonce: [u8; NONCE_SIZE] = to_array(&encrypted[1..1 + NONCE_SIZE])?;
    let aad = build_aad(version, expected_type, vault_id, object_id);

    let mut plaintext = aead_open(key, &nonce, &encrypted[1 + NONCE_SIZE..], &aad)?;

    Ok(std::mem::take(&mut *plaintext))
}

// ---------------------------------------------------------------------------
// Identity private keys (encrypted with enc_key or recovery enc_key)
// ---------------------------------------------------------------------------

fn identity_blob_aad(
    user_id: &[u8],
    x25519_public: &[u8; KEY_SIZE],
    ed25519_public: &[u8; KEY_SIZE],
) -> Result<Vec<u8>, CryptoError> {
    encode(&[
        IDENTITY_BLOB_CONTEXT,
        &[PROTOCOL_VERSION],
        user_id,
        x25519_public,
        ed25519_public,
    ])
}

/// Output: version || nonce || ciphertext + tag.
/// The AAD binds the blob to the user and to the public keys.
pub fn encrypt_identity(
    enc_key: &[u8; KEY_SIZE],
    identity: &IdentityKeys,
    user_id: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let aad = identity_blob_aad(user_id, &identity.x25519_public, &identity.ed25519_public)?;

    let mut plaintext = Zeroizing::new([0u8; KEY_SIZE * 2]);
    plaintext[..KEY_SIZE].copy_from_slice(identity.x25519_private());
    plaintext[KEY_SIZE..].copy_from_slice(identity.ed25519_seed());

    let (nonce, ciphertext) = aead_seal(enc_key, &*plaintext, &aad)?;

    let mut blob = Vec::with_capacity(IDENTITY_BLOB_SIZE);
    blob.push(PROTOCOL_VERSION);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);

    Ok(blob)
}

/// `own_identity` must come from local storage, not from a fresh server reply.
pub fn decrypt_identity(
    enc_key: &[u8; KEY_SIZE],
    own_identity: &PublicIdentity,
    blob: &[u8],
) -> Result<IdentityKeys, CryptoError> {
    if blob.len() != IDENTITY_BLOB_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }
    if blob[0] != PROTOCOL_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }

    let nonce: [u8; NONCE_SIZE] = to_array(&blob[1..1 + NONCE_SIZE])?;

    let aad = identity_blob_aad(
        &own_identity.user_id,
        &own_identity.x25519_public,
        &own_identity.ed25519_public,
    )?;

    let plaintext = aead_open(enc_key, &nonce, &blob[1 + NONCE_SIZE..], &aad)?;

    if plaintext.len() != KEY_SIZE * 2 {
        return Err(CryptoError::DecryptionFailed);
    }

    let mut x25519_private = Zeroizing::new([0u8; KEY_SIZE]);
    let mut ed25519_seed = Zeroizing::new([0u8; KEY_SIZE]);
    x25519_private.copy_from_slice(&plaintext[..KEY_SIZE]);
    ed25519_seed.copy_from_slice(&plaintext[KEY_SIZE..]);

    let identity = IdentityKeys::from_secrets(x25519_private, ed25519_seed);

    if identity.x25519_public != own_identity.x25519_public
        || identity.ed25519_public != own_identity.ed25519_public
    {
        return Err(CryptoError::IdentityMismatch);
    }

    Ok(identity)
}

// ---------------------------------------------------------------------------
// Vault key sharing (encrypted and signed by the sender)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct WrappedVaultKey {
    pub vault_id: Vec<u8>,
    pub sender_id: Vec<u8>,
    pub recipient_id: Vec<u8>,
    pub ephemeral_public: [u8; KEY_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
    pub signature: [u8; SIGNATURE_SIZE],
}

impl WrappedVaultKey {
    /// Layout: version || ephemeral_public || nonce || signature || ciphertext.
    /// IDs are stored separately by the server.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WRAPPED_VAULT_KEY_SIZE);
        out.push(PROTOCOL_VERSION);
        out.extend_from_slice(&self.ephemeral_public);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(
        vault_id: &[u8],
        sender_id: &[u8],
        recipient_id: &[u8],
        bytes: &[u8],
    ) -> Result<Self, CryptoError> {
        if bytes.len() != WRAPPED_VAULT_KEY_SIZE {
            return Err(CryptoError::DecryptionFailed);
        }
        if bytes[0] != PROTOCOL_VERSION {
            return Err(CryptoError::UnsupportedVersion);
        }

        Ok(Self {
            vault_id: vault_id.to_vec(),
            sender_id: sender_id.to_vec(),
            recipient_id: recipient_id.to_vec(),
            ephemeral_public: to_array(&bytes[1..33])?,
            nonce: to_array(&bytes[33..57])?,
            signature: to_array(&bytes[57..121])?,
            ciphertext: bytes[121..].to_vec(),
        })
    }
}

fn wrap_aad(
    vault_id: &[u8],
    sender_id: &[u8],
    recipient_id: &[u8],
    ephemeral_public: &[u8; KEY_SIZE],
    recipient_public: &[u8; KEY_SIZE],
) -> Result<Vec<u8>, CryptoError> {
    encode(&[
        WRAP_AAD_CONTEXT,
        &[PROTOCOL_VERSION],
        vault_id,
        sender_id,
        recipient_id,
        ephemeral_public,
        recipient_public,
    ])
}

fn wrap_signed_message(
    aad: &[u8],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    encode(&[WRAP_SIGNATURE_CONTEXT, aad, nonce, ciphertext])
}

/// The recipient must already be verified.
pub fn encrypt_vault_key(
    sender: &IdentityKeys,
    sender_id: &[u8],
    recipient: &VerifiedIdentity,
    vault_id: &[u8],
    vault_key: &[u8; KEY_SIZE],
) -> Result<WrappedVaultKey, CryptoError> {
    let (eph_private, ephemeral_public) = generate_ephemeral_keypair()?;

    let shared = x25519_shared_secret(&eph_private, recipient.x25519_public())?;

    let aead_key = derive_x25519_aead_key(
        &shared,
        &ephemeral_public,
        recipient.x25519_public(),
        vault_id,
        sender_id,
        recipient.user_id(),
    )?;

    let aad = wrap_aad(
        vault_id,
        sender_id,
        recipient.user_id(),
        &ephemeral_public,
        recipient.x25519_public(),
    )?;

    let (nonce, ciphertext) = aead_seal(&aead_key, vault_key, &aad)?;

    let msg = wrap_signed_message(&aad, &nonce, &ciphertext)?;
    let signature = sender.sign(&msg);

    Ok(WrappedVaultKey {
        vault_id: vault_id.to_vec(),
        sender_id: sender_id.to_vec(),
        recipient_id: recipient.user_id().to_vec(),
        ephemeral_public,
        nonce,
        ciphertext,
        signature,
    })
}

/// The sender must already be verified.
pub fn decrypt_vault_key(
    recipient: &IdentityKeys,
    recipient_id: &[u8],
    sender: &VerifiedIdentity,
    wrapped: &WrappedVaultKey,
    expected_vault_id: &[u8],
) -> Result<Zeroizing<[u8; KEY_SIZE]>, CryptoError> {
    if wrapped.vault_id != expected_vault_id
        || wrapped.recipient_id != recipient_id
        || wrapped.sender_id != sender.user_id()
    {
        return Err(CryptoError::IdentityMismatch);
    }

    let aad = wrap_aad(
        &wrapped.vault_id,
        &wrapped.sender_id,
        &wrapped.recipient_id,
        &wrapped.ephemeral_public,
        &recipient.x25519_public,
    )?;

    let msg = wrap_signed_message(&aad, &wrapped.nonce, &wrapped.ciphertext)?;
    verify_signature(sender.ed25519_public(), &msg, &wrapped.signature)?;

    let shared = x25519_shared_secret(recipient.x25519_private(), &wrapped.ephemeral_public)?;

    let aead_key = derive_x25519_aead_key(
        &shared,
        &wrapped.ephemeral_public,
        &recipient.x25519_public,
        &wrapped.vault_id,
        &wrapped.sender_id,
        &wrapped.recipient_id,
    )?;

    let plaintext = aead_open(&aead_key, &wrapped.nonce, &wrapped.ciphertext, &aad)?;

    if plaintext.len() != KEY_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }

    let mut vault_key = Zeroizing::new([0u8; KEY_SIZE]);
    vault_key.copy_from_slice(&plaintext);

    Ok(vault_key)
}