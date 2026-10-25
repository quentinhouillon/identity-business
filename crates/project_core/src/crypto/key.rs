use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::{TryRng, rngs::SysRng};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::crypto_error::CryptoError;

pub const PROTOCOL_NAME: &[u8] = b"LAIR-VAULT";
pub const PROTOCOL_VERSION: u8 = 1;

pub const KEY_SIZE: usize = 32;
pub const SALT_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

const ARGON2_MEMORY_KIB: u32 = 128 * 1024;
const ARGON2_ITERATIONS: u32 = 4;
const ARGON2_LANES: u32 = 2;

// Must match the bounds enforced by the server.
const KDF_MEMORY_KIB_RANGE: std::ops::RangeInclusive<u32> = (64 * 1024)..=(512 * 1024);
const KDF_ITERATIONS_RANGE: std::ops::RangeInclusive<u32> = 2..=10;
const KDF_LANES_RANGE: std::ops::RangeInclusive<u32> = 1..=4;

const ENC_KEY_INFO: &[u8] = b"LAIR-VAULT/enc/v1";
const AUTH_KEY_INFO: &[u8] = b"LAIR-VAULT/auth/v1";
const RECOVERY_ENC_KEY_INFO: &[u8] = b"LAIR-VAULT/recovery-enc/v1";
const RECOVERY_AUTH_KEY_INFO: &[u8] = b"LAIR-VAULT/recovery-auth/v1";

const X25519_WRAP_CONTEXT: &[u8] = b"LAIR-VAULT/x25519-vault-key-wrap/v1";
const BINDING_CONTEXT: &[u8] = b"LAIR-VAULT/identity-binding/v1";
const FINGERPRINT_CONTEXT: &[u8] = b"LAIR-VAULT/fingerprint/v1";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fill_random(buf: &mut [u8], error: CryptoError) -> Result<(), CryptoError> {
    SysRng.try_fill_bytes(buf).map_err(|_| error)
}

/// Length-prefixed encoding (u32 BE) to avoid ambiguous concatenation.
pub fn encode(parts: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
    let total: usize = parts.iter().map(|p| p.len() + 4).sum();
    let mut out = Vec::with_capacity(total);

    for part in parts {
        let len = u32::try_from(part.len()).map_err(|_| CryptoError::InvalidKey)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(part);
    }

    Ok(out)
}

pub fn verify_signature(
    ed25519_public: &[u8; KEY_SIZE],
    message: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(ed25519_public).map_err(|_| CryptoError::InvalidKey)?;

    vk.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::InvalidSignature)
}

// ---------------------------------------------------------------------------
// Password / recovery key derivation
// ---------------------------------------------------------------------------

/// Argon2id parameters received from /prelogin or selected at registration.
#[derive(Clone, Copy, Debug)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: ARGON2_MEMORY_KIB,
            iterations: ARGON2_ITERATIONS,
            lanes: ARGON2_LANES,
        }
    }
}

impl KdfParams {
    /// Server-provided parameters must never be trusted without validation.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if KDF_MEMORY_KIB_RANGE.contains(&self.memory_kib)
            && KDF_ITERATIONS_RANGE.contains(&self.iterations)
            && KDF_LANES_RANGE.contains(&self.lanes)
        {
            Ok(())
        } else {
            Err(CryptoError::KeyDerivationFailed)
        }
    }
}

/// `enc_key` never leaves the client; `auth_key` is sent to the server.
pub struct AccountKeys {
    pub enc_key: Zeroizing<[u8; KEY_SIZE]>,
    pub auth_key: Zeroizing<[u8; KEY_SIZE]>,
}

pub fn generate_salt() -> Result<[u8; SALT_SIZE], CryptoError> {
    let mut salt = [0u8; SALT_SIZE];
    fill_random(&mut salt, CryptoError::KeyGenerationFailed)?;
    Ok(salt)
}

fn derive_master_key(
    master_password: &[u8],
    salt: &[u8],
    kdf: KdfParams,
) -> Result<Zeroizing<[u8; KEY_SIZE]>, CryptoError> {
    if salt.len() < SALT_SIZE {
        return Err(CryptoError::InvalidSalt);
    }

    kdf.validate()?;

    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.lanes, Some(KEY_SIZE))
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut master_key = Zeroizing::new([0u8; KEY_SIZE]);

    argon2
        .hash_password_into(master_password, salt, &mut *master_key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(master_key)
}

fn derive_key_pair(
    prk: &[u8; KEY_SIZE],
    enc_info: &[u8],
    auth_info: &[u8],
) -> Result<AccountKeys, CryptoError> {
    let hkdf = Hkdf::<Sha256>::from_prk(&prk[..]).map_err(|_| CryptoError::KeyDerivationFailed)?;

    let mut enc_key = Zeroizing::new([0u8; KEY_SIZE]);
    let mut auth_key = Zeroizing::new([0u8; KEY_SIZE]);

    hkdf.expand(enc_info, &mut *enc_key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    hkdf.expand(auth_info, &mut *auth_key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(AccountKeys { enc_key, auth_key })
}

pub fn derive_account_keys(
    master_password: &[u8],
    salt: &[u8],
    kdf: KdfParams,
) -> Result<AccountKeys, CryptoError> {
    let master_key = derive_master_key(master_password, salt, kdf)?;
    derive_key_pair(&master_key, ENC_KEY_INFO, AUTH_KEY_INFO)
}

pub fn generate_recovery_key() -> Result<Zeroizing<[u8; KEY_SIZE]>, CryptoError> {
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    fill_random(&mut *key, CryptoError::KeyGenerationFailed)?;
    Ok(key)
}

/// No Argon2 needed: the recovery key is already 256 random bits.
pub fn derive_recovery_keys(recovery_key: &[u8; KEY_SIZE]) -> Result<AccountKeys, CryptoError> {
    derive_key_pair(recovery_key, RECOVERY_ENC_KEY_INFO, RECOVERY_AUTH_KEY_INFO)
}

pub fn generate_vault_key() -> Result<Zeroizing<[u8; KEY_SIZE]>, CryptoError> {
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    fill_random(&mut *key, CryptoError::KeyGenerationFailed)?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// Identity keys: X25519 (key agreement) + Ed25519 (signing)
// ---------------------------------------------------------------------------

pub struct IdentityKeys {
    x25519_private: Zeroizing<[u8; KEY_SIZE]>,
    ed25519_seed: Zeroizing<[u8; KEY_SIZE]>,
    pub x25519_public: [u8; KEY_SIZE],
    pub ed25519_public: [u8; KEY_SIZE],
}

impl IdentityKeys {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut x25519_private = Zeroizing::new([0u8; KEY_SIZE]);
        let mut ed25519_seed = Zeroizing::new([0u8; KEY_SIZE]);

        fill_random(&mut *x25519_private, CryptoError::KeyGenerationFailed)?;
        fill_random(&mut *ed25519_seed, CryptoError::KeyGenerationFailed)?;

        Ok(Self::from_secrets(x25519_private, ed25519_seed))
    }

    /// Rebuilds an identity from decrypted secrets; public keys are recomputed.
    pub fn from_secrets(
        x25519_private: Zeroizing<[u8; KEY_SIZE]>,
        ed25519_seed: Zeroizing<[u8; KEY_SIZE]>,
    ) -> Self {
        let x25519_public = PublicKey::from(&StaticSecret::from(*x25519_private)).to_bytes();
        let ed25519_public = SigningKey::from_bytes(&ed25519_seed)
            .verifying_key()
            .to_bytes();

        Self {
            x25519_private,
            ed25519_seed,
            x25519_public,
            ed25519_public,
        }
    }

    pub fn x25519_private(&self) -> &[u8; KEY_SIZE] {
        &self.x25519_private
    }

    pub fn ed25519_seed(&self) -> &[u8; KEY_SIZE] {
        &self.ed25519_seed
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_SIZE] {
        SigningKey::from_bytes(&self.ed25519_seed)
            .sign(message)
            .to_bytes()
    }
}

// ---------------------------------------------------------------------------
// Signed binding: user_id <-> public keys
// ---------------------------------------------------------------------------

/// What the server stores and distributes for a user.
#[derive(Clone, Debug)]
pub struct PublicIdentity {
    pub user_id: Vec<u8>,
    pub x25519_public: [u8; KEY_SIZE],
    pub ed25519_public: [u8; KEY_SIZE],
    pub signature: [u8; SIGNATURE_SIZE],
}

fn binding_message(
    user_id: &[u8],
    x25519_public: &[u8; KEY_SIZE],
    ed25519_public: &[u8; KEY_SIZE],
) -> Result<Vec<u8>, CryptoError> {
    encode(&[
        BINDING_CONTEXT,
        &[PROTOCOL_VERSION],
        user_id,
        x25519_public,
        ed25519_public,
    ])
}

impl PublicIdentity {
    /// `user_id` must be the raw 16 bytes of the UUID, not its text form.
    pub fn sign(identity: &IdentityKeys, user_id: &[u8]) -> Result<Self, CryptoError> {
        let msg = binding_message(user_id, &identity.x25519_public, &identity.ed25519_public)?;

        Ok(Self {
            user_id: user_id.to_vec(),
            x25519_public: identity.x25519_public,
            ed25519_public: identity.ed25519_public,
            signature: identity.sign(&msg),
        })
    }

    fn verify_binding(&self) -> Result<(), CryptoError> {
        let msg = binding_message(&self.user_id, &self.x25519_public, &self.ed25519_public)?;
        verify_signature(&self.ed25519_public, &msg, &self.signature)
    }

    /// Fingerprint to compare out of band.
    pub fn fingerprint(&self) -> Result<String, CryptoError> {
        let data = encode(&[FINGERPRINT_CONTEXT, &self.user_id, &self.ed25519_public])?;
        let hex: String = Sha256::digest(&data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        Ok(hex
            .as_bytes()
            .chunks(8)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join(" "))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustStatus {
    /// Ed25519 key matches the locally pinned one.
    Pinned,
    /// First contact: the caller should pin the key.
    FirstUse,
}

/// Only obtainable through `verify_peer_identity`.
#[derive(Clone, Debug)]
pub struct VerifiedIdentity {
    user_id: Vec<u8>,
    x25519_public: [u8; KEY_SIZE],
    ed25519_public: [u8; KEY_SIZE],
}

impl VerifiedIdentity {
    pub fn user_id(&self) -> &[u8] {
        &self.user_id
    }
    pub fn x25519_public(&self) -> &[u8; KEY_SIZE] {
        &self.x25519_public
    }
    pub fn ed25519_public(&self) -> &[u8; KEY_SIZE] {
        &self.ed25519_public
    }
}

/// Must be called on every public identity received from the server.
pub fn verify_peer_identity(
    received: &PublicIdentity,
    expected_user_id: &[u8],
    pinned_ed25519: Option<&[u8; KEY_SIZE]>,
) -> Result<(VerifiedIdentity, TrustStatus), CryptoError> {
    if received.user_id != expected_user_id {
        return Err(CryptoError::IdentityMismatch);
    }

    received.verify_binding()?;

    let status = match pinned_ed25519 {
        Some(pinned) if pinned != &received.ed25519_public => {
            return Err(CryptoError::IdentityKeyChanged);
        }
        Some(_) => TrustStatus::Pinned,
        None => TrustStatus::FirstUse,
    };

    Ok((
        VerifiedIdentity {
            user_id: received.user_id.clone(),
            x25519_public: received.x25519_public,
            ed25519_public: received.ed25519_public,
        },
        status,
    ))
}

// ---------------------------------------------------------------------------
// X25519 key agreement
// ---------------------------------------------------------------------------

pub fn generate_ephemeral_keypair()
-> Result<(Zeroizing<[u8; KEY_SIZE]>, [u8; KEY_SIZE]), CryptoError> {
    let mut private = Zeroizing::new([0u8; KEY_SIZE]);
    fill_random(&mut *private, CryptoError::KeyGenerationFailed)?;

    let public = PublicKey::from(&StaticSecret::from(*private)).to_bytes();

    Ok((private, public))
}

/// Rejects low-order points.
pub fn x25519_shared_secret(
    private_key: &[u8; KEY_SIZE],
    peer_public: &[u8; KEY_SIZE],
) -> Result<Zeroizing<[u8; KEY_SIZE]>, CryptoError> {
    let secret = StaticSecret::from(*private_key);
    let shared = secret.diffie_hellman(&PublicKey::from(*peer_public));

    if !shared.was_contributory() {
        return Err(CryptoError::KeyDerivationFailed);
    }

    Ok(Zeroizing::new(shared.to_bytes()))
}

/// AEAD key bound to the protocol, Vault, sender, recipient and both public keys.
pub fn derive_x25519_aead_key(
    shared_secret: &[u8; KEY_SIZE],
    ephemeral_public: &[u8; KEY_SIZE],
    recipient_public: &[u8; KEY_SIZE],
    vault_id: &[u8],
    sender_id: &[u8],
    recipient_id: &[u8],
) -> Result<Zeroizing<[u8; KEY_SIZE]>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(PROTOCOL_NAME), shared_secret);

    let info = encode(&[
        X25519_WRAP_CONTEXT,
        &[PROTOCOL_VERSION, 0x01],
        ephemeral_public,
        recipient_public,
        vault_id,
        sender_id,
        recipient_id,
    ])?;

    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    hkdf.expand(&info, &mut *key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(key)
}