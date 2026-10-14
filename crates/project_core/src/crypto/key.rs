use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::{TryRng, rngs::SysRng};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::crypto_error::CryptoError;

pub const PROTOCOL_NAME: &[u8] = b"LAIR-VAULT";
pub const PROTOCOL_VERSION: u8 = 1;

pub const KEY_SIZE: usize = 32;
pub const SALT_SIZE: usize = 32;

// Default Argon2id parameters used during registration.
const ARGON2_MEMORY_KIB: u32 = 128 * 1024;
const ARGON2_ITERATIONS: u32 = 4;
const ARGON2_LANES: u32 = 2;

// Same bounds as those enforced by the server during registration.
const KDF_MEMORY_KIB_RANGE: std::ops::RangeInclusive<u32> = (64 * 1024)..=(512 * 1024);
const KDF_ITERATIONS_RANGE: std::ops::RangeInclusive<u32> = 2..=10;
const KDF_LANES_RANGE: std::ops::RangeInclusive<u32> = 1..=4;

const ENC_KEY_INFO: &[u8] = b"LAIR-VAULT/enc/v1";
const AUTH_KEY_INFO: &[u8] = b"LAIR-VAULT/auth/v1";
const RECOVERY_ENC_KEY_INFO: &[u8] = b"LAIR-VAULT/recovery-enc/v1";
const RECOVERY_AUTH_KEY_INFO: &[u8] = b"LAIR-VAULT/recovery-auth/v1";

const X25519_WRAP_CONTEXT: &[u8] = b"x25519-vault-key-wrap";

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

/// Paire de sous-clés indépendantes dérivées d'une clé racine.
/// - `enc_key`  : chiffre la clé privée, ne quitte JAMAIS le client.
/// - `auth_key` : envoyée au serveur (mot de passe ou clé de récupération
///   n'étant jamais transmis).
pub struct AccountKeys {
    pub enc_key: Zeroizing<[u8; KEY_SIZE]>,
    pub auth_key: Zeroizing<[u8; KEY_SIZE]>,
}

fn fill_random(buf: &mut [u8], error: CryptoError) -> Result<(), CryptoError> {
    SysRng.try_fill_bytes(buf).map_err(|_| error)
}

/// Generates a random salt for registration or password changes.
pub fn generate_salt() -> Result<[u8; SALT_SIZE], CryptoError> {
    let mut salt = [0u8; SALT_SIZE];

    fill_random(&mut salt, CryptoError::KeyGenerationFailed)?;

    Ok(salt)
}

/// Derives a 32-byte key from the user's password with Argon2id.
/// Private: this key must not leave this module. It is used only as the root
/// key for `derive_account_keys`.
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

/// Splits a root key (a 32-byte PRK) into two independent subkeys.
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

/// Password + salt -> (enc_key, auth_key).
/// The two keys are independent: knowing `auth_key` on the server does not
/// reveal `enc_key` or `master_key`.
pub fn derive_account_keys(
    master_password: &[u8],
    salt: &[u8],
    kdf: KdfParams,
) -> Result<AccountKeys, CryptoError> {
    let master_key = derive_master_key(master_password, salt, kdf)?;

    derive_key_pair(&master_key, ENC_KEY_INFO, AUTH_KEY_INFO)
}

/// Generates a 256-bit recovery key to display to the user once at registration.
pub fn generate_recovery_key() -> Result<Zeroizing<[u8; KEY_SIZE]>, CryptoError> {
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);

    fill_random(&mut *key, CryptoError::KeyGenerationFailed)?;

    Ok(key)
}

/// recovery_key -> (recovery enc_key, recovery auth_key).
/// Argon2 is not needed because the recovery key is already random (256 bits).
pub fn derive_recovery_keys(recovery_key: &[u8; KEY_SIZE]) -> Result<AccountKeys, CryptoError> {
    derive_key_pair(recovery_key, RECOVERY_ENC_KEY_INFO, RECOVERY_AUTH_KEY_INFO)
}

/// Generates a cryptographically random Vault key.
/// The Vault key is the symmetric key used to encrypt Vault data.
pub fn generate_vault_key() -> Result<[u8; KEY_SIZE], CryptoError> {
    let mut key = [0u8; KEY_SIZE];

    fill_random(&mut key, CryptoError::KeyGenerationFailed)?;

    Ok(key)
}

/// Generates an X25519 key pair.
/// The private key must remain client-side.
/// Only the public key should be sent to the backend.
pub fn generate_asymmetric_keypair() -> Result<([u8; KEY_SIZE], [u8; KEY_SIZE]), CryptoError> {
    let mut private_bytes = Zeroizing::new([0u8; KEY_SIZE]);

    fill_random(&mut *private_bytes, CryptoError::KeyGenerationFailed)?;

    let private_key = StaticSecret::from(*private_bytes);
    let public_key = PublicKey::from(&private_key);

    Ok((private_key.to_bytes(), public_key.to_bytes()))
}

/// Derives an AEAD key from an X25519 shared secret.
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

    let hkdf = Hkdf::<Sha256>::new(Some(PROTOCOL_NAME), shared_secret);

    let mut key = [0u8; KEY_SIZE];

    let mut info =
        Vec::with_capacity(X25519_WRAP_CONTEXT.len() + 1 + 1 + vault_id.len() + user_id.len());

    info.extend_from_slice(X25519_WRAP_CONTEXT);

    // Protocol version.
    info.push(PROTOCOL_VERSION);

    // Cryptographic purpose identifier.
    info.push(0x01);

    // Bind the derived key to the Vault and recipient.
    info.extend_from_slice(vault_id);
    info.extend_from_slice(user_id);

    hkdf.expand(&info, &mut key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(key)
}
