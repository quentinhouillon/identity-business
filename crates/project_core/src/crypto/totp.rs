use base32::{decode, Alphabet};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use thiserror::Error;

use crate::models::Totp;

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("invalid base32 secret")]
    InvalidSecret,

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("digits must be 6 or 8")]
    InvalidDigits,

    #[error("period must be greater than 0")]
    InvalidPeriod,
}


pub fn generate_code(
    totp: &Totp,
    timestamp: u64,
) -> Result<String, TotpError> {
    if totp.digits != 6 && totp.digits != 8 {
        return Err(TotpError::InvalidDigits);
    }

    if totp.period == 0 {
        return Err(TotpError::InvalidPeriod);
    }

    let secret = decode(
        Alphabet::Rfc4648 { padding: false },
        &totp.secret.to_uppercase(),
    )
    .ok_or(TotpError::InvalidSecret)?;

    let counter = timestamp / totp.period as u64;
    let counter_bytes = counter.to_be_bytes();

    let hash = match totp.algorithm.to_uppercase().as_str() {
        "SHA1" => {
            let mut mac =
                Hmac::<Sha1>::new_from_slice(&secret)
                    .map_err(|_| TotpError::InvalidSecret)?;

            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }

        "SHA256" => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&secret)
                    .map_err(|_| TotpError::InvalidSecret)?;

            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }

        "SHA512" => {
            let mut mac =
                Hmac::<Sha512>::new_from_slice(&secret)
                    .map_err(|_| TotpError::InvalidSecret)?;

            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }

        algorithm => {
            return Err(
                TotpError::UnsupportedAlgorithm(
                    algorithm.to_string()
                )
            );
        }
    };

    let offset =
        (hash[hash.len() - 1] & 0x0f) as usize;

    let binary =
        ((hash[offset] & 0x7f) as u32) << 24 |
        (hash[offset + 1] as u32) << 16 |
        (hash[offset + 2] as u32) << 8 |
        hash[offset + 3] as u32;

    let modulo = 10u32.pow(totp.digits);

    let code = binary % modulo;

    Ok(format!(
        "{:0width$}",
        code,
        width = totp.digits as usize
    ))
}