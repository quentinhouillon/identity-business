use argon2::Argon2;

pub fn derive_key(password: String, salt: &[u8]) -> Result<[u8; 32], argon2::Error> {
    let mut key = [0u8; 32];
    let argon2 = Argon2::default();
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)?;
    Ok(key)
}