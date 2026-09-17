use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub username: String,
    pub email: String,
    pub bio: String,
    pub profile_picture: String,
    pub salt: Vec<u16>,
    pub public_key: Vec<u16>,
    pub encrypted_private_key: Vec<u16>,
}