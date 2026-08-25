pub struct User {
    pub username: String,
    pub email: String,
    pub bio: String,
    pub profile_picture: String,
    pub salt: Vec<u16>,
}