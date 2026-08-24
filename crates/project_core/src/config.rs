use std::sync::OnceLock;

static BASE_URL: OnceLock<String> = OnceLock::new();

pub fn set_base_url(base_url: String) {
    BASE_URL
        .set(base_url)
        .expect("BASE_URL has already been initialized");
}

pub fn get_base_url() -> &'static str {
    BASE_URL
        .get()
        .expect("BASE_URL has not been initialized")
}