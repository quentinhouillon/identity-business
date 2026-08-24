use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Client,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

pub struct ApiService {
    client: Client,
    base_url: String,
}

impl ApiService {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: crate::config::get_base_url().to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url,
            path.trim_start_matches('/')
        )
    }

    fn build_headers(headers: Option<Vec<(&str, &str)>>) -> HeaderMap {
        let mut header_map = HeaderMap::new();

        if let Some(headers) = headers {
            for (key, value) in headers {
                if let (Ok(name), Ok(value)) = (
                    HeaderName::from_bytes(key.as_bytes()),
                    HeaderValue::from_str(value),
                ) {
                    header_map.insert(name, value);
                }
            }
        }

        header_map
    }

    pub async fn get<T>(
        &self,
        path: &str,
        headers: Option<Vec<(&str, &str)>>,
    ) -> Result<T, reqwest::Error>
    where
        T: DeserializeOwned,
    {
        self.client
            .get(self.url(path))
            .headers(Self::build_headers(headers))
            .send()
            .await?
            .error_for_status()?
            .json::<T>()
            .await
    }

    pub async fn post<T, B>(
        &self,
        path: &str,
        body: &B,
        headers: Option<Vec<(&str, &str)>>,
    ) -> Result<T, reqwest::Error>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.client
            .post(self.url(path))
            .headers(Self::build_headers(headers))
            .json(body)
            .send()
            .await?
            .error_for_status()?
            .json::<T>()
            .await
    }

    pub async fn put<T, B>(
        &self,
        path: &str,
        body: &B,
        headers: Option<Vec<(&str, &str)>>,
    ) -> Result<T, reqwest::Error>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.client
            .put(self.url(path))
            .headers(Self::build_headers(headers))
            .json(body)
            .send()
            .await?
            .error_for_status()?
            .json::<T>()
            .await
    }

    pub async fn delete<T>(
        &self,
        path: &str,
        headers: Option<Vec<(&str, &str)>>,
    ) -> Result<T, reqwest::Error>
    where
        T: DeserializeOwned,
    {
        self.client
            .delete(self.url(path))
            .headers(Self::build_headers(headers))
            .send()
            .await?
            .error_for_status()?
            .json::<T>()
            .await
    }
}