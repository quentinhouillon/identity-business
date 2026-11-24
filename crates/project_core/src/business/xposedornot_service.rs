use std::{collections::HashMap, vec};

use reqwest::{Client, StatusCode};
use serde_json::Value;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

async fn check_identifier(client: &Client, identifier: &str) -> Result<Vec<String>, Error> {
    let url = format!("https://api.xposedornot.com/v1/check-email/{}", identifier);

        let response = client
        .get(url)
        .header("User-Agent", "Lair/1.0")
        .send()
        .await?;
    
    match response.status() {
        StatusCode::OK => {
            // response type : {"breaches": [["Adobe","LinkedIn"]]}
            let value: Value = response.json().await?;
            let names = value["breaches"]
                .as_array()
                .map(|outer| {
                    outer
                        .iter()
                        .flat_map(|inner| inner.as_array().into_iter().flatten())
                        .filter_map(|s| s.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            Ok(names)
        }
        StatusCode::NOT_FOUND => Ok(vec![]),
        StatusCode::TOO_MANY_REQUESTS => Err("Rate limit atteint, réessaie plus tard".into()),
        s => Err(format!("Erreur HTTP : {s}").into()),
    }
}

pub async fn check_identifiers(
    identifiers: Vec<String>,
) -> Result<HashMap<String, Vec<String>>, Error> {
    let client = Client::new();
    let mut result: HashMap<String, Vec<String>> = HashMap::new();

    for identifier in identifiers {
        let response = check_identifier(&client, &identifier).await?;
        result.insert(identifier, response);
    }

    Ok(result)
}
