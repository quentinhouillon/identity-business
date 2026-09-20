use futures::{StreamExt, stream};
use reqwest::Client;
use sha1::{Digest, Sha1};
use std::collections::HashMap;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
struct PasswordHash {
    password: String,
    prefix: String,
    suffix: String,
}

fn _hash_password(password: String) -> PasswordHash {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());

    let hash = format!("{:X}", hasher.finalize());

    PasswordHash {
        password,
        prefix: hash[..5].to_string(),
        suffix: hash[5..].to_string(),
    }
}

fn _hash_passwords(passwords: Vec<String>) -> Vec<PasswordHash> {
    passwords.into_iter().map(_hash_password).collect()
}

fn _group_by_prefix(passwords: Vec<PasswordHash>) -> HashMap<String, Vec<PasswordHash>> {
    let mut groups = HashMap::new();

    for password in passwords {
        groups
            .entry(password.prefix.clone())
            .or_insert_with(Vec::new)
            .push(password);
    }

    groups
}

async fn _fetch_prefix(client: &Client, prefix: &str) -> Result<HashMap<String, u64>, Error> {
    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

    let response = client
        .get(url)
        .header("User-Agent", "Lair/1.0")
        .send()
        .await?
        .text()
        .await?;

    let mut hashes = HashMap::new();

    for line in response.lines() {
        let mut parts = line.split(':');

        if let (Some(suffix), Some(count)) = (parts.next(), parts.next()) {
            hashes.insert(suffix.to_uppercase(), count.parse::<u64>().unwrap_or(0));
        }
    }

    Ok(hashes)
}

fn _check_hashes(
    passwords: Vec<PasswordHash>,
    leaked_hashes: &HashMap<String, u64>,
) -> Vec<(String, bool)> {
    passwords
        .into_iter()
        .map(|password| {
            let compromised = leaked_hashes.contains_key(&password.suffix);

            (password.password, compromised)
        })
        .collect()
}

async fn _fetch_prefixes(
    groups: HashMap<String, Vec<PasswordHash>>,
    client: Client,
) -> Result<Vec<(Vec<PasswordHash>, HashMap<String, u64>)>, Error> {

    let results = stream::iter(groups)
        .map(|(prefix, passwords)| {
            let client = client.clone();

            async move {
                let hashes = _fetch_prefix(&client, &prefix).await?;

                Ok::<_, Error>((passwords, hashes))
            }
        })
        .buffer_unordered(10)
        .collect::<Vec<_>>()
        .await;

    results.into_iter().collect()
}

pub async fn check_passwords(passwords: Vec<String>) -> Result<Vec<(String, bool)>, Error> {
    let client = Client::new();

    let passwords = _hash_passwords(passwords);

    let groups = _group_by_prefix(passwords);

    let groups = _fetch_prefixes(groups, client).await?;

    let mut results = Vec::new();

    for (passwords, leaked_hashes) in groups {
        let group_results = _check_hashes(passwords, &leaked_hashes);

        results.extend(group_results);
    }

    Ok(results)
}
