use reqwest::Client;
use sha1::{Digest, Sha1};
use thiserror::Error;

const DEFAULT_BASE_URL: &str = "https://api.pwnedpasswords.com";
const USER_AGENT: &str = "lockmate-password-manager";

#[derive(Debug, Error)]
pub enum KAnonymityError {
    #[error("failed to query k-anonymity API: {0}")]
    Http(#[from] reqwest::Error),
    #[error("received an invalid breach count from the k-anonymity API")]
    InvalidCount,
}

#[derive(Clone, Debug)]
pub struct KAnonymityClient {
    base_url: String,
    http: Client,
}

impl KAnonymityClient {
    pub fn new() -> Self {
        let base_url = std::env::var("PWNED_PASSWORDS_BASE_URL")
            .unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
        Self::with_base_url(base_url)
    }

    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        let http = Client::builder()
            .user_agent(USER_AGENT)
            .build()
            .expect("failed to build reqwest client");

        Self {
            base_url: base_url.into(),
            http,
        }
    }

    pub async fn breached_count(&self, password: &str) -> Result<u32, KAnonymityError> {
        if password.is_empty() {
            return Ok(0);
        }

        let hash = Sha1::digest(password.as_bytes());
        let hash_hex = hash
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();
        let (prefix, suffix) = hash_hex.split_at(5);

        let url = format!("{}/range/{}", self.base_url.trim_end_matches('/'), prefix);

        let response = self
            .http
            .get(url)
            .header("Add-Padding", "true")
            .send()
            .await?
            .error_for_status()?;

        let body = response.text().await?;
        for line in body.lines() {
            if let Some((candidate, count)) = line.split_once(':') {
                if candidate.trim().eq_ignore_ascii_case(suffix) {
                    let count = count
                        .trim()
                        .parse::<u32>()
                        .map_err(|_| KAnonymityError::InvalidCount)?;
                    return Ok(count);
                }
            }
        }

        Ok(0)
    }
}
