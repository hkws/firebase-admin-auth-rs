use crate::header_parser::get_max_age;
use reqwest;
use serde::{Deserialize, Serialize};
use std::time::Duration;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
use async_trait::async_trait;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyResponse {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Jwk {
    pub e: String,
    pub alg: String,
    pub kty: String,
    pub kid: String,
    pub n: String,
    pub r#use: String,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
    pub validity: Duration,
}

#[derive(Debug, PartialEq)]
pub struct JwkFetcher {
    pub url: String,
}

#[async_trait]
pub trait Fetcher {
    fn new(url: Option<String>) -> Self;
    async fn fetch_keys(&self) -> Result<Jwks, String>;
}

#[async_trait]
impl Fetcher for JwkFetcher {
    fn new(url: Option<String>) -> JwkFetcher {
        let _url = url.unwrap_or("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string());
        JwkFetcher { url: _url }
    }
    async fn fetch_keys(&self) -> Result<Jwks, String> {
        let response = reqwest::get(&self.url).await.map_err(|e| e.to_string())?;
        let max_age = get_max_age(&response).unwrap_or(DEFAULT_TIMEOUT);
        let response_body = response
            .json::<KeyResponse>()
            .await
            .map_err(|e| e.to_string())?;
        return Ok(Jwks {
            keys: response_body.keys,
            validity: max_age,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;

    #[tokio::test]
    async fn test_fetch_keys() {
        let mock_server = get_mock_server().await;
        let keys = get_test_keys();
        let result = JwkFetcher::new(Some(get_mock_url(&mock_server)))
            .fetch_keys()
            .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            Jwks {
                keys: keys,
                validity: Duration::from_secs(20045)
            }
        );
    }
}
