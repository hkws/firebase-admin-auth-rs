use crate::header_parser::get_max_age;
use async_trait::async_trait;
use reqwest;
use serde::{Deserialize, Serialize};
use std::time::Duration;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

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

#[derive(Debug)]
pub enum KeyFetchError {
    RequestError(reqwest::Error),
    ReponseBodyError(reqwest::Error),
}

#[async_trait]
pub trait Fetcher {
    fn new(url: String) -> Self;
    async fn fetch_keys(&self) -> Result<Jwks, KeyFetchError>;
}

#[async_trait]
impl Fetcher for JwkFetcher {
    fn new(url: String) -> JwkFetcher {
        JwkFetcher { url: url }
    }
    async fn fetch_keys(&self) -> Result<Jwks, KeyFetchError> {
        let response = reqwest::get(&self.url)
            .await
            .map_err(|e| KeyFetchError::RequestError(e))?;
        let max_age = get_max_age(&response).unwrap_or(DEFAULT_TIMEOUT);
        let response_body = response
            .json::<KeyResponse>()
            .await
            .map_err(|e| KeyFetchError::ReponseBodyError(e))?;
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
    async fn test_new_with_url() {
        let url = "http://example/test".to_string();
        let result = JwkFetcher::new(url.clone());
        assert_eq!(result.url, url);
    }

    #[tokio::test]
    async fn test_fetch_keys() {
        let mock_server = get_mock_server().await;
        let keys = get_test_keys();
        let result = JwkFetcher::new(get_mock_url(&mock_server))
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

    #[tokio::test]
    async fn test_fetch_keys_request_error() {
        let result = JwkFetcher::new("http://example/test".to_string())
            .fetch_keys()
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fetch_keys_invalid_response() {
        let mock_server = get_mock_server_invalid_response().await;
        let result = JwkFetcher::new(get_mock_url(&mock_server))
            .fetch_keys()
            .await;
        assert!(result.is_err());
    }
}
