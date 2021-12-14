use reqwest;
use std::time::Duration;
use std::error::Error;
use serde::{Serialize, Deserialize};
use crate::header_parser::get_max_age;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(test)]
use mockall::{automock};

//---------------------
// 公開鍵取得元に関する設定
//---------------------
#[derive(Debug, PartialEq)]
pub struct JwkConfig {
    pub url: String,
    pub audience: String,
    pub issuer: String
}

fn expect_env_var(name: &str, _default: &str) -> String {
    return std::env::var(name).unwrap_or(_default.to_string());
}

// 環境変数から公開鍵取得元の情報を取得
pub fn get_configuration() -> JwkConfig {
    JwkConfig {
        url: expect_env_var("JWK_URL", "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"),
        audience: expect_env_var("JWK_AUDIENCE", "fir-admin-auth-rs-test"),
        issuer: expect_env_var("JWK_ISSUER", "https://securetoken.google.com/fir-admin-auth-rs-test"),
    }
}

//---------------------
// 公開鍵取得処理
//---------------------
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyResponse {
    pub keys: Vec<JwkKey>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct JwkKey {
    pub e: String,
    pub alg: String,
    pub kty: String,
    pub kid: String,
    pub n: String,
    pub r#use: String,
}

#[derive(Debug, PartialEq, Clone)]
pub struct JwkKeys {
    pub keys: Vec<JwkKey>,
    pub validity: Duration,
}

//
// jwk_configで設定してあるパラメータを使って公開鍵を取得する
//
#[cfg_attr(test, automock)]
pub mod keys { 
    use super::*;
    pub async fn fetch_keys() -> Result<JwkKeys, String> {
        let config = get_configuration();
        let response = reqwest::get(&config.url).await.map_err(|e| e.to_string())?;
        let max_age = get_max_age(&response).unwrap_or(DEFAULT_TIMEOUT);
        let response_body = response.json::<KeyResponse>().await.map_err(|e| e.to_string())?;
        return Ok(JwkKeys {
            keys: response_body.keys,
            validity: max_age
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use crate::jwk::{KeyResponse, JwkKey};
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};

    // audience: expect_env_var("JWK_AUDIENCE", "fir-admin-auth-rs-test"),
    // issuer: expect_env_var("JWK_ISSUER", "https://securetoken.google.com/fir-admin-auth-rs-test"),
    
    #[test]
    fn test_get_configuration() {
        env::set_var("JWK_URL", "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com");
        env::set_var("JWK_AUDIENCE", "audience");
        env::set_var("JWK_ISSUER", "issuer");
        assert_eq!(get_configuration(), JwkConfig {
            url: "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com".to_string(),
            audience: "audience".to_string(),
            issuer: "issuer".to_string()
        });
        env::remove_var("JWK_URL");
        env::remove_var("JWK_AUDIENCE");
        env::remove_var("JWK_ISSUER");
    }
    
    #[tokio::test]
    async fn test_fetch_keys() {
        let mock_server = MockServer::start().await;
        let maxage = 20045;
        let keys = vec![
            JwkKey {
                alg: "RS256".to_string(),
                kid: "80585f992112ff88111399a369756175aa1b4cf9".to_string(),
                e: "AQAB".to_string(),
                n: "o3o6mxbgRBPx393pvoGp8OLIEa5g6as2uea5Xxw8nhdLyDEs0DgwRQRFHxBQGbOIOHLDDBxuL4zBWF1c-M8y1yXz96TiMF1db23f-63piSWLeaNdsDQ1uCHynOYSfsZ4bcXvPncxQ1t0a4DQay1xn7RKZJafmhffOCkVwzPlYo1brLyidPw8iGGl9OQrIPAjczNfOGtu7__uXLxs1RP3PeFJ6fWNz0X0vzjjI5W1vH2P2kP_ivGbsB7oldN62lVshtDmQikmfFGYCW-7ZVyuM7tA8M2HghDdZBcqQb0PD_P7u5cQmPCE5ScZt4naFfbxXC0HlHNSgi93ZB7XeLamaw".to_string(),
                kty: "RSA".to_string(),
                r#use: "sig".to_string()
            },
            JwkKey {
                e: "AQAB".to_string(),
                kty: "RSA".to_string(),
                n: "larGNn26VeAWwyGsbEEsKDQV5RKOoXB-hCqcH0-eudhK2F_9e-31L4lzOMjnzPWlwv1zlInl7iX4sgsZ381kWKHYbfX1RA7B-AM1wnPaRTXlYIzaM9jIOysswHy5IBvFrYxDSZzAwlW2ooD_1fiDGFeKz3tZ8OvjIFlXAOCsf9da7vSMxw4rR-7LnnPf4kTXlFj97UwXgxblZ5Kw7uK9s9IHlaNnXOxdUUmBci_6DcoI6wnz3rm3ulTxMlN1VvBjP9txOk1LYg_AZEnfrEvFWFEXXzSM4Vhiu3sG3YU04vPXUGoGUeIU5YYjGASAAJbabiLshh5sqHfb_A1msqpHYQ".to_string(),
                kid: "47989e58ee5838983d8a4405de95da9ee6f5eeb8".to_string(),
                alg: "RS256".to_string(),
                r#use: "sig".to_string()
            }
        ];
        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200)
                            .insert_header(
                                "Cache-Control",
                                &format!("public, max-age={}, must-revalidate, no-transform", maxage) as &str
                            )
                            .set_body_json(
                                KeyResponse {
                                    keys: keys.clone()
                                }
                            )
                          )
            .mount(&mock_server)
            .await;
        
        env::set_var("JWK_URL", &format!("{}/test", &mock_server.uri()));
        env::set_var("JWK_AUDIENCE", "audience");
        env::set_var("JWK_ISSUER", "issuer");

        let result = keys::fetch_keys().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), JwkKeys {
            keys: keys,
            validity: Duration::from_secs(maxage)
        });

        env::remove_var("JWK_URL");
        env::remove_var("JWK_AUDIENCE");
        env::remove_var("JWK_ISSUER");
    }

}

