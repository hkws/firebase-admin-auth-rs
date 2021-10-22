use reqwest;
use std::time::Duration;
use std::error::Error;
use serde::Deserialize;
use crate::cache_control::get_max_age;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

//---------------------
// 公開鍵取得元に関する設定
//---------------------
#[derive(Debug)]
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
#[derive(Debug, Deserialize)]
struct KeyResponse {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct JwkKey {
    pub e: String,
    pub alg: String,
    pub kty: String,
    pub kid: String,
    pub n: String,
}

pub struct JwkKeys {
    pub keys: Vec<JwkKey>,
    pub validity: Duration,
}

pub fn fetch_keys_with_config(config: JwkConfig) -> Result<JwkKeys, Box<dyn Error>> {
    // let response = reqwest::get(&config.url)
    //                         .await?
    //                         .json::<KeyResponse>()
    //                         .await?;
    let response = reqwest::blocking::get(&config.url)?;
    let max_age = get_max_age(&response).unwrap_or(DEFAULT_TIMEOUT); //DEFAULT_TIMEOUT;
    let response_body = response.json::<KeyResponse>()?;
    return Ok(JwkKeys {
        keys: response_body.keys,
        validity: max_age
    })
}

//
// jwk_configで設定してあるパラメータを使って公開鍵を取得する
// 外部から利用されるのはこのfunctionだけのはず
//
pub fn fetch_keys() -> Result<JwkKeys, Box<dyn Error>> {
    return fetch_keys_with_config(get_configuration())
}