use crate::jwk::{Fetcher, JwkFetcher};
use crate::verifier::{Claims, JwkVerifier};
use jsonwebtoken::TokenData;
use log::info;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::sleep;

pub struct JwkAuth {
    verifier: Arc<Mutex<JwkVerifier>>,
    fetcher: Arc<JwkFetcher>,
    task_handler: Arc<Mutex<Box<JoinHandle<()>>>>,
}

impl Drop for JwkAuth {
    fn drop(&mut self) {
        let handler = self.task_handler.lock().unwrap();
        handler.abort();
    }
}

impl JwkAuth {
    pub async fn new(audience: String, issuer: String, pub_key_url: Option<String>) -> JwkAuth {
        let fetcher = JwkFetcher::new(pub_key_url);
        let jwk_key_result = fetcher.fetch_keys().await;
        let jwk_keys = match jwk_key_result {
            Ok(keys) => keys,
            Err(_) => {
                panic!("Unable to fetch jwk keys!")
            }
        };
        let mut instance = JwkAuth {
            verifier: Arc::new(Mutex::new(JwkVerifier::new(
                jwk_keys.keys,
                audience,
                issuer,
            ))),
            fetcher: Arc::new(fetcher),
            task_handler: Arc::new(Mutex::new(Box::new(tokio::spawn(async {})))),
        };
        instance.start_periodic_key_update();
        instance
    }
    pub fn verify(&self, token: &String) -> Option<TokenData<Claims>> {
        let verifier = self.verifier.lock().unwrap();
        verifier.verify(token)
    }
    fn start_periodic_key_update(&mut self) {
        let verifier_ref = Arc::clone(&self.verifier);
        let fetcher_ref = Arc::clone(&self.fetcher);
        let task = tokio::spawn(async move {
            loop {
                let fetch_result = fetcher_ref.fetch_keys().await;
                let delay = match fetch_result {
                    Ok(jwk_keys) => {
                        {
                            let mut verifier = verifier_ref.lock().unwrap();
                            verifier.set_keys(jwk_keys.keys);
                        }
                        info!(
                            "Updated JWK Keys. Next refresh will be in {:?}",
                            jwk_keys.validity
                        );
                        jwk_keys.validity
                    }
                    Err(_) => Duration::from_secs(60),
                };
                sleep(delay).await;
            }
        });
        let mut handler = self.task_handler.lock().unwrap();
        *handler = Box::new(task);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;
    use crate::verifier::JwkConfig;

    #[tokio::test]
    async fn test_jwk_auth_new() {
        let keys = get_test_keys();
        let mock_server = get_mock_server().await;

        let jwk_auth = JwkAuth::new(
            "aud".to_string(),
            "iss".to_string(),
            Some(get_mock_url(&mock_server)),
        )
        .await;
        let verifier = jwk_auth.verifier.lock().unwrap();

        assert_eq!(verifier.get_key("kid-0"), Some(&keys[0]));
        assert_eq!(verifier.get_key("kid-1"), Some(&keys[1]));
        assert_eq!(
            verifier.get_config(),
            Some(&JwkConfig {
                audience: "aud".to_string(),
                issuer: "iss".to_string()
            })
        );
    }
}
