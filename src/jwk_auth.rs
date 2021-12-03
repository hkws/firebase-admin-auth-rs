use crate::jwk::{fetch_keys, JwkKeys};
use crate::verifier::{Claims, JwkVerifier};
use jsonwebtoken::TokenData;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use log::{info};
use tokio::time::sleep;
use tokio::task::JoinHandle;

pub struct JwkAuth {
    verifier: Arc<Mutex<JwkVerifier>>,
    task_handler: Arc<Mutex<Box<JoinHandle<()>>>>
}

impl Drop for JwkAuth {
    fn drop(&mut self) {
        let handler = self.task_handler.lock().unwrap();
        handler.abort();
    }
}

impl JwkAuth {
    pub async fn new() -> JwkAuth {
        let jwk_key_result = fetch_keys().await;
        let jwk_keys: JwkKeys = match jwk_key_result {
            Ok(keys) => keys,
            Err(_) => {
                panic!("Unable to fetch jwk keys! Cannot verify user tokens!")
            }
        };
        let verifier = Arc::new(Mutex::new(JwkVerifier::new(jwk_keys.keys)));
        let mut instance = JwkAuth {
            verifier: verifier,
            task_handler: Arc::new(Mutex::new(Box::new(tokio::spawn(async {}))))
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
        let task = tokio::spawn(async move {
            loop {
                let delay = match fetch_keys().await {
                    Ok(jwk_keys) => {
                        {
                            let mut verifier = verifier_ref.lock().unwrap();
                            verifier.set_keys(jwk_keys.keys);
                        }
                        info!("Updated JWK Keys. Next refresh will be in {:?}", jwk_keys.validity);
                        jwk_keys.validity
                    },
                    Err(_) => Duration::from_secs(60)
                };
                sleep(delay).await;
            }
        });
        let mut handler = self.task_handler.lock().unwrap();
        *handler = Box::new(task);
    }
}

