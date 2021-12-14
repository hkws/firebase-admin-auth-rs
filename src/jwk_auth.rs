use mockall_double::double;
#[double]
use crate::jwk::keys;

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
        let jwk_key_result = keys::fetch_keys().await;
        let jwk_keys = match jwk_key_result {
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
                let delay = match keys::fetch_keys().await {
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


#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use crate::jwk::{JwkKey, JwkKeys, JwkConfig};
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};

    #[tokio::test]
    async fn test_jwk_auth_new() {
        // let mock_server = MockServer::start().await;
        let maxage = 20045;
        let keys = vec![
            JwkKey {
                alg: "RS256".to_string(),
                kid: "kid-1".to_string(),
                e: "AQAB".to_string(),
                n: "n-string".to_string(),
                kty: "RSA".to_string(),
                r#use: "sig".to_string()
            },
            JwkKey {
                e: "AQAB".to_string(),
                kty: "RSA".to_string(),
                n: "n-string".to_string(),
                kid: "kid-2".to_string(),
                alg: "RS256".to_string(),
                r#use: "sig".to_string()
            }
        ];
        
        env::set_var("JWK_URL", "http://example");
        env::set_var("JWK_AUDIENCE", "audience");
        env::set_var("JWK_ISSUER", "issuer");

        let ctx = keys::fetch_keys_context();
        ctx.expect()
            .return_const(Ok(JwkKeys {
                keys: keys.clone(),
                validity: Duration::from_secs(maxage)
            }));

        let jwk_auth = JwkAuth::new().await;
        let verifier = jwk_auth.verifier.lock().unwrap();
        assert_eq!(verifier.get_key("kid-1".to_string()), Some(&keys[0]));
        assert_eq!(verifier.get_key("kid-2".to_string()), Some(&keys[1]));
        assert_eq!(verifier.get_config(), Some(&JwkConfig {
            url: "http://example".to_string(),
            audience: "audience".to_string(),
            issuer: "issuer".to_string()
        }));

        env::remove_var("JWK_URL");
        env::remove_var("JWK_AUDIENCE");
        env::remove_var("JWK_ISSUER");
    }

    // #[tokio::test]
    // async fn test_jwk_auth_new_err() {
    //     let mock_server = MockServer::start().await;
    //     let maxage = 20045;
    //     let keys = vec![
    //         JwkKey {
    //             alg: "RS256".to_string(),
    //             kid: "kid-1".to_string(),
    //             e: "AQAB".to_string(),
    //             n: "n-string".to_string(),
    //             kty: "RSA".to_string(),
    //             r#use: "sig".to_string()
    //         },
    //         JwkKey {
    //             e: "AQAB".to_string(),
    //             kty: "RSA".to_string(),
    //             n: "n-string".to_string(),
    //             kid: "kid-2".to_string(),
    //             alg: "RS256".to_string(),
    //             r#use: "sig".to_string()
    //         }
    //     ];
    //     Mock::given(method("GET"))
    //         .and(path("/test"))
    //         .respond_with(ResponseTemplate::new(200)
    //                         .insert_header(
    //                             "Cache-Control",
    //                             &format!("public, max-age={}, must-revalidate, no-transform", maxage) as &str
    //                         )
    //                         .set_body_json(
    //                             KeyResponse {
    //                                 keys: keys.clone()
    //                             }
    //                         )
    //                       )
    //         .mount(&mock_server)
    //         .await;
        
    //     env::set_var("JWK_URL", &format!("{}/test", &mock_server.uri()));
    //     env::set_var("JWK_AUDIENCE", "audience");
    //     env::set_var("JWK_ISSUER", "issuer");

    //     let jwk_auth = JwkAuth::new().await;
    //     let verifier = jwk_auth.verifier.lock().unwrap();
    //     assert_eq!(verifier.get_key("kid-1".to_string()), Some(&keys[0]));
    //     assert_eq!(verifier.get_key("kid-2".to_string()), Some(&keys[1]));
    //     assert_eq!(verifier.get_config(), Some(&JwkConfig {
    //         url: format!("{}/test", &mock_server.uri()),
    //         audience: "audience".to_string(),
    //         issuer: "issuer".to_string()
    //     }));

    //     env::remove_var("JWK_URL");
    //     env::remove_var("JWK_AUDIENCE");
    //     env::remove_var("JWK_ISSUER");
    // }
    
    
}