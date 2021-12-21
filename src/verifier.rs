#[double]
use crate::jwk::configs;
use crate::jwk::{JwkConfig, JwkKey};
use mockall_double::double;

use jsonwebtoken::decode_header;
use jsonwebtoken::TokenData;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub aud: String,
    pub exp: i64,
    pub iss: String,
    pub sub: String,
    pub iat: i64,
}

enum VerificationError {
    InvalidSignature,
    UnknownKeyAlgorithm,
}

#[derive(Debug, PartialEq)]
pub struct JwkVerifier {
    keys: HashMap<String, JwkKey>,
    config: JwkConfig,
}

fn keys_to_map(keys: Vec<JwkKey>) -> HashMap<String, JwkKey> {
    let mut keys_as_map = HashMap::new();
    for key in keys {
        keys_as_map.insert(key.kid.clone(), key);
    }
    keys_as_map
}

impl JwkVerifier {
    pub fn new(keys: Vec<JwkKey>) -> JwkVerifier {
        JwkVerifier {
            keys: keys_to_map(keys),
            config: configs::get_configuration(),
        }
    }
    pub fn get_key(&self, key_id: &str) -> Option<&JwkKey> {
        self.keys.get(key_id)
    }
    pub fn get_config(&self) -> Option<&JwkConfig> {
        Some(&self.config)
    }
    fn decode_token_with_key(
        &self,
        key: &JwkKey,
        token: &String,
    ) -> Result<TokenData<Claims>, VerificationError> {
        let algorithm = match Algorithm::from_str(&key.alg) {
            Ok(alg) => alg,
            Err(_error) => return Err(VerificationError::UnknownKeyAlgorithm),
        };
        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[&self.config.audience]);
        validation.iss = Some(self.config.issuer.clone());
        let key = DecodingKey::from_rsa_components(&key.n, &key.e);
        return decode::<Claims>(token, &key, &validation)
            .map_err(|_| VerificationError::InvalidSignature);
    }
    // verifierが認識している公開鍵を更新する
    // Cache-Controlで指定されたmax-ageを超えたら、このメソッドでkeyを更新する。
    pub fn set_keys(&mut self, keys: Vec<JwkKey>) {
        self.keys = keys_to_map(keys);
    }
    // トークン検証を行うメソッド
    // 外部から利用する際はJwkVerifierをnewしてverifyを実行する以外の形は無いはず。
    pub fn verify(&self, token: &String) -> Option<TokenData<Claims>> {
        // トークンのヘッダからkidを取得
        let token_kid = match decode_header(token).map(|header| header.kid) {
            Ok(Some(header)) => header,
            _ => return None,
        };
        // kidに対応する公開鍵を取得
        let jwk_key = match self.get_key(&token_kid) {
            Some(key) => key,
            _ => return None,
        };
        // 公開鍵を使ってデコードし、トークンの有効性を確認。TokenData<Claims>を返す。
        match self.decode_token_with_key(jwk_key, token) {
            Ok(token_data) => Some(token_data),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keys_to_map() {
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
        let map = keys_to_map(keys.clone());
        let mut expected = HashMap::new();
        expected.insert(keys[0].kid.clone(), keys[0].clone());
        expected.insert(keys[1].kid.clone(), keys[1].clone());
        assert_eq!(expected, map);
    }

    #[test]
    fn test_jwk_verifier_new() {
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
        let map = keys_to_map(keys.clone());

        let ctx = configs::get_configuration_context();
        ctx.expect().return_once(|| JwkConfig {
            url: "https://example.com".to_string(),
            audience: "aud".to_string(),
            issuer: "iss".to_string(),
        });

        let expected = JwkVerifier {
            keys: map,
            config: JwkConfig {
                url: "https://example.com".to_string(),
                audience: "aud".to_string(),
                issuer: "iss".to_string(),
            },
        };

        let obtained = JwkVerifier::new(keys);
        assert_eq!(expected, obtained);
    }

    #[test]
    fn test_get_key() {
        let keys = vec![
            JwkKey {
                alg: "RS256".to_string(),
                kid: "kid-0".to_string(),
                e: "AQAB".to_string(),
                n: "n-string".to_string(),
                kty: "RSA".to_string(),
                r#use: "sig".to_string(),
            },
            JwkKey {
                e: "AQAB".to_string(),
                kty: "RSA".to_string(),
                n: "n-string".to_string(),
                kid: "kid-1".to_string(),
                alg: "RS256".to_string(),
                r#use: "sig".to_string(),
            },
        ];

        let ctx = configs::get_configuration_context();
        ctx.expect().return_once(|| JwkConfig {
            url: "https://example.com".to_string(),
            audience: "aud".to_string(),
            issuer: "iss".to_string(),
        });

        let verifier = JwkVerifier::new(keys.clone());
        assert_eq!(verifier.get_key("kid-0"), Some(&keys[0]));
        assert_eq!(verifier.get_key("kid-1"), Some(&keys[1]));
    }

    #[test]
    fn test_get_config() {
        let keys = vec![
            JwkKey {
                alg: "RS256".to_string(),
                kid: "kid-0".to_string(),
                e: "AQAB".to_string(),
                n: "n-string".to_string(),
                kty: "RSA".to_string(),
                r#use: "sig".to_string(),
            },
            JwkKey {
                e: "AQAB".to_string(),
                kty: "RSA".to_string(),
                n: "n-string".to_string(),
                kid: "kid-1".to_string(),
                alg: "RS256".to_string(),
                r#use: "sig".to_string(),
            },
        ];

        let ctx = configs::get_configuration_context();
        ctx.expect().return_once(|| JwkConfig {
            url: "https://example.com".to_string(),
            audience: "aud".to_string(),
            issuer: "iss".to_string(),
        });

        let verifier = JwkVerifier::new(keys.clone());
        assert_eq!(
            verifier.get_config(),
            Some(&JwkConfig {
                url: "https://example.com".to_string(),
                audience: "aud".to_string(),
                issuer: "iss".to_string(),
            })
        );
    }
}
