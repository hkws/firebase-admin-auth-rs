use crate::jwk::Jwk;
use jsonwebtoken::decode_header;
use jsonwebtoken::TokenData;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Claims {
    pub aud: String,
    pub exp: i64,
    pub iss: String,
    pub sub: String,
    pub iat: i64,
}

#[derive(Debug)]
enum VerificationError {
    InvalidSignature,
    UnknownKeyAlgorithm,
}

#[derive(Debug, PartialEq)]
pub struct JwkConfig {
    pub audience: String,
    pub issuer: String,
}

#[derive(Debug, PartialEq)]
pub struct JwkVerifier {
    keys: HashMap<String, Jwk>,
    config: JwkConfig,
}

fn keys_to_map(keys: Vec<Jwk>) -> HashMap<String, Jwk> {
    let mut keys_as_map = HashMap::new();
    for key in keys {
        keys_as_map.insert(key.kid.clone(), key);
    }
    keys_as_map
}

impl JwkVerifier {
    pub fn new(keys: Vec<Jwk>, audience: String, issuer: String) -> JwkVerifier {
        JwkVerifier {
            keys: keys_to_map(keys),
            config: JwkConfig { audience, issuer },
        }
    }
    pub fn get_key(&self, key_id: &str) -> Option<&Jwk> {
        self.keys.get(key_id)
    }
    #[cfg(test)]
    pub fn get_config(&self) -> Option<&JwkConfig> {
        Some(&self.config)
    }
    fn decode_token_with_key(
        &self,
        key: &Jwk,
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
    pub fn set_keys(&mut self, keys: Vec<Jwk>) {
        self.keys = keys_to_map(keys);
    }
    pub fn verify(&self, token: &String) -> Option<TokenData<Claims>> {
        let token_kid = match decode_header(token).map(|header| header.kid) {
            Ok(Some(header)) => header,
            _ => return None,
        };
        let jwk_key = match self.get_key(&token_kid) {
            Some(key) => key,
            _ => return None,
        };
        match self.decode_token_with_key(jwk_key, token) {
            Ok(token_data) => Some(token_data),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;

    #[test]
    fn test_keys_to_map() {
        let keys = get_test_keys();
        let map = keys_to_map(keys.clone());
        let mut expected = HashMap::new();
        expected.insert(keys[0].kid.clone(), keys[0].clone());
        expected.insert(keys[1].kid.clone(), keys[1].clone());
        assert_eq!(expected, map);
    }

    #[test]
    fn test_jwk_verifier_new() {
        let keys = get_test_keys();
        let map = keys_to_map(keys.clone());
        let expected = JwkVerifier {
            keys: map,
            config: JwkConfig {
                audience: "aud".to_string(),
                issuer: "iss".to_string(),
            },
        };
        let obtained = JwkVerifier::new(keys, "aud".to_string(), "iss".to_string());
        assert_eq!(expected, obtained);
    }

    #[test]
    fn test_get_key() {
        let keys = get_test_keys();
        let verifier = JwkVerifier::new(keys.clone(), "aud".to_string(), "iss".to_string());
        assert_eq!(verifier.get_key("kid-0"), Some(&keys[0]));
        assert_eq!(verifier.get_key("kid-1"), Some(&keys[1]));
    }

    #[test]
    fn test_get_config() {
        let keys = get_test_keys();
        let verifier = JwkVerifier::new(keys.clone(), "aud".to_string(), "iss".to_string());
        assert_eq!(
            verifier.get_config(),
            Some(&JwkConfig {
                audience: "aud".to_string(),
                issuer: "iss".to_string(),
            })
        );
    }
}
