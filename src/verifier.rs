use crate::jwk::*;
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
    pub iat: i64
}

enum VerificationError {
    InvalidSignature,
    UnknownKeyAlgorithm
}

#[derive(Debug)]
pub struct JwkVerifier {
    keys: HashMap<String, JwkKey>,
    config: JwkConfig
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
            config: get_configuration()
        }
    }
    fn get_key(&self, key_id: String) -> Option<&JwkKey> {
        self.keys.get(&key_id)
    }
    fn decode_token_with_key (
        &self,
        key: &JwkKey,
        token: &String
    ) -> Result<TokenData<Claims>, VerificationError> {
        let algorithm = match Algorithm::from_str(&key.alg) {
            Ok(alg) => alg,
            Err(_error) => return Err(VerificationError::UnknownKeyAlgorithm)
        };
        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[&self.config.audience]);
        validation.iss = Some(self.config.issuer.clone());
        let key = DecodingKey::from_rsa_components(&key.n, &key.e);
        return decode::<Claims>(token, &key, &validation).map_err(|_| VerificationError::InvalidSignature)
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
            _ => return None
        };
        // kidに対応する公開鍵を取得
        let jwk_key = match self.get_key(token_kid) {
            Some(key) => key,
            _ => return None
        };
        // 公開鍵を使ってデコードし、トークンの有効性を確認。TokenData<Claims>を返す。
        match self.decode_token_with_key(jwk_key, token) {
            Ok(token_data) => Some(token_data),
            _ => None
        }
    }
}
