use reqwest::Response;
use reqwest::header::HeaderValue;
use std::time::Duration;

#[derive(Debug, PartialEq)]
pub enum MaxAgeParseError {
    NoMaxAgeStr,
    NoCacheControlKey,
    NoCacheControlValue,
    NotNumericValue
}

pub fn get_max_age(response: &Response) -> Result<Duration, MaxAgeParseError>{
    let headers = response.headers();
    let cache_control = headers.get("Cache-Control");

    match cache_control {
        Some(cache_control_value) => parse_cache_control_value(cache_control_value),
        None => Err(MaxAgeParseError::NoCacheControlKey)
    }
}

fn parse_cache_control_value(value: &HeaderValue) -> Result<Duration, MaxAgeParseError> {
    match value.to_str() {
        Ok(str_value) => _parse_cache_control_value(str_value),
        Err(_) => Err(MaxAgeParseError::NoCacheControlValue)
    }
}

fn _parse_cache_control_value(value: &str) -> Result<Duration, MaxAgeParseError> {
    let tokens: Vec<&str> = value.split(",").collect();
    for token in tokens {
        let kv: Vec<&str> = token.split("=").map(|s| s.trim()).collect();
        let key = kv.first().unwrap();
        let value = kv.get(1);
        if String::from("max-age").eq(&key.to_lowercase()) {
            match value {
                Some(value) => {
                    return Ok(Duration::from_secs(value.parse().map_err(|_| MaxAgeParseError::NotNumericValue)?))
                },
                None => {
                    unreachable!();
                } 
            }
        }
    }
    return Err(MaxAgeParseError::NoMaxAgeStr);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::{KeyResponse, JwkKey};
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};

    #[tokio::test]
    async fn test_inner_parse_cache_control_value() {
        let value = "public, max-age=20045, must-revalidate, no-transform";
        let result = _parse_cache_control_value(value);

        assert_eq!(result, Ok(Duration::from_secs(20045)));
    }

    #[tokio::test]
    async fn test_inner_parse_cache_control_value_without_max_age() {
        let value = "public, must-revalidate, no-transform";
        let result = _parse_cache_control_value(value);

        assert_eq!(result, Err(MaxAgeParseError::NoMaxAgeStr));
    }

    #[tokio::test]
    async fn test_inner_parse_cache_control_value_with_non_numeric_max_age() {
        let value = "public, max-age=abc, must-revalidate, no-transform";
        let result = _parse_cache_control_value(value);

        assert_eq!(result, Err(MaxAgeParseError::NotNumericValue));
    }

    #[tokio::test]
    async fn test_inner_parse_cache_control_value_without_max_age_value() {
        let value = "public, max-age=, must-revalidate, no-transform";
        let result = _parse_cache_control_value(value);

        assert_eq!(result, Err(MaxAgeParseError::NotNumericValue));
    }

    #[tokio::test]
    async fn test_parse_cache_control() {
        let cc_header = HeaderValue::from_static("public, max-age=20045, must-revalidate, no-transform");
        assert_eq!(parse_cache_control_value(&cc_header), Ok(std::time::Duration::from_secs(20045)));
    }

    #[tokio::test]
    async fn test_parse_cache_control_without_cache_control_value() {
        let cc_header = HeaderValue::from_bytes(b"hello\xfa").unwrap();
        assert_eq!(parse_cache_control_value(&cc_header), Err(MaxAgeParseError::NoCacheControlValue));
    }

    #[tokio::test]
    async fn test_get_max_age_by_response() {
        // Start a background HTTP server on a random local port
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200)
                            .insert_header(
                                "Cache-Control",
                                "public, max-age=20045, must-revalidate, no-transform"
                            )
                            .set_body_json(
                                KeyResponse {
                                    keys: vec![
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
                                    ]
                                }
                            )
                          )
            .mount(&mock_server)
            .await;
        
        let response = reqwest::get(&format!("{}/test", &mock_server.uri()))
                                .await
                                .unwrap();
        
        assert_eq!(get_max_age(&response).unwrap(), std::time::Duration::from_secs(20045))
    }
    
    #[tokio::test]
    async fn test_get_max_age_by_response_without_cache_control() {
        // Start a background HTTP server on a random local port
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200)
                            .set_body_json(
                                KeyResponse {
                                    keys: vec![
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
                                    ]
                                }
                            )
                          )
            .mount(&mock_server)
            .await;
        
        let response = reqwest::get(&format!("{}/test", &mock_server.uri()))
                                .await
                                .unwrap();
        
        assert_eq!(get_max_age(&response), Err(MaxAgeParseError::NoCacheControlKey));
    }


}
