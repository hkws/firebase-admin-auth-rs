use reqwest::header::HeaderValue;
use reqwest::Response;
use std::time::Duration;

#[derive(Debug, PartialEq)]
pub enum MaxAgeParseError {
    NoMaxAgeStr,
    NoCacheControlKey,
    NoCacheControlValue,
    NotNumericValue,
}

pub fn get_max_age(response: &Response) -> Result<Duration, MaxAgeParseError> {
    let headers = response.headers();
    let cache_control = headers.get("Cache-Control");

    match cache_control {
        Some(cache_control_value) => parse_cache_control_value(cache_control_value),
        None => Err(MaxAgeParseError::NoCacheControlKey),
    }
}

fn parse_cache_control_value(value: &HeaderValue) -> Result<Duration, MaxAgeParseError> {
    match value.to_str() {
        Ok(str_value) => _parse_cache_control_value(str_value),
        Err(_) => Err(MaxAgeParseError::NoCacheControlValue),
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
                    return Ok(Duration::from_secs(
                        value
                            .parse()
                            .map_err(|_| MaxAgeParseError::NotNumericValue)?,
                    ))
                }
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
    use crate::jwk::KeyResponse;
    use crate::tests::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_inner_parse_cache_control_value() {
        let value = &format!("public, max-age={}, must-revalidate, no-transform", MAXAGE);
        let result = _parse_cache_control_value(value);

        assert_eq!(result, Ok(Duration::from_secs(MAXAGE)));
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
        let cc_header =
            HeaderValue::from_static("public, max-age=20045, must-revalidate, no-transform");
        assert_eq!(
            parse_cache_control_value(&cc_header),
            Ok(std::time::Duration::from_secs(20045))
        );
    }

    #[tokio::test]
    async fn test_parse_cache_control_without_cache_control_value() {
        let cc_header = HeaderValue::from_bytes(b"hello\xfa").unwrap();
        assert_eq!(
            parse_cache_control_value(&cc_header),
            Err(MaxAgeParseError::NoCacheControlValue)
        );
    }

    #[tokio::test]
    async fn test_get_max_age_by_response() {
        let mock_server = get_mock_server().await;
        let response = reqwest::get(&get_mock_url(&mock_server)).await.unwrap();
        assert_eq!(
            get_max_age(&response).unwrap(),
            std::time::Duration::from_secs(MAXAGE)
        )
    }
    #[tokio::test]
    async fn test_get_max_age_by_response_without_cache_control() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(KeyResponse {
                keys: get_test_keys(),
            }))
            .mount(&mock_server)
            .await;
        let response = reqwest::get(&get_mock_url(&mock_server)).await.unwrap();
        assert_eq!(
            get_max_age(&response),
            Err(MaxAgeParseError::NoCacheControlKey)
        );
    }
}
