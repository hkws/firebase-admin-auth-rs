use reqwest::blocking::Response;
use reqwest::header::HeaderValue;
use std::time::Duration;

pub enum MaxAgeParseError {
    NoMaxAgeSpecified,
    NoCacheControlHeader,
    MaxAgeValueEmpty,
    NonNumericMaxAge
}

pub fn get_max_age(response: &Response) -> Result<Duration, MaxAgeParseError>{
    let headers = response.headers();
    let cache_control = headers.get("Cache-Control");

    match cache_control {
        Some(cache_control_value) => parse_cache_control_value(cache_control_value),
        None => Err(MaxAgeParseError::NoCacheControlHeader)
    }
}

fn parse_cache_control_value(value: &HeaderValue) -> Result<Duration, MaxAgeParseError> {
    match value.to_str() {
        Ok(str_value) => _parse_cache_control_value(str_value),
        Err(_) => Err(MaxAgeParseError::NoCacheControlHeader)
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
                    return Ok(Duration::from_secs(value.parse().map_err(|_| MaxAgeParseError::NonNumericMaxAge)?))
                },
                None => {
                    return Err(MaxAgeParseError::MaxAgeValueEmpty)
                } 
            }
        }
    }
    return Err(MaxAgeParseError::NoMaxAgeSpecified);
}