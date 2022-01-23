mod header_parser;
mod jwk;
pub mod jwk_auth;
mod verifier;

#[cfg(test)]
mod tests {
    use crate::jwk::{Jwk, KeyResponse};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    pub const MAXAGE: u64 = 20045;
    pub const PATH: &'static str = "/test";
    pub fn get_test_keys() -> Vec<Jwk> {
        vec![
            Jwk {
                alg: "RS256".to_string(),
                kid: "kid-0".to_string(),
                e: "AQAB".to_string(),
                n: "n-string".to_string(),
                kty: "RSA".to_string(),
                r#use: "sig".to_string(),
            },
            Jwk {
                e: "AQAB".to_string(),
                kty: "RSA".to_string(),
                n: "n-string".to_string(),
                kid: "kid-1".to_string(),
                alg: "RS256".to_string(),
                r#use: "sig".to_string(),
            },
        ]
    }
    pub async fn get_mock_server() -> MockServer {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "Cache-Control",
                        &format!("public, max-age={}, must-revalidate, no-transform", MAXAGE)
                            as &str,
                    )
                    .set_body_json(KeyResponse {
                        keys: get_test_keys(),
                    }),
            )
            .mount(&mock_server)
            .await;

        mock_server
    }

    pub async fn get_mock_server_invalid_response() -> MockServer {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(PATH))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        mock_server
    }

    pub fn get_mock_url(mock_server: &MockServer) -> String {
        format!("{}{}", mock_server.uri(), PATH)
    }
}
