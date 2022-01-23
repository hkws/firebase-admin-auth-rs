extern crate firebase_admin_auth_rs;
use actix_web::{get, web, App, HttpServer, Responder};
use firebase_admin_auth_rs::jwk_auth::JwkAuth;

use actix_web::error::ErrorUnauthorized;
use actix_web::{dev::Payload, web::Data, Error, FromRequest, HttpRequest, HttpResponse, Result};
use futures_util::future::{err, ok, Ready};
use serde::{Deserialize, Serialize};

use actix_files::NamedFile;
use std::fs;

use env_logger;

#[derive(Deserialize, Serialize, Debug)]
pub struct RequestUser {
    pub uid: String,
}

#[cfg(not(test))]
impl FromRequest for RequestUser {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let token = match req.headers().get("Authorization") {
            Some(auth_header) => match auth_header.to_str() {
                Ok(v) => get_token_from_header(v),
                _ => return err(ErrorUnauthorized("Could not parse auth header")),
            },
            _ => return err(ErrorUnauthorized("Could not parse auth header")),
        };
        if token.is_none() {
            return err(ErrorUnauthorized("Could not parse auth header"));
        }
        let _token = token.unwrap();

        // let jwk_auth = req.app_data::<Data<JwkAuth>>().expect("Could not get JwkAuth");
        let jwk_auth = req.app_data::<Data<JwkAuth>>().unwrap();
        let token_data = jwk_auth.verify(&_token);
        match token_data {
            Some(data) => ok(RequestUser {
                uid: data.claims.sub,
            }),
            _ => err(ErrorUnauthorized("verification failed")),
        }
    }
}

fn get_token_from_header(header: &str) -> Option<String> {
    let prefix_len = "Bearer ".len();

    match header.len() {
        l if l < prefix_len => None,
        _ => Some(header[prefix_len..].to_string()),
    }
}

#[get("/uid")]
async fn uid(user: RequestUser) -> impl Responder {
    user.uid.to_string()
}

#[get("/{file}")]
async fn index(req: HttpRequest, path: web::Path<String>) -> impl Responder {
    let filepath = path.into_inner();
    if let Ok(file) = fs::canonicalize(format!("./examples/statics/{}", filepath)) {
        if let Ok(data) = NamedFile::open_async(file).await {
            return data.into_response(&req);
        }
    }
    HttpResponse::NotFound().finish()
}

fn expect_env_var(name: &str, _default: &str) -> String {
    return std::env::var(name).unwrap_or(_default.to_string());
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info,actix_web=debug");
    env_logger::Builder::from_default_env()
        .target(env_logger::Target::Stdout)
        .init();

    let auth = web::Data::new(
        JwkAuth::new(
            expect_env_var("JWK_AUDIENCE", "fir-admin-auth-rs-test"),
            expect_env_var("JWK_ISSUER", "https://securetoken.google.com/fir-admin-auth-rs-test"),
            Some(expect_env_var("JWK_URL", "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"))
        ).await
    );
    HttpServer::new(move || {
        App::new()
            .app_data(auth.clone())
            .service(uid)
            .service(index)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
