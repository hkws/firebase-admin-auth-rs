# firebase-admin-auth-rs

## About

Validate firabase ID token for web backend written in Rust

## Installation

Add the following to Cargo.toml:

```
[dependencies]
firebase-admin-auth-rs = "0.1.0"
```

## Example

Clone this repository

```
git clone https://github.com/hkws/firebase-admin-auth-rs.git
cd firebase-admin-auth-rs
```

Set your firebase project ID to .env file

```
echo "FIREBASE_PROJECT_ID=<YOUR PROJECT ID>" > .env
```

Run actix-web example

```
cargo run --example actix-web
```

then open http://localhost:8080/index.html on your browser.

See details in [actix-web example](https://github.com/hkws/firebase-admin-auth-rs/blob/main/examples/actix-web.rs)

## License

MIT
