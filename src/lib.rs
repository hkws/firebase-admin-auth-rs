mod jwk;
mod verifier;
mod header_parser;
pub mod jwk_auth;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
