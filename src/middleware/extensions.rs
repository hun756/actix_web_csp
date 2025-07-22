use crate::core::source::Source;
use crate::security::hash::HashAlgorithm;
use crate::security::nonce::RequestNonce;
use actix_web::HttpMessage;

pub trait CspExtensions {
    fn get_nonce(&self) -> Option<String>;
    fn generate_hash(&self, algorithm: HashAlgorithm, data: &[u8]) -> String;
    fn generate_hash_source(&self, algorithm: HashAlgorithm, data: &[u8]) -> Source;
}

impl<T> CspExtensions for T
where
    T: HttpMessage,
{
    fn get_nonce(&self) -> Option<String> {
        self.extensions()
            .get::<RequestNonce>()
            .map(|nonce| nonce.0.clone())
    }

    fn generate_hash(&self, algorithm: HashAlgorithm, data: &[u8]) -> String {
        crate::security::hash::HashGenerator::generate(algorithm, data)
    }

    fn generate_hash_source(&self, algorithm: HashAlgorithm, data: &[u8]) -> Source {
        crate::security::hash::HashGenerator::generate_source(algorithm, data)
    }
}
