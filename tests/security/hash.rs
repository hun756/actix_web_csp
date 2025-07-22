use actix_web_csp::error::CspError;
use actix_web_csp::security::{HashAlgorithm, HashGenerator};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithm_creation() {
        let sha256 = HashAlgorithm::Sha256;
        let sha384 = HashAlgorithm::Sha384;
        let sha512 = HashAlgorithm::Sha512;

        assert_eq!(sha256.name(), "sha256");
        assert_eq!(sha384.name(), "sha384");
        assert_eq!(sha512.name(), "sha512");
    }

    #[test]
    fn test_hash_algorithm_prefix() {
        assert_eq!(HashAlgorithm::Sha256.prefix(), "'sha256-");
        assert_eq!(HashAlgorithm::Sha384.prefix(), "'sha384-");
        assert_eq!(HashAlgorithm::Sha512.prefix(), "'sha512-");
    }

    #[test]
    fn test_hash_algorithm_display() {
        assert_eq!(HashAlgorithm::Sha256.to_string(), "sha256");
        assert_eq!(HashAlgorithm::Sha384.to_string(), "sha384");
        assert_eq!(HashAlgorithm::Sha512.to_string(), "sha512");
    }

    #[test]
    fn test_hash_algorithm_try_from_valid() {
        assert_eq!(
            HashAlgorithm::try_from("sha256").unwrap(),
            HashAlgorithm::Sha256
        );
        assert_eq!(
            HashAlgorithm::try_from("sha384").unwrap(),
            HashAlgorithm::Sha384
        );
        assert_eq!(
            HashAlgorithm::try_from("sha512").unwrap(),
            HashAlgorithm::Sha512
        );
    }

    #[test]
    fn test_hash_algorithm_try_from_invalid() {
        let result = HashAlgorithm::try_from("md5");
        assert!(result.is_err());

        if let Err(CspError::InvalidHashAlgorithm(algo)) = result {
            assert_eq!(algo, "md5");
        } else {
            panic!("Expected InvalidHashAlgorithm error");
        }
    }

    #[test]
    fn test_hash_algorithm_equality() {
        let sha256_1 = HashAlgorithm::Sha256;
        let sha256_2 = HashAlgorithm::Sha256;
        let sha384 = HashAlgorithm::Sha384;

        assert_eq!(sha256_1, sha256_2);
        assert_ne!(sha256_1, sha384);
    }

    #[test]
    fn test_hash_algorithm_digest_algorithm() {
        let sha256 = HashAlgorithm::Sha256;
        let digest_algo = sha256.digest_algorithm();

        assert_eq!(digest_algo, &ring::digest::SHA256);
    }

    #[test]
    fn test_hash_generator_generate() {
        let content = b"console.log('Hello, World!');";

        let hash = HashGenerator::generate(HashAlgorithm::Sha256, content);
        assert!(!hash.is_empty());

        let hash2 = HashGenerator::generate(HashAlgorithm::Sha256, content);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_generator_different_algorithms() {
        let content = b"test content";

        let sha256_hash = HashGenerator::generate(HashAlgorithm::Sha256, content);
        let sha384_hash = HashGenerator::generate(HashAlgorithm::Sha384, content);
        let sha512_hash = HashGenerator::generate(HashAlgorithm::Sha512, content);

        assert_ne!(sha256_hash, sha384_hash);
        assert_ne!(sha256_hash, sha512_hash);
        assert_ne!(sha384_hash, sha512_hash);

        assert_ne!(sha256_hash.len(), sha384_hash.len());
        assert_ne!(sha256_hash.len(), sha512_hash.len());
    }

    #[test]
    fn test_hash_generator_empty_content() {
        let empty_content = b"";

        let hash = HashGenerator::generate(HashAlgorithm::Sha256, empty_content);
        assert!(!hash.is_empty());
    }

    #[test]
    fn test_hash_generator_large_content() {
        let large_content = vec![b'a'; 10000];

        let hash = HashGenerator::generate(HashAlgorithm::Sha256, &large_content);
        assert!(!hash.is_empty());
    }
}
