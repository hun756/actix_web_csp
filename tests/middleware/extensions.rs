use actix_web_csp::{security::HashAlgorithm};

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web_csp::security::hash::HashGenerator;

    #[test]
    fn test_hash_generation_for_csp() {
        let content = b"console.log('Hello, World!');";
        let hash = HashGenerator::generate(HashAlgorithm::Sha256, content);

        assert!(!hash.is_empty());

        let hash2 = HashGenerator::generate(HashAlgorithm::Sha256, content);
        assert_eq!(hash, hash2);

        let different_content = b"alert('Hello, World!');";
        let hash3 = HashGenerator::generate(HashAlgorithm::Sha256, different_content);
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_hash_source_generation() {
        let content = b"console.log('Hello, World!');";
        let source = HashGenerator::generate_source(HashAlgorithm::Sha256, content);

        assert!(source.contains_hash());

        let source_str = source.to_string();
        assert!(source_str.starts_with("'sha256-"));
        assert!(source_str.ends_with("'"));
    }

    #[test]
    fn test_hash_generation_different_algorithms() {
        let content = b"test content";
        let sha256_hash = HashGenerator::generate(HashAlgorithm::Sha256, content);
        let sha384_hash = HashGenerator::generate(HashAlgorithm::Sha384, content);
        let sha512_hash = HashGenerator::generate(HashAlgorithm::Sha512, content);

        assert_ne!(sha256_hash, sha384_hash);
        assert_ne!(sha256_hash, sha512_hash);
        assert_ne!(sha384_hash, sha512_hash);
    }

    #[test]
    fn test_hash_generation_empty_content() {
        let empty_content = b"";
        let hash = HashGenerator::generate(HashAlgorithm::Sha256, empty_content);

        assert!(!hash.is_empty());
    }

    #[test]
    fn test_hash_generation_large_content() {
        let large_content = vec![b'a'; 10000];
        let hash = HashGenerator::generate(HashAlgorithm::Sha256, &large_content);

        assert!(!hash.is_empty());
    }
}
