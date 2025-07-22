use actix_web_csp::security::{NonceGenerator, RequestNonce};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generator_creation() {
        let generator = NonceGenerator::new(16);

        let nonce = generator.generate();
        assert!(!nonce.is_empty());
    }

    #[test]
    fn test_nonce_generator_with_capacity() {
        let generator = NonceGenerator::with_capacity(32, 12);

        let nonce = generator.generate();
        assert!(!nonce.is_empty());
    }

    #[test]
    fn test_nonce_generation_uniqueness() {
        let generator = NonceGenerator::new(16);

        let nonce1 = generator.generate();
        let nonce2 = generator.generate();
        let nonce3 = generator.generate();

        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce1, nonce3);
        assert_ne!(nonce2, nonce3);
    }

    #[test]
    fn test_nonce_generation_length() {
        let generator = NonceGenerator::new(16);

        let nonce = generator.generate();

        assert!(nonce.len() >= 20 && nonce.len() <= 24);
    }

    #[test]
    fn test_nonce_generator_different_lengths() {
        let gen_8 = NonceGenerator::new(8);
        let gen_16 = NonceGenerator::new(16);
        let gen_32 = NonceGenerator::new(32);

        let nonce_8 = gen_8.generate();
        let nonce_16 = gen_16.generate();
        let nonce_32 = gen_32.generate();

        assert!(nonce_8.len() < nonce_16.len());
        assert!(nonce_16.len() < nonce_32.len());
    }

    #[test]
    fn test_nonce_generator_clone() {
        let generator1 = NonceGenerator::new(16);
        let generator2 = generator1.clone();

        let nonce1 = generator1.generate();
        let nonce2 = generator2.generate();

        assert!(!nonce1.is_empty());
        assert!(!nonce2.is_empty());
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_nonce_generator_multiple_generations() {
        let generator = NonceGenerator::new(16);
        let mut nonces = Vec::new();

        for _ in 0..100 {
            nonces.push(generator.generate());
        }

        for i in 0..nonces.len() {
            for j in (i + 1)..nonces.len() {
                assert_ne!(nonces[i], nonces[j], "Nonce {} and {} are the same", i, j);
            }
        }
    }

    #[test]
    fn test_nonce_generator_length_setting() {
        let generator = NonceGenerator::new(16);

        assert_eq!(generator.length(), 16);

        generator.set_length(32);
        assert_eq!(generator.length(), 32);
    }

    #[test]
    fn test_request_nonce_creation() {
        let nonce_value = "test-nonce-123";
        let request_nonce = RequestNonce(nonce_value.to_string());

        assert_eq!(*request_nonce, nonce_value);
    }

    #[test]
    fn test_request_nonce_clone() {
        let nonce_value = "test-nonce-456";
        let request_nonce1 = RequestNonce(nonce_value.to_string());
        let request_nonce2 = request_nonce1.clone();

        assert_eq!(*request_nonce1, *request_nonce2);
    }

    #[test]
    fn test_request_nonce_deref() {
        let nonce_value = "test-nonce-789";
        let request_nonce = RequestNonce(nonce_value.to_string());

        assert_eq!(request_nonce.len(), nonce_value.len());
        assert!(request_nonce.contains("nonce"));
    }
}
