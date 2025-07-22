use actix_web_csp::core::{CspConfig, CspConfigBuilder, CspPolicy};
use actix_web_csp::security::NonceGenerator;
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csp_config_creation() {
        let policy = CspPolicy::new();
        let config = CspConfig::new(policy);

        assert!(config.stats().policy_update_count() == 0);
    }

    #[test]
    fn test_csp_config_builder_default() {
        let config = CspConfigBuilder::new().build();

        assert!(config.generate_nonce().is_none());
    }

    #[test]
    fn test_csp_config_builder_with_policy() {
        let policy = CspPolicy::new();
        let config = CspConfigBuilder::new().policy(policy).build();

        assert!(config.generate_nonce().is_none());
    }

    #[test]
    fn test_csp_config_with_nonce_generator() {
        let config = CspConfigBuilder::new().with_nonce_generator(16).build();

        let nonce = config.generate_nonce();
        assert!(nonce.is_some());
        let nonce_str = nonce.unwrap();
        assert!(nonce_str.len() > 0);
    }

    #[test]
    fn test_csp_config_with_prebuilt_nonce_generator() {
        let generator = Arc::new(NonceGenerator::with_capacity(32, 12));
        let config = CspConfigBuilder::new()
            .with_prebuilt_nonce_generator(generator)
            .build();

        let nonce = config.generate_nonce();
        assert!(nonce.is_some());
        let nonce_str = nonce.unwrap();
        assert!(nonce_str.len() > 0);
    }

    #[test]
    fn test_csp_config_with_cache_settings() {
        let config = CspConfigBuilder::new()
            .with_cache_duration(Duration::from_secs(120))
            .with_cache_size(100)
            .build();

        assert_eq!(config.cache_duration(), Duration::from_secs(120));
    }

    #[test]
    fn test_csp_config_nonce_per_request() {
        let config = CspConfigBuilder::new()
            .with_nonce_generator(16)
            .with_nonce_per_request(true)
            .build();

        let nonce1 = config.get_or_generate_request_nonce("request1");
        let nonce2 = config.get_or_generate_request_nonce("request1");
        let nonce3 = config.get_or_generate_request_nonce("request2");

        assert!(nonce1.is_some());
        assert!(nonce2.is_some());
        assert!(nonce3.is_some());

        assert_eq!(nonce1.as_ref().unwrap(), nonce2.as_ref().unwrap());

        assert_ne!(nonce1.as_ref().unwrap(), nonce3.as_ref().unwrap());
    }

    #[test]
    fn test_csp_config_clear_request_nonces() {
        let config = CspConfigBuilder::new()
            .with_nonce_generator(16)
            .with_nonce_per_request(true)
            .build();

        let _nonce = config.get_or_generate_request_nonce("request1");
        config.clear_request_nonces();

        let new_nonce = config.get_or_generate_request_nonce("request1");
        assert!(new_nonce.is_some());
    }

    #[test]
    fn test_csp_config_policy_update() {
        let policy = CspPolicy::new();
        let config = CspConfig::new(policy);

        config.update_policy(|_policy| {});

        assert!(config.stats().policy_update_count() > 0);
    }

    #[test]
    fn test_csp_config_update_listeners() {
        let policy = CspPolicy::new();
        let config = CspConfig::new(policy);

        let listener_id = config.add_update_listener(|_policy| {});

        assert!(config.remove_update_listener(listener_id));
        assert!(!config.remove_update_listener(listener_id));
    }

    #[test]
    fn test_csp_config_with_default_directives() {
        let policy = CspPolicy::new();
        let config = CspConfig::new(policy).with_default_directives();

        let policy_guard = config.policy();
        let policy_ref = policy_guard.read();
        assert!(policy_ref.get_directive("default-src").is_some());
        assert!(policy_ref.get_directive("object-src").is_some());
    }
}
