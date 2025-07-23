use actix_web_csp::{
    core::{CspConfigBuilder, CspPolicy, CspPolicyBuilder, Source},
    middleware::{csp_middleware, CspMiddleware},
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csp_middleware_creation() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_, Source::UnsafeInline])
            .build_unchecked();

        let middleware = csp_middleware(policy);

        assert!(middleware
            .config()
            .policy()
            .read()
            .get_directive("default-src")
            .is_some());
        assert!(middleware
            .config()
            .policy()
            .read()
            .get_directive("script-src")
            .is_some());
    }

    #[test]
    fn test_csp_middleware_with_config() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .build_unchecked();

        let config = CspConfigBuilder::new()
            .policy(policy)
            .with_nonce_generator(16)
            .with_cache_size(100)
            .build();

        let middleware = CspMiddleware::new(config);

        assert!(middleware
            .config()
            .policy()
            .read()
            .get_directive("default-src")
            .is_some());
    }

    #[test]
    fn test_csp_middleware_with_report_only() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .report_only(true)
            .build_unchecked();

        let middleware = csp_middleware(policy);

        assert!(middleware.config().policy().read().is_report_only());
    }

    #[test]
    fn test_csp_middleware_with_report_uri() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .report_uri("https://example.com/csp-report")
            .build_unchecked();

        let middleware = csp_middleware(policy);

        assert_eq!(
            middleware.config().policy().read().report_uri(),
            Some("https://example.com/csp-report")
        );
    }

    #[test]
    fn test_csp_middleware_with_report_to() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .report_to("csp-endpoint")
            .build_unchecked();

        let middleware = csp_middleware(policy);

        assert_eq!(
            middleware.config().policy().read().report_to(),
            Some("csp-endpoint")
        );
    }

    #[test]
    fn test_csp_middleware_with_multiple_directives() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_, Source::UnsafeInline])
            .style_src([Source::Self_, Source::UnsafeInline])
            .img_src([Source::Self_, Source::Host("example.com".into())])
            .connect_src([Source::Self_, Source::Scheme("https".into())])
            .build_unchecked();

        let middleware = csp_middleware(policy);

        let policy_guard = middleware.config().policy();
        let policy = policy_guard.read();
        assert!(policy.get_directive("default-src").is_some());
        assert!(policy.get_directive("script-src").is_some());
        assert!(policy.get_directive("style-src").is_some());
        assert!(policy.get_directive("img-src").is_some());
        assert!(policy.get_directive("connect-src").is_some());
    }

    #[test]
    fn test_csp_middleware_empty_policy() {
        let policy = CspPolicy::new();

        let middleware = csp_middleware(policy);

        assert_eq!(middleware.config().policy().read().directives().count(), 0);
    }

    #[test]
    fn test_csp_middleware_with_nonce_generator() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .build_unchecked();

        let config = CspConfigBuilder::new()
            .policy(policy)
            .with_nonce_generator(16)
            .build();

        let middleware = CspMiddleware::new(config);

        let nonce = middleware.config().generate_nonce();
        assert!(nonce.is_some());
        assert!(!nonce.unwrap().is_empty());
    }
}
