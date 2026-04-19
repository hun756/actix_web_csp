use actix_web::http::header::HeaderName;
use actix_web_csp::core::{CspPolicy, CspPolicyBuilder, Source};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csp_policy_creation() {
        let policy = CspPolicy::new();

        assert!(!policy.is_report_only());
        assert!(policy.report_uri().is_none());
        assert!(policy.report_to().is_none());
        assert_eq!(policy.directives().count(), 0);
    }

    #[test]
    fn test_csp_policy_default() {
        let policy = CspPolicy::default();

        assert!(!policy.is_report_only());
        assert!(policy.report_uri().is_none());
        assert!(policy.report_to().is_none());
    }

    #[test]
    fn test_csp_policy_report_only() {
        let mut policy = CspPolicy::new();

        policy.set_report_only(true);
        assert!(policy.is_report_only());

        policy.set_report_only(false);
        assert!(!policy.is_report_only());
    }

    #[test]
    fn test_csp_policy_report_uri() {
        let mut policy = CspPolicy::new();

        policy.set_report_uri("https://example.com/csp-report");
        assert_eq!(policy.report_uri(), Some("https://example.com/csp-report"));
    }

    #[test]
    fn test_csp_policy_report_to() {
        let mut policy = CspPolicy::new();

        policy.set_report_to("csp-endpoint");
        assert_eq!(policy.report_to(), Some("csp-endpoint"));
    }

    #[test]
    fn test_csp_policy_header_name() {
        let mut policy = CspPolicy::new();

        assert_eq!(
            policy.header_name(),
            HeaderName::from_static("content-security-policy")
        );

        policy.set_report_only(true);
        assert_eq!(
            policy.header_name(),
            HeaderName::from_static("content-security-policy-report-only")
        );
    }

    #[test]
    fn test_csp_policy_validate_empty() {
        let policy = CspPolicy::new();

        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_csp_policy_hash() {
        let mut policy1 = CspPolicy::new();
        let mut policy2 = CspPolicy::new();

        assert_eq!(policy1.hash(), policy2.hash());

        policy2.set_report_only(true);
        assert_ne!(policy1.hash(), policy2.hash());
    }

    #[test]
    fn test_csp_policy_builder_creation() {
        let builder = CspPolicyBuilder::new();
        let policy = builder.build_unchecked();

        assert!(!policy.is_report_only());
        assert_eq!(policy.directives().count(), 0);
    }

    #[test]
    fn test_csp_policy_builder_default_src() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .build_unchecked();

        assert!(policy.get_directive("default-src").is_some());
    }

    #[test]
    fn test_csp_policy_builder_script_src() {
        let policy = CspPolicyBuilder::new()
            .script_src([Source::Self_, Source::UnsafeInline])
            .build_unchecked();

        assert!(policy.get_directive("script-src").is_some());
    }

    #[test]
    fn test_csp_policy_builder_style_src() {
        let policy = CspPolicyBuilder::new()
            .style_src([Source::Self_, Source::UnsafeInline])
            .build_unchecked();

        assert!(policy.get_directive("style-src").is_some());
    }

    #[test]
    fn test_csp_policy_builder_multiple_directives() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_])
            .style_src([Source::Self_])
            .img_src([Source::Self_])
            .build_unchecked();

        assert!(policy.get_directive("default-src").is_some());
        assert!(policy.get_directive("script-src").is_some());
        assert!(policy.get_directive("style-src").is_some());
        assert!(policy.get_directive("img-src").is_some());
        assert_eq!(policy.directives().count(), 4);
    }

    #[test]
    fn test_csp_policy_builder_report_settings() {
        let policy = CspPolicyBuilder::new()
            .report_uri("https://example.com/csp-report")
            .report_to("csp-endpoint")
            .report_only(true)
            .build_unchecked();

        assert!(policy.is_report_only());
        assert_eq!(policy.report_uri(), Some("https://example.com/csp-report"));
        assert_eq!(policy.report_to(), Some("csp-endpoint"));
    }

    #[test]
    fn test_csp_policy_builder_special_directives() {
        let policy = CspPolicyBuilder::new()
            .upgrade_insecure_requests()
            .block_all_mixed_content()
            .build_unchecked();

        assert!(policy.get_directive("upgrade-insecure-requests").is_some());
        assert!(policy.get_directive("block-all-mixed-content").is_some());
    }

    #[test]
    fn test_csp_policy_builder_all_source_directives() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_])
            .style_src([Source::Self_])
            .img_src([Source::Self_])
            .connect_src([Source::Self_])
            .font_src([Source::Self_])
            .object_src([Source::None])
            .media_src([Source::Self_])
            .frame_src([Source::Self_])
            .worker_src([Source::Self_])
            .manifest_src([Source::Self_])
            .child_src([Source::Self_])
            .frame_ancestors([Source::Self_])
            .base_uri([Source::Self_])
            .form_action([Source::Self_])
            .build_unchecked();

        assert_eq!(policy.directives().count(), 15);
    }

    #[test]
    fn test_csp_policy_builder_build_with_validation() {
        let result = CspPolicyBuilder::new().default_src([Source::Self_]).build();

        assert!(result.is_ok());
    }

    #[test]
    fn test_csp_policy_builder_build_unchecked() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .build_unchecked();

        assert!(policy.get_directive("default-src").is_some());
    }

    #[test]
    fn test_csp_policy_contains_nonce() {
        use std::borrow::Cow;

        let policy_without_nonce = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .build_unchecked();

        let policy_with_nonce = CspPolicyBuilder::new()
            .script_src([Source::Nonce(Cow::Borrowed("test123"))])
            .build_unchecked();

        assert!(!policy_without_nonce.contains_nonce());
        assert!(policy_with_nonce.contains_nonce());
    }

    #[test]
    fn test_csp_policy_contains_hash() {
        use actix_web_csp::security::HashAlgorithm;
        use std::borrow::Cow;

        let policy_without_hash = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .build_unchecked();

        let policy_with_hash = CspPolicyBuilder::new()
            .script_src([Source::Hash {
                algorithm: HashAlgorithm::Sha256,
                value: Cow::Borrowed("abc123"),
            }])
            .build_unchecked();

        assert!(!policy_without_hash.contains_hash());
        assert!(policy_with_hash.contains_hash());
    }

    #[test]
    fn test_csp_policy_header_value_generation() {
        let mut policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_, Source::UnsafeInline])
            .build_unchecked();

        let header_value = policy.header_value();
        assert!(header_value.is_ok());

        let header = header_value.unwrap();
        let header_str = header.to_str().unwrap();
        assert!(header_str.contains("default-src 'self'"));
        assert!(header_str.contains("script-src 'self' 'unsafe-inline'"));
    }

    #[test]
    fn test_csp_policy_compile_creates_snapshot() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .report_uri("/csp-report")
            .build_unchecked();

        let compiled = policy.compile().unwrap();
        assert_eq!(
            compiled.header_name(),
            &HeaderName::from_static("content-security-policy")
        );
        assert!(compiled
            .header_value()
            .to_str()
            .unwrap()
            .contains("report-uri /csp-report"));
    }

    #[test]
    fn test_csp_policy_round_trips_through_string_parser() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_, Source::Host("cdn.example.com".into())])
            .report_uri("/csp-report")
            .report_to("csp-endpoint")
            .build_unchecked();

        let serialized = policy.to_string();
        let reparsed = serialized.parse::<CspPolicy>().unwrap();

        assert_eq!(reparsed.to_string(), serialized);
        assert!(reparsed.get_directive("script-src").is_some());
        assert_eq!(reparsed.report_uri(), Some("/csp-report"));
        assert_eq!(reparsed.report_to(), Some("csp-endpoint"));
    }

    #[cfg(feature = "extended-validation")]
    #[test]
    fn test_extended_validation_rejects_host_with_scheme() {
        let result = CspPolicyBuilder::new()
            .script_src([Source::Host("https://cdn.example.com".into())])
            .build();

        assert!(result.is_err());
    }

    #[cfg(feature = "extended-validation")]
    #[test]
    fn test_extended_validation_rejects_invalid_scheme() {
        let result = CspPolicyBuilder::new()
            .connect_src([Source::Scheme("https:".into())])
            .build();

        assert!(result.is_err());
    }

    #[cfg(feature = "extended-validation")]
    #[test]
    fn test_extended_validation_rejects_invalid_nonce() {
        let result = CspPolicyBuilder::new()
            .script_src([Source::Nonce("bad nonce".into())])
            .build();

        assert!(result.is_err());
    }

    #[cfg(feature = "extended-validation")]
    #[test]
    fn test_extended_validation_accepts_relative_report_uri() {
        let result = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .report_uri("/csp-report")
            .build();

        assert!(result.is_ok());
    }

    #[cfg(feature = "extended-validation")]
    #[test]
    fn test_extended_validation_rejects_invalid_report_to() {
        let result = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .report_to("bad endpoint")
            .build();

        assert!(result.is_err());
    }
}
