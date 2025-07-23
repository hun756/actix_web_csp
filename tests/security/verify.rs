use actix_web_csp::{
    core::{CspPolicy, CspPolicyBuilder, Source},
    security::{HashAlgorithm, HashGenerator, PolicyVerifier},
};
use std::borrow::Cow;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_verifier_creation() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .build_unchecked();

        let verifier = PolicyVerifier::new(policy);
        assert!(verifier.policy().get_directive("default-src").is_some());
    }

    #[test]
    fn test_verify_uri_allowed() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([
                Source::Self_,
                Source::Host(Cow::Borrowed("example.com")),
                Source::Host(Cow::Borrowed("*.trusted.com")),
            ])
            .build_unchecked();

        let mut verifier = PolicyVerifier::new(policy);

        assert!(verifier
            .verify_uri("https://example.com/script.js", "script-src")
            .unwrap());
        assert!(verifier
            .verify_uri("https://sub.trusted.com/script.js", "script-src")
            .unwrap());
        assert!(!verifier
            .verify_uri("https://evil.com/script.js", "script-src")
            .unwrap());
    }

    #[test]
    fn test_verify_uri_fallback_to_default_src() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_, Source::Host(Cow::Borrowed("example.com"))])
            .build_unchecked();

        let mut verifier = PolicyVerifier::new(policy);

        assert!(verifier
            .verify_uri("https://example.com/script.js", "script-src")
            .unwrap());
        assert!(!verifier
            .verify_uri("https://evil.com/script.js", "script-src")
            .unwrap());
    }

    #[test]
    fn test_verify_uri_none_source() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::None])
            .build_unchecked();

        let mut verifier = PolicyVerifier::new(policy);

        assert!(!verifier
            .verify_uri("https://example.com/script.js", "script-src")
            .unwrap());
        assert!(!verifier
            .verify_uri("https://self.com/script.js", "script-src")
            .unwrap());
    }

    #[test]
    fn test_verify_hash() {
        let script = b"console.log('test');";
        let hash = HashGenerator::generate(HashAlgorithm::Sha256, script);

        let policy = CspPolicyBuilder::new()
            .script_src([Source::Hash {
                algorithm: HashAlgorithm::Sha256,
                value: Cow::Owned(hash),
            }])
            .build_unchecked();

        let verifier = PolicyVerifier::new(policy);

        assert!(verifier.verify_hash(script, "script-src").unwrap());
        assert!(!verifier
            .verify_hash(b"console.log('different');", "script-src")
            .unwrap());
    }

    #[test]
    fn test_verify_nonce() {
        let nonce = "random123";

        let policy = CspPolicyBuilder::new()
            .script_src([Source::Nonce(Cow::Borrowed(nonce))])
            .build_unchecked();

        let verifier = PolicyVerifier::new(policy);

        assert!(verifier.verify_nonce(nonce, "script-src").unwrap());
        assert!(!verifier.verify_nonce("different456", "script-src").unwrap());
    }

    #[test]
    fn test_verify_inline_script() {
        let script = b"console.log('test');";
        let nonce = "random123";

        let policy = CspPolicyBuilder::new()
            .script_src([
                Source::Nonce(Cow::Borrowed(nonce)),
                Source::Hash {
                    algorithm: HashAlgorithm::Sha256,
                    value: Cow::Owned(HashGenerator::generate(HashAlgorithm::Sha256, script)),
                },
            ])
            .build_unchecked();

        let verifier = PolicyVerifier::new(policy);

        assert!(verifier.verify_inline_script(script, Some(nonce)).unwrap());

        assert!(verifier.verify_inline_script(script, None).unwrap());

        assert!(!verifier
            .verify_inline_script(b"console.log('different');", Some(nonce))
            .unwrap());

        assert!(!verifier
            .verify_inline_script(script, Some("wrong456"))
            .unwrap());
    }

    #[test]
    fn test_verify_inline_style() {
        let style = b"body { color: red; }";
        let nonce = "random123";

        let policy = CspPolicyBuilder::new()
            .style_src([Source::Nonce(Cow::Borrowed(nonce)), Source::UnsafeInline])
            .build_unchecked();

        let verifier = PolicyVerifier::new(policy);

        assert!(verifier.verify_inline_style(style, Some(nonce)).unwrap());

        assert!(verifier.verify_inline_style(style, None).unwrap());

        assert!(!verifier
            .verify_inline_style(style, Some("wrong456"))
            .unwrap());
    }

    #[test]
    fn test_blocks_inline_scripts() {
        let policy_blocks = CspPolicyBuilder::new()
            .script_src([Source::Self_])
            .build_unchecked();

        let policy_allows = CspPolicyBuilder::new()
            .script_src([Source::Self_, Source::UnsafeInline])
            .build_unchecked();

        let verifier_blocks = PolicyVerifier::new(policy_blocks);
        let verifier_allows = PolicyVerifier::new(policy_allows);

        assert!(verifier_blocks.blocks_inline_scripts().unwrap());
        assert!(!verifier_allows.blocks_inline_scripts().unwrap());
    }

    #[test]
    fn test_allows_unsafe_eval() {
        let policy_blocks = CspPolicyBuilder::new()
            .script_src([Source::Self_])
            .build_unchecked();

        let policy_allows = CspPolicyBuilder::new()
            .script_src([Source::Self_, Source::UnsafeEval])
            .build_unchecked();

        let verifier_blocks = PolicyVerifier::new(policy_blocks);
        let verifier_allows = PolicyVerifier::new(policy_allows);

        assert!(!verifier_blocks.allows_unsafe_eval());
        assert!(verifier_allows.allows_unsafe_eval());
    }

    #[test]
    fn test_has_report_uri() {
        let policy_with_uri = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .report_uri("https://example.com/csp-report")
            .build_unchecked();

        let policy_without_uri = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .build_unchecked();

        let verifier_with_uri = PolicyVerifier::new(policy_with_uri);
        let verifier_without_uri = PolicyVerifier::new(policy_without_uri);

        assert!(verifier_with_uri.has_report_uri());
        assert!(!verifier_without_uri.has_report_uri());
    }

    #[test]
    fn test_has_report_to() {
        let policy_with_to = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .report_to("csp-endpoint")
            .build_unchecked();

        let policy_without_to = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .build_unchecked();

        let verifier_with_to = PolicyVerifier::new(policy_with_to);
        let verifier_without_to = PolicyVerifier::new(policy_without_to);

        assert!(verifier_with_to.has_report_to());
        assert!(!verifier_without_to.has_report_to());
    }

    #[test]
    fn test_has_directive() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_])
            .build_unchecked();

        let verifier = PolicyVerifier::new(policy);

        assert!(verifier.has_directive("default-src"));
        assert!(verifier.has_directive("script-src"));
        assert!(!verifier.has_directive("style-src"));
    }

    #[test]
    fn test_clear_caches() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .build_unchecked();

        let mut verifier = PolicyVerifier::new(policy);

        let _ = verifier.verify_uri("https://example.com/script.js", "script-src");

        verifier.clear_caches();

        assert!(!verifier
            .verify_uri("https://evil.com/script.js", "script-src")
            .unwrap());
    }
}
