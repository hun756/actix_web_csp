use actix_web_csp::core::Source;
use actix_web_csp::security::HashAlgorithm;
use std::borrow::Cow;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_creation() {
        let source_none = Source::None;
        let source_self = Source::Self_;
        let source_unsafe_inline = Source::UnsafeInline;
        let source_unsafe_eval = Source::UnsafeEval;
        
        assert!(source_none.is_none());
        assert!(source_self.is_self());
        assert!(source_unsafe_inline.is_unsafe_inline());
        assert!(source_unsafe_eval.is_unsafe_eval());
    }

    #[test]
    fn test_source_host() {
        let host_source = Source::Host(Cow::Borrowed("example.com"));
        assert_eq!(host_source.host(), Some("example.com"));
        assert!(!host_source.is_none());
        assert!(!host_source.is_self());
    }

    #[test]
    fn test_source_scheme() {
        let scheme_source = Source::Scheme(Cow::Borrowed("https"));
        assert_eq!(scheme_source.scheme(), Some("https"));
        assert_eq!(scheme_source.to_string(), "https:");
    }

    #[test]
    fn test_source_nonce() {
        let nonce_value = "abc123";
        let nonce_source = Source::Nonce(Cow::Borrowed(nonce_value));
        
        assert!(nonce_source.contains_nonce());
        assert_eq!(nonce_source.nonce(), Some(nonce_value));
        assert!(nonce_source.to_string().contains(nonce_value));
    }

    #[test]
    fn test_source_hash() {
        let hash_value = "sha256-abc123";
        let hash_source = Source::Hash {
            algorithm: HashAlgorithm::Sha256,
            value: Cow::Borrowed(hash_value),
        };
        
        assert!(hash_source.contains_hash());
        assert_eq!(hash_source.hash_value(), Some((hash_value, HashAlgorithm::Sha256)));
    }

    #[test]
    fn test_source_display() {
        assert_eq!(Source::None.to_string(), "'none'");
        assert_eq!(Source::Self_.to_string(), "'self'");
        assert_eq!(Source::UnsafeInline.to_string(), "'unsafe-inline'");
        assert_eq!(Source::UnsafeEval.to_string(), "'unsafe-eval'");
        assert_eq!(Source::StrictDynamic.to_string(), "'strict-dynamic'");
        
        let host_source = Source::Host(Cow::Borrowed("example.com"));
        assert_eq!(host_source.to_string(), "example.com");
    }

    #[test]
    fn test_source_estimated_size() {
        let none_source = Source::None;
        assert!(none_source.estimated_size() > 0);
        
        let host_source = Source::Host(Cow::Borrowed("example.com"));
        assert_eq!(host_source.estimated_size(), "example.com".len());
        
        let nonce_source = Source::Nonce(Cow::Borrowed("abc123"));
        assert!(nonce_source.estimated_size() > "abc123".len());
    }

    #[test]
    fn test_source_equality() {
        let source1 = Source::Self_;
        let source2 = Source::Self_;
        let source3 = Source::None;
        
        assert_eq!(source1, source2);
        assert_ne!(source1, source3);
        
        let host1 = Source::Host(Cow::Borrowed("example.com"));
        let host2 = Source::Host(Cow::Borrowed("example.com"));
        let host3 = Source::Host(Cow::Borrowed("other.com"));
        
        assert_eq!(host1, host2);
        assert_ne!(host1, host3);
    }

    #[test]
    fn test_source_as_static_str() {
        assert_eq!(Source::None.as_static_str(), Some("'none'"));
        assert_eq!(Source::Self_.as_static_str(), Some("'self'"));
        assert_eq!(Source::UnsafeInline.as_static_str(), Some("'unsafe-inline'"));
        
        let host_source = Source::Host(Cow::Borrowed("example.com"));
        assert_eq!(host_source.as_static_str(), None);
    }
}
