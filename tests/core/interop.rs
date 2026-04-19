use actix_web_csp::core::{CspPolicy, CspPolicyBuilder, DirectiveDocument, PolicyDocument, Source};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_document_round_trip() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_, Source::Host("cdn.example.com".into())])
            .report_uri("/csp-report")
            .report_to("security-endpoint")
            .report_only(true)
            .build_unchecked();

        let document = policy.to_document();
        let restored = CspPolicy::from_document(document).unwrap();

        assert_eq!(restored.to_string(), policy.to_string());
        assert!(restored.is_report_only());
    }

    #[test]
    fn test_policy_json_round_trip() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .connect_src([Source::Self_, Source::Scheme("https".into())])
            .build_unchecked();

        let json = policy.to_json_pretty().unwrap();
        let restored = CspPolicy::from_json_str(&json).unwrap();

        assert_eq!(restored.to_string(), policy.to_string());
    }

    #[test]
    fn test_policy_from_json_rejects_invalid_source() {
        let json = r#"{
  "directives": [
    {
      "name": "script-src",
      "sources": ["'sha1024-bad'"]
    }
  ]
}"#;

        let result = CspPolicy::from_json_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_directive_document_supports_fallback_sources() {
        let document = PolicyDocument {
            directives: vec![DirectiveDocument {
                name: "script-src".to_string(),
                sources: vec!["'self'".to_string()],
                fallback_sources: vec!["https:".to_string()],
            }],
            report_only: false,
            report_uri: None,
            report_to: None,
        };

        let policy = CspPolicy::from_document(document).unwrap();
        let directive = policy.get_directive("script-src").unwrap();

        assert_eq!(directive.fallback_sources().unwrap()[0].to_string(), "https:");
    }
}
