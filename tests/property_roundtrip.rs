use actix_web_csp::{CspPolicy, CspPolicyBuilder, Source};
use proptest::prelude::*;

fn arb_host() -> impl Strategy<Value = String> {
    "[a-z]{3,8}\\.example\\.com".prop_map(|value| value)
}

fn arb_source() -> impl Strategy<Value = Source> {
    prop_oneof![
        Just(Source::Self_),
        Just(Source::None),
        Just(Source::UnsafeInline),
        Just(Source::UnsafeEval),
        Just(Source::StrictDynamic),
        arb_host().prop_map(|host| Source::Host(host.into())),
        prop_oneof![Just("https"), Just("wss"), Just("data")]
            .prop_map(|scheme| Source::Scheme((*scheme).into())),
        "[A-Za-z0-9_-]{8,16}".prop_map(|nonce| Source::Nonce(nonce.into())),
    ]
}

proptest! {
    #[test]
    fn source_display_round_trips(source in arb_source()) {
        let rendered = source.to_string();
        let parsed = rendered.parse::<Source>().unwrap();
        prop_assert_eq!(parsed, source);
    }

    #[test]
    fn policy_json_round_trips(
        default_src in prop::collection::vec(arb_source(), 1..4),
        script_src in prop::collection::vec(arb_source(), 1..4),
    ) {
        let mut default_directive = Vec::new();
        let mut script_directive = Vec::new();

        for source in default_src {
            if source != Source::None {
                default_directive.push(source);
            }
        }

        for source in script_src {
            if source != Source::None {
                script_directive.push(source);
            }
        }

        prop_assume!(!default_directive.is_empty());
        prop_assume!(!script_directive.is_empty());

        let policy = CspPolicyBuilder::new()
            .default_src(default_directive)
            .script_src(script_directive)
            .build()
            .unwrap();

        let json = policy.to_json_string().unwrap();
        let restored = CspPolicy::from_json_str(&json).unwrap();

        prop_assert_eq!(restored.to_string(), policy.to_string());
    }
}
