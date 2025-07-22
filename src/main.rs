use actix_web_csp::{
    configure_csp, CspConfig, CspConfigBuilder, CspExtensions, CspMiddleware, CspPolicy,
    CspPolicyBuilder, HashAlgorithm, HashGenerator, NonceGenerator, PolicyVerifier, Source,
};

fn main() {
    println!("Actix Web CSP Middleware Example");

    // Create a simple CSP policy
    let policy = CspPolicyBuilder::new()
        .default_src([Source::Self_])
        .script_src([Source::Self_, Source::UnsafeInline])
        .style_src([Source::Self_, Source::UnsafeInline])
        .img_src([Source::Self_, Source::Scheme("data".into())])
        .build_unchecked();

    println!("Created CSP policy");
}
