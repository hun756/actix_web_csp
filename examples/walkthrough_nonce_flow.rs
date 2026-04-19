use actix_web_csp::{CspConfigBuilder, CspPolicyBuilder, Source};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = CspPolicyBuilder::new()
        .default_src([Source::Self_])
        .script_src([Source::Self_])
        .style_src([Source::Self_])
        .build()?;

    let config = CspConfigBuilder::new()
        .policy(policy.clone())
        .with_nonce_generator(32)
        .with_nonce_per_request(true)
        .build();

    let request_one_nonce = config
        .get_or_generate_request_nonce("request-1")
        .expect("nonce generation should be enabled");
    let repeated_lookup = config
        .get_or_generate_request_nonce("request-1")
        .expect("request nonce should stay stable within the same request id");
    let request_two_nonce = config
        .get_or_generate_request_nonce("request-2")
        .expect("a new request id should receive a new nonce");

    assert_eq!(request_one_nonce, repeated_lookup);
    assert_ne!(request_one_nonce, request_two_nonce);

    let compiled = policy.compile_with_runtime_nonce(&request_one_nonce)?;

    println!("Nonce walkthrough");
    println!("Request 1 nonce: {request_one_nonce}");
    println!("Request 2 nonce: {request_two_nonce}");
    println!(
        "Header with runtime nonce: {}",
        compiled.header_value().to_str()?
    );

    Ok(())
}
