use actix_web_csp::{CspPolicyBuilder, Source};
use std::borrow::Cow;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = CspPolicyBuilder::new()
        .default_src([Source::Self_])
        .script_src([
            Source::Self_,
            Source::Host(Cow::Borrowed("cdn.example.com")),
        ])
        .style_src([Source::Self_])
        .img_src([Source::Self_, Source::Scheme(Cow::Borrowed("https"))])
        .object_src([Source::None])
        .report_uri("/csp-report")
        .build()?;

    let compiled = policy.compile()?;

    println!("Basic CSP walkthrough");
    println!("Header name : {}", compiled.header_name());
    println!("Header value: {}", compiled.header_value().to_str()?);
    println!("Policy hash : {}", compiled.policy_hash());

    Ok(())
}
