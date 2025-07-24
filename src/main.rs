use actix_web_csp::{
    CspPolicyBuilder, Source
};
use std::borrow::Cow;

fn main() {
    println!("Actix Web CSP Middleware Example");

    // Create a simple CSP policy
    let policy = CspPolicyBuilder::new()
        .default_src([Source::Self_])
        .script_src([Source::Self_, Source::UnsafeInline])
        .style_src([Source::Self_, Source::UnsafeInline])
        .img_src([Source::Self_, Source::Scheme(Cow::Borrowed("data"))])
        .build_unchecked();

    println!("Created CSP policy");
    println!("Run examples with: cargo run --example real_world_test_fixed");
}