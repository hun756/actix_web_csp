# Actix Web CSP

`actix-web-csp` is a Content Security Policy middleware for Actix Web.

The goal of this crate is pretty simple: help you define CSP rules in Rust, attach the right header to each response, and keep policy-related code out of stringly-typed ad hoc helpers.

It includes:

- a builder API for CSP policies
- middleware for normal and report-only headers
- nonce generation support
- CSP violation report handling
- verification and hashing helpers for tests or internal tooling
- lightweight stats and performance counters through `CspConfig`

If you want startup-time validation, prefer `build()`. The examples below mostly use `build_unchecked()` to keep the snippets short.

## Support Policy

- Current MSRV: Rust `1.85`
- Primary CI coverage: default features, all features, no default features, and `extended-validation`
- Security and dependency hygiene checks run in CI as part of the release workflow

## Installation

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
actix-web = "4.3"
actix-web-csp = "0.1.0"
```

## Quick Start

This is the smallest useful setup: create a policy and wrap your app with the middleware.

```rust
use actix_web::{web, App, HttpResponse, HttpServer};
use actix_web_csp::{csp_middleware, CspPolicyBuilder, Source};

async fn index() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html")
        .body("<h1>Hello from Actix</h1>")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let policy = CspPolicyBuilder::new()
        .default_src([Source::Self_])
        .script_src([Source::Self_])
        .style_src([Source::Self_])
        .img_src([Source::Self_, Source::Scheme("https".into())])
        .build_unchecked();

    HttpServer::new(move || {
        App::new()
            .wrap(csp_middleware(policy.clone()))
            .route("/", web::get().to(index))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

## Common Policy Shapes

### A stricter default

```rust
use actix_web_csp::{CspPolicyBuilder, Source};

let policy = CspPolicyBuilder::new()
    .default_src([Source::None])
    .script_src([Source::Self_])
    .style_src([Source::Self_])
    .img_src([Source::Self_])
    .connect_src([Source::Self_])
    .font_src([Source::Self_])
    .object_src([Source::None])
    .frame_src([Source::None])
    .base_uri([Source::Self_])
    .form_action([Source::Self_])
    .build()?;
```

### A more practical development setup

```rust
use actix_web_csp::{CspPolicyBuilder, Source};

let policy = CspPolicyBuilder::new()
    .default_src([Source::Self_])
    .script_src([
        Source::Self_,
        Source::Host("localhost:3000".into()),
        Source::Host("cdn.jsdelivr.net".into()),
    ])
    .style_src([
        Source::Self_,
        Source::UnsafeInline,
        Source::Host("fonts.googleapis.com".into()),
    ])
    .img_src([
        Source::Self_,
        Source::Scheme("data".into()),
        Source::Scheme("https".into()),
    ])
    .connect_src([
        Source::Self_,
        Source::Scheme("https".into()),
        Source::Scheme("ws".into()),
    ])
    .font_src([
        Source::Self_,
        Source::Scheme("data".into()),
        Source::Host("fonts.gstatic.com".into()),
    ])
    .build()?;
```

## Working With Nonces

If you need inline scripts or styles, build the middleware from `CspConfigBuilder` so nonce generation is enabled explicitly.

```rust
use actix_web::{web, App, HttpMessage, HttpRequest, HttpResponse};
use actix_web_csp::{
    CspConfigBuilder, CspMiddleware, CspPolicyBuilder, RequestNonce, Source,
};

async fn page(req: HttpRequest) -> HttpResponse {
    let nonce = req
        .extensions()
        .get::<RequestNonce>()
        .map(|value| value.to_string())
        .unwrap_or_default();

    let html = format!(
        r#"
        <!doctype html>
        <html>
            <head>
                <script nonce="{nonce}">
                    console.log("inline script allowed");
                </script>
            </head>
            <body>
                <h1>Nonce example</h1>
            </body>
        </html>
        "#
    );

    HttpResponse::Ok()
        .content_type("text/html")
        .body(html)
}

let policy = CspPolicyBuilder::new()
    .default_src([Source::Self_])
    .script_src([Source::Self_])
    .build_unchecked();

let csp = CspMiddleware::new(
    CspConfigBuilder::new()
        .policy(policy)
        .with_nonce_generator(32)
        .with_nonce_per_request(true)
        .build(),
);

let app = App::new()
    .wrap(csp)
    .route("/", web::get().to(page));
```

## CSP Reporting

The crate can also register a reporting endpoint and pass parsed violation reports to your handler.

```rust
use actix_web::{web, App, HttpResponse};
use actix_web_csp::{csp_with_reporting, CspPolicyBuilder, CspViolationReport, Source};

async fn index() -> HttpResponse {
    HttpResponse::Ok().finish()
}

fn handle_violation(report: CspViolationReport) {
    println!(
        "blocked={} directive={}",
        report.blocked_uri, report.violated_directive
    );
}

let policy = CspPolicyBuilder::new()
    .default_src([Source::Self_])
    .script_src([Source::Self_])
    .report_uri("/csp-report")
    .build_unchecked();

let (middleware, configure_reporting) = csp_with_reporting(policy, handle_violation);

let app = App::new()
    .wrap(middleware)
    .configure(configure_reporting)
    .route("/", web::get().to(index));
```

At the moment, the built-in reporting configurator mounts a `POST /csp-report` endpoint.

## Builder API

The policy builder covers the directives you usually need in an Actix app:

```rust
use actix_web_csp::{CspPolicyBuilder, Source};

let policy = CspPolicyBuilder::new()
    .default_src([Source::Self_])
    .script_src([Source::Self_, Source::Host("cdn.example.com".into())])
    .style_src([Source::Self_])
    .img_src([Source::Self_, Source::Scheme("data".into())])
    .connect_src([Source::Self_, Source::Scheme("https".into())])
    .font_src([Source::Self_])
    .frame_ancestors([Source::None])
    .base_uri([Source::Self_])
    .form_action([Source::Self_])
    .report_uri("/csp-report")
    .build()?;
```

Source values are typed as well:

```rust
use actix_web_csp::{HashAlgorithm, Source};

Source::Self_;
Source::None;
Source::UnsafeInline;
Source::UnsafeEval;
Source::StrictDynamic;
Source::Scheme("https".into());
Source::Host("cdn.example.com".into());
Source::Nonce("random-value".into());
Source::Hash {
    algorithm: HashAlgorithm::Sha256,
    value: "base64-hash".into(),
};
```

## Helpers

Besides middleware, the crate also exposes a few utilities that are handy in tests, validation code, or internal tooling:

- `PolicyVerifier` for checking whether a URI, hash, or nonce would be allowed by a policy
- `HashGenerator` for generating CSP hash values
- `NonceGenerator` for manual nonce generation
- `CspConfig` and `CspStats` if you want direct access to counters and configuration state

## Examples In This Repo

There are two good entry points if you want a fuller example than the snippets above:

- `cargo run --example real_world_test_fixed`
- `cargo run --example csp_security_tester`

## Feature Flags

- `stats`: enables runtime statistics collection
- `reporting`: enables violation report parsing and reporting middleware helpers
- `verify`: enables `PolicyVerifier`
- `extended-validation`: enables stricter semantic validation for sources and reporting directives

Default features: `stats`, `reporting`, `verify`

## Development

Run the test suite:

```bash
cargo test
```

Run the stricter validation matrix:

```bash
cargo test --all-features
cargo test --features extended-validation
cargo check --no-default-features
```

Run the release-quality checks:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

Run benchmarks:

```bash
cargo bench
```

## Contributing

Issues and pull requests are welcome. If you plan to make a larger change, opening an issue first is helpful.

For dependency policy and vulnerability handling, see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
