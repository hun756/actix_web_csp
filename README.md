# Actix Web CSP

A comprehensive, high-performance Content Security Policy (CSP) middleware for Actix Web applications. Built with security-first principles and optimized for production workloads.

## Features

- 🛡️ **Complete CSP Implementation** - Full support for all CSP directives
- ⚡ **High Performance** - Optimized for minimal overhead with connection pooling
- 🔒 **Security Focused** - Blocks XSS, injection attacks, and unauthorized resource loading
- 📊 **Built-in Monitoring** - Real-time violation reporting and performance metrics
- 🎯 **Nonce & Hash Support** - Dynamic nonce generation and content hashing
- 🔧 **Easy Integration** - Simple middleware setup with extensive configuration options
- 🧪 **Security Testing** - Comprehensive security validation tools included

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
actix_web_csp = "0.1.0"
actix-web = "4.3"
```

Basic usage:

```rust
use actix_web::{web, App, HttpServer, HttpResponse, Result};
use actix_web_csp::{CspPolicyBuilder, Source, csp_middleware};

async fn index() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body("<h1>Protected by CSP</h1>"))
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
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Configuration Examples

### Strict Security Policy

For applications requiring maximum security:

```rust
let policy = CspPolicyBuilder::new()
    .default_src([Source::None])
    .script_src([Source::Self_])
    .style_src([Source::Self_])
    .img_src([Source::Self_])
    .connect_src([Source::Self_])
    .font_src([Source::Self_])
    .object_src([Source::None])
    .media_src([Source::None])
    .frame_src([Source::None])
    .base_uri([Source::Self_])
    .form_action([Source::Self_])
    .build_unchecked();
```
### Development-Friendly Policy

For development environments:

```rust
let policy = CspPolicyBuilder::new()
    .default_src([Source::Self_])
    .script_src([
        Source::Self_,
        Source::Host("localhost:3000".into()),
        Source::Host("cdn.jsdelivr.net".into())
    ])
    .style_src([
        Source::Self_,
        Source::UnsafeInline, // Only for development!
        Source::Host("fonts.googleapis.com".into())
    ])
    .img_src([
        Source::Self_,
        Source::Scheme("data".into()),
        Source::Scheme("https".into())
    ])
    .connect_src([
        Source::Self_,
        Source::Scheme("https".into()),
        Source::Scheme("ws".into()) // WebSocket support
    ])
    .font_src([
        Source::Self_,
        Source::Scheme("data".into()),
        Source::Host("fonts.gstatic.com".into())
    ])
    .report_uri("/csp-violations")
    .build_unchecked();
```
