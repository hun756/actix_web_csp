# Actix Web CSP

A high-performance Content Security Policy (CSP) middleware for Actix Web applications. Built with security-first principles and optimized for production workloads.

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

### E-commerce Application

Secure configuration for online stores:

```rust
let policy = CspPolicyBuilder::new()
    .default_src([Source::Self_])
    .script_src([
        Source::Self_,
        Source::Host("js.stripe.com".into()),
        Source::Host("checkout.paypal.com".into())
    ])
    .style_src([
        Source::Self_,
        Source::Host("fonts.googleapis.com".into())
    ])
    .img_src([
        Source::Self_,
        Source::Scheme("https".into()),
        Source::Scheme("data".into()) // For product images
    ])
    .connect_src([
        Source::Self_,
        Source::Host("api.stripe.com".into()),
        Source::Host("api.paypal.com".into()),
        Source::Scheme("https".into())
    ])
    .frame_src([
        Source::Host("js.stripe.com".into()),
        Source::Host("checkout.paypal.com".into())
    ])
    .font_src([
        Source::Self_,
        Source::Scheme("data".into()),
        Source::Host("fonts.gstatic.com".into())
    ])
    .report_uri("/security/csp-report")
    .build_unchecked();
```

## Advanced Features

### Nonce-Based CSP

For dynamic content with inline scripts:

```rust
use actix_web_csp::{csp_middleware_with_nonce, RequestNonce};

async fn secure_page(req: HttpRequest) -> Result<HttpResponse> {
    let nonce = req.extensions()
        .get::<RequestNonce>()
        .map(|n| n.to_string())
        .unwrap_or_default();

    let html = format!(r#"
        <!DOCTYPE html>
        <html>
        <head>
            <script nonce="{}">
                console.log('This script is allowed');
            </script>
        </head>
        <body>
            <h1>Secure Page</h1>
        </body>
        </html>
    "#, nonce);

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(html))
}

let policy = CspPolicyBuilder::new()
    .default_src([Source::Self_])
    .script_src([Source::Self_]) // Nonce will be added automatically
    .build_unchecked();

let app = App::new()
    .wrap(csp_middleware_with_nonce(policy, 32)) // 32-byte nonce
    .route("/secure", web::get().to(secure_page));
```

### Violation Reporting

Handle CSP violations in real-time:

```rust
use actix_web_csp::{csp_with_reporting, CspViolationReport};

fn handle_violation(report: CspViolationReport) {
    println!("🚨 CSP Violation Detected:");
    println!("  Document: {}", report.document_uri);
    println!("  Violated: {}", report.violated_directive);
    println!("  Blocked: {}", report.blocked_uri);

    // Log to security monitoring system
    // security_logger::log_csp_violation(&report);
}

let policy = CspPolicyBuilder::new()
    .default_src([Source::Self_])
    .script_src([Source::Self_])
    .report_uri("/csp-report")
    .build_unchecked();

let (middleware, configurator) = csp_with_reporting(policy, handle_violation);

let app = App::new()
    .wrap(middleware)
    .configure(configurator) // Adds /csp-report endpoint
    .route("/", web::get().to(index));
```

### Performance Monitoring

Track CSP performance metrics:

```rust
use actix_web_csp::{CspStats, csp_middleware_with_stats};

let policy = CspPolicyBuilder::new()
    .default_src([Source::Self_])
    .build_unchecked();

let (middleware, stats) = csp_middleware_with_stats(policy);

// Monitor performance
tokio::spawn(async move {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        println!("CSP Stats: {} requests processed", stats.total_requests());
        println!("Average response time: {}μs", stats.avg_response_time_micros());
    }
});

let app = App::new()
    .wrap(middleware)
    .route("/", web::get().to(index));
```

## Security Testing

The library includes a comprehensive security testing tool:

```rust
use actix_web_csp::{CspSecurityTester, CspPolicyBuilder, Source};

let policy = CspPolicyBuilder::new()
    .default_src([Source::Self_])
    .script_src([Source::Self_])
    .build_unchecked();

let mut tester = CspSecurityTester::new(policy);
let results = tester.run_comprehensive_test();

// Results show:
// ✅ XSS Protection - 4/4 XSS payloads blocked
// ✅ Inline Script Protection - Inline scripts blocked
// ✅ External Script Protection - 4/4 malicious domains blocked
// ✅ Overall Assessment: 🟢 Your CSP configuration looks secure!
```

Run the security tester:

```bash
cargo run --example csp_security_tester
```

## Policy Builder API

The `CspPolicyBuilder` provides a fluent interface for policy construction:

```rust
let policy = CspPolicyBuilder::new()
    // Content sources
    .default_src([Source::Self_])
    .script_src([Source::Self_, Source::Host("cdn.example.com".into())])
    .style_src([Source::Self_, Source::UnsafeInline])
    .img_src([Source::Self_, Source::Scheme("data".into())])
    .connect_src([Source::Self_, Source::Scheme("https".into())])
    .font_src([Source::Self_, Source::Host("fonts.gstatic.com".into())])
    .object_src([Source::None])
    .media_src([Source::Self_])
    .frame_src([Source::None])

    // Navigation sources
    .base_uri([Source::Self_])
    .form_action([Source::Self_])

    // Reporting
    .report_uri("/csp-violations")
    .report_to("csp-endpoint")

    // Build policy (validates configuration)
    .build()
    .expect("Invalid CSP policy");
```

### Source Types

```rust
use actix_web_csp::Source;

// Special keywords
Source::Self_           // 'self'
Source::None           // 'none'
Source::UnsafeInline   // 'unsafe-inline'
Source::UnsafeEval     // 'unsafe-eval'
Source::StrictDynamic  // 'strict-dynamic'

// Schemes
Source::Scheme("https".into())  // https:
Source::Scheme("data".into())   // data:

// Hosts
Source::Host("example.com".into())        // example.com
Source::Host("*.example.com".into())      // *.example.com
Source::Host("example.com:443".into())    // example.com:443

// Nonces (auto-generated)
Source::Nonce("random-value".into())      // 'nonce-random-value'

// Hashes (auto-calculated)
Source::Hash {
    algorithm: HashAlgorithm::Sha256,
    value: "base64-hash".into()
}  // 'sha256-base64-hash'
```

## Real-World Examples

### Production Web Application

```rust
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let policy = CspPolicyBuilder::new()
        .default_src([Source::Self_])
        .script_src([
            Source::Self_,
            Source::Host("cdnjs.cloudflare.com".into()),
            Source::Host("cdn.jsdelivr.net".into())
        ])
        .style_src([
            Source::Self_,
            Source::Host("fonts.googleapis.com".into()),
            Source::Host("cdnjs.cloudflare.com".into())
        ])
        .img_src([
            Source::Self_,
            Source::Scheme("https".into()),
            Source::Scheme("data".into())
        ])
        .connect_src([
            Source::Self_,
            Source::Host("api.example.com".into()),
            Source::Scheme("https".into())
        ])
        .font_src([
            Source::Self_,
            Source::Host("fonts.gstatic.com".into()),
            Source::Scheme("data".into())
        ])
        .frame_ancestors([Source::None])
        .report_uri("/security/csp-violations")
        .build_unchecked();

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(csp_middleware(policy.clone()))
            .service(
                web::scope("/api")
                    .route("/users", web::get().to(get_users))
                    .route("/products", web::get().to(get_products))
            )
            .service(Files::new("/", "./static").index_file("index.html"))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
```

### API Server with CORS

```rust
use actix_cors::Cors;

let policy = CspPolicyBuilder::new()
    .default_src([Source::None])
    .connect_src([
        Source::Self_,
        Source::Host("api.frontend.com".into())
    ])
    .report_uri("/api/csp-violations")
    .build_unchecked();

let app = App::new()
    .wrap(
        Cors::default()
            .allowed_origin("https://frontend.com")
            .allowed_methods(vec!["GET", "POST"])
            .max_age(3600)
    )
    .wrap(csp_middleware(policy))
    .route("/api/data", web::get().to(api_handler));
```

## Performance

Benchmark results on a modern system:

- **Overhead**: < 0.1ms per request
- **Memory usage**: ~50KB per 1000 concurrent requests
- **Throughput**: Handles 50,000+ requests/second
- **Nonce generation**: 2M nonces/second

Run benchmarks:

```bash
cargo bench
```

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

---

**Note**: This middleware is production-ready and actively maintained. For security issues, please email ekemenms@gmail.com.
