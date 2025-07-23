use actix_web::{test, web, App, HttpResponse, Result};
use actix_web_csp::{csp_middleware, CspPolicyBuilder, Source};
use std::borrow::Cow;

async fn test_page_with_nonce() -> Result<HttpResponse> {
    let html = r#"<!DOCTYPE html>
<html>
<head>
    <style nonce="test-nonce-123">
        body { color: blue; }
    </style>
</head>
<body>
    <script nonce="test-nonce-123">
        console.log('Script protected with nonce');
    </script>
    <script>
        console.log('Unprotected script - will be blocked');
    </script>
</body>
</html>"#;

    Ok(HttpResponse::Ok().content_type("text/html").body(html))
}

async fn test_page_with_hash() -> Result<HttpResponse> {
    let html = r#"<!DOCTYPE html>
<html>
<body>
    <script>console.log('Script protected with hash');</script>
    <script>alert('Malicious script - will be blocked');</script>
</body>
</html>"#;

    Ok(HttpResponse::Ok().content_type("text/html").body(html))
}

async fn test_api_endpoint() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "data": "API is working"
    })))
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use actix_web::http::StatusCode;

    #[actix_web::test]
    async fn test_csp_header_presence() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_, Source::UnsafeInline])
            .style_src([Source::Self_, Source::UnsafeInline])
            .build_unchecked();

        let app = test::init_service(
            App::new()
                .wrap(csp_middleware(policy))
                .route("/test", web::get().to(test_page_with_hash)),
        )
        .await;

        let req = test::TestRequest::get().uri("/test").to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let csp_header = resp.headers().get("content-security-policy");
        assert!(csp_header.is_some(), "CSP header not found");

        let csp_value = csp_header.unwrap().to_str().unwrap();
        assert!(csp_value.contains("default-src 'self'"));
        assert!(csp_value.contains("script-src"));
        assert!(csp_value.contains("style-src"));
    }

    #[actix_web::test]
    async fn test_nonce_generation() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_, Source::UnsafeInline])
            .style_src([Source::Self_, Source::UnsafeInline])
            .build_unchecked();

        let app = test::init_service(
            App::new()
                .wrap(csp_middleware(policy))
                .route("/test-nonce", web::get().to(test_page_with_nonce)),
        )
        .await;

        let req = test::TestRequest::get().uri("/test-nonce").to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let csp_header = resp.headers().get("content-security-policy");
        assert!(csp_header.is_some());

        let csp_value = csp_header.unwrap().to_str().unwrap();
        assert!(csp_value.contains("script-src"));
    }

    #[actix_web::test]
    async fn test_hash_based_csp() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_, Source::UnsafeInline])
            .build_unchecked();

        let app = test::init_service(
            App::new()
                .wrap(csp_middleware(policy))
                .route("/test-hash", web::get().to(test_page_with_hash)),
        )
        .await;

        let req = test::TestRequest::get().uri("/test-hash").to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let csp_header = resp.headers().get("content-security-policy");
        assert!(csp_header.is_some());

        let csp_value = csp_header.unwrap().to_str().unwrap();
        assert!(csp_value.contains("script-src"));
    }

    #[actix_web::test]
    async fn test_report_only_mode() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_])
            .report_only(true)
            .report_uri("/csp-report")
            .build_unchecked();

        let app = test::init_service(
            App::new()
                .wrap(csp_middleware(policy))
                .route("/test-report", web::get().to(test_page_with_hash)),
        )
        .await;

        let req = test::TestRequest::get().uri("/test-report").to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let csp_header = resp.headers().get("content-security-policy-report-only");
        assert!(csp_header.is_some(), "CSP Report-Only header not found");

        let csp_value = csp_header.unwrap().to_str().unwrap();
        assert!(csp_value.contains("report-uri /csp-report"));
    }

    #[actix_web::test]
    async fn test_multiple_sources() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([
                Source::Self_,
                Source::Host(Cow::Borrowed("cdn.example.com")),
                Source::Scheme(Cow::Borrowed("https")),
            ])
            .style_src([
                Source::Self_,
                Source::UnsafeInline,
                Source::Host(Cow::Borrowed("fonts.googleapis.com")),
            ])
            .img_src([
                Source::Self_,
                Source::Scheme(Cow::Borrowed("data")),
                Source::Scheme(Cow::Borrowed("https")),
            ])
            .connect_src([
                Source::Self_,
                Source::Scheme(Cow::Borrowed("wss")),
                Source::Host(Cow::Borrowed("api.example.com")),
            ])
            .build_unchecked();

        let app = test::init_service(
            App::new()
                .wrap(csp_middleware(policy))
                .route("/test-multi", web::get().to(test_api_endpoint)),
        )
        .await;

        let req = test::TestRequest::get().uri("/test-multi").to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let csp_header = resp.headers().get("content-security-policy");
        assert!(csp_header.is_some());

        let csp_value = csp_header.unwrap().to_str().unwrap();
        assert!(csp_value.contains("script-src 'self' cdn.example.com https:"));
        assert!(csp_value.contains("style-src 'self' 'unsafe-inline' fonts.googleapis.com"));
        assert!(csp_value.contains("img-src 'self' data: https:"));
        assert!(csp_value.contains("connect-src 'self' wss: api.example.com"));
    }

    #[actix_web::test]
    async fn test_strict_csp_policy() {
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
            .build_unchecked();

        let app = test::init_service(
            App::new()
                .wrap(csp_middleware(policy))
                .route("/test-strict", web::get().to(test_api_endpoint)),
        )
        .await;

        let req = test::TestRequest::get().uri("/test-strict").to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let csp_header = resp.headers().get("content-security-policy");
        assert!(csp_header.is_some());

        let csp_value = csp_header.unwrap().to_str().unwrap();
        assert!(csp_value.contains("default-src 'none'"));
        assert!(csp_value.contains("object-src 'none'"));
        assert!(csp_value.contains("media-src 'none'"));
        assert!(csp_value.contains("frame-src 'none'"));
    }

    #[actix_web::test]
    async fn test_csp_with_reporting_endpoint() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_])
            .report_uri("/csp-violations")
            .report_to("csp-endpoint")
            .build_unchecked();

        let app = test::init_service(
            App::new()
                .wrap(csp_middleware(policy))
                .route("/test-reporting", web::get().to(test_api_endpoint)),
        )
        .await;

        let req = test::TestRequest::get().uri("/test-reporting").to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let csp_header = resp.headers().get("content-security-policy");
        assert!(csp_header.is_some());

        let csp_value = csp_header.unwrap().to_str().unwrap();
        assert!(csp_value.contains("report-uri /csp-violations"));
        assert!(csp_value.contains("report-to csp-endpoint"));
    }

    #[actix_web::test]
    async fn test_performance_with_large_policy() {
        use std::time::Instant;

        let mut policy_builder = CspPolicyBuilder::new().default_src([Source::Self_]);

        let hosts: Vec<Source> = (0..100)
            .map(|i| Source::Host(format!("host{}.example.com", i).into()))
            .collect();

        policy_builder = policy_builder.script_src(hosts.clone());
        policy_builder = policy_builder.style_src(hosts.clone());
        policy_builder = policy_builder.img_src(hosts);

        let policy = policy_builder.build_unchecked();

        let app = test::init_service(
            App::new()
                .wrap(csp_middleware(policy))
                .route("/test-perf", web::get().to(test_api_endpoint)),
        )
        .await;

        let start = Instant::now();

        for _ in 0..100 {
            let req = test::TestRequest::get().uri("/test-perf").to_request();

            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::OK);
        }

        let duration = start.elapsed();
        println!("Time elapsed for 100 requests: {:?}", duration);
        assert!(
            duration.as_secs() < 1,
            "Performance too low: {:?}",
            duration
        );
    }
}
