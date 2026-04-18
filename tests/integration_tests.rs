use actix_web::{test, web, App, HttpMessage, HttpRequest, HttpResponse, Result};
use actix_web_csp::{
    csp_middleware, csp_middleware_with_nonce, csp_middleware_with_request_nonce,
    csp_with_reporting, CspPolicyBuilder, CspViolationReport, RequestNonce, Source,
};
use std::borrow::Cow;
use std::sync::{Arc, Mutex};

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

async fn test_page_returning_nonce(req: HttpRequest) -> Result<HttpResponse> {
    let nonce = req
        .extensions()
        .get::<RequestNonce>()
        .map(|value| value.to_string())
        .unwrap_or_default();

    Ok(HttpResponse::Ok().body(nonce))
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
    async fn test_runtime_nonce_is_injected_into_header_and_request_extensions() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_])
            .style_src([Source::Self_])
            .build_unchecked();

        let app = test::init_service(
            App::new()
                .wrap(csp_middleware_with_request_nonce(policy, 16))
                .route("/nonce", web::get().to(test_page_returning_nonce)),
        )
        .await;

        let req = test::TestRequest::get().uri("/nonce").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let nonce = test::read_body(resp).await;
        let nonce = String::from_utf8(nonce.to_vec()).unwrap();
        assert!(!nonce.is_empty());

        let req = test::TestRequest::get().uri("/nonce").to_request();
        let resp = test::call_service(&app, req).await;
        let csp_header = resp.headers().get("content-security-policy").unwrap();
        let csp_value = csp_header.to_str().unwrap().to_owned();
        let response_nonce = test::read_body(resp).await;
        let response_nonce = String::from_utf8(response_nonce.to_vec()).unwrap();

        assert!(csp_value.contains(&format!("'nonce-{}'", response_nonce)));
        assert_ne!(nonce, response_nonce);
    }

    #[actix_web::test]
    async fn test_nonce_middleware_exposes_request_nonce_without_cache_mode() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_])
            .build_unchecked();

        let app = test::init_service(
            App::new()
                .wrap(csp_middleware_with_nonce(policy, 16))
                .route("/nonce-once", web::get().to(test_page_returning_nonce)),
        )
        .await;

        let req = test::TestRequest::get().uri("/nonce-once").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let csp_header = resp.headers().get("content-security-policy").unwrap();
        let csp_value = csp_header.to_str().unwrap().to_owned();
        let body = test::read_body(resp).await;
        let nonce = String::from_utf8(body.to_vec()).unwrap();

        assert!(!nonce.is_empty());
        assert!(csp_value.contains(&format!("'nonce-{}'", nonce)));
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

        let reports: Arc<Mutex<Vec<CspViolationReport>>> = Arc::new(Mutex::new(Vec::new()));
        let handler_reports = reports.clone();
        let handler = move |report: CspViolationReport| {
            handler_reports.lock().unwrap().push(report);
        };

        let (middleware, configure_reporting) = csp_with_reporting(policy, handler);

        let app = test::init_service(
            App::new()
                .wrap(middleware)
                .configure(configure_reporting)
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

        let report_body = serde_json::json!({
            "csp-report": {
                "document-uri": "https://example.com",
                "referrer": "",
                "blocked-uri": "https://evil.com/script.js",
                "violated-directive": "script-src-elem",
                "effective-directive": "script-src-elem",
                "original-policy": csp_value,
                "disposition": "enforce"
            }
        });

        let report_req = test::TestRequest::post()
            .uri("/csp-violations")
            .set_json(&report_body)
            .to_request();

        let report_resp = test::call_service(&app, report_req).await;
        assert_eq!(report_resp.status(), StatusCode::OK);

        let stored_reports = reports.lock().unwrap();
        assert_eq!(stored_reports.len(), 1);
        assert_eq!(stored_reports[0].blocked_uri, "https://evil.com/script.js");
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
