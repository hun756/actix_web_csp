use actix_web::{test, web, App, HttpResponse, Result};
use actix_web_csp::{CspPolicyBuilder, Source};

async fn test_handler() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok()
        .insert_header(("content-security-policy", "default-src 'self'"))
        .body("Test page"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::StatusCode;

    #[actix_web::test]
    async fn test_basic_csp_header() {
        let app = test::init_service(App::new().route("/test", web::get().to(test_handler))).await;

        let req = test::TestRequest::get().uri("/test").to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let csp_header = resp.headers().get("content-security-policy");
        assert!(csp_header.is_some(), "CSP header not found");

        let csp_value = csp_header.unwrap().to_str().unwrap();
        assert!(csp_value.contains("default-src 'self'"));
    }

    #[actix_web::test]
    async fn test_csp_policy_builder() {
        let policy = CspPolicyBuilder::new()
            .default_src([Source::Self_])
            .script_src([Source::Self_, Source::UnsafeInline])
            .style_src([Source::Self_, Source::UnsafeInline])
            .build_unchecked();

        assert!(!policy.is_report_only());
    }

    #[actix_web::test]
    async fn test_source_types() {
        let self_source = Source::Self_;
        let unsafe_inline = Source::UnsafeInline;
        let scheme_source = Source::Scheme("https".into());

        assert!(self_source.is_self());
        assert!(unsafe_inline.is_unsafe_inline());
        assert!(!scheme_source.is_self());
    }
}
