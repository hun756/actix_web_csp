use actix_web::{test, web, App, HttpResponse};
use actix_web_csp::prelude::*;

/// Test için basit bir handler
pub async fn test_handler() -> HttpResponse {
    HttpResponse::Ok().body("Test response")
}

/// Test için CSP konfigürasyonu oluşturur
pub fn create_test_config() -> CspConfig {
    CspConfigBuilder::new()
        .default_src(vec![Source::SelfOrigin])
        .script_src(vec![Source::SelfOrigin, Source::UnsafeInline])
        .style_src(vec![Source::SelfOrigin, Source::UnsafeInline])
        .build()
        .expect("Test config oluşturulamadı")
}

/// Test için CSP policy oluşturur
pub fn create_test_policy() -> CspPolicy {
    CspPolicyBuilder::new()
        .default_src(vec![Source::SelfOrigin])
        .script_src(vec![Source::SelfOrigin])
        .build()
        .expect("Test policy oluşturulamadı")
}

/// Test için Actix web app oluşturur
pub fn create_test_app() -> App<
    impl actix_service::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    App::new()
        .wrap(csp_middleware(create_test_config()))
        .route("/test", web::get().to(test_handler))
}