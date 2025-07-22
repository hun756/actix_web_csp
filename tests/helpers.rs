use actix_web::HttpResponse;
use actix_web_csp::core::CspPolicy;

pub async fn test_handler() -> HttpResponse {
    HttpResponse::Ok().body("Test response")
}

pub fn create_test_policy() -> CspPolicy {
    CspPolicy::default()
}