use crate::constants::{HEADER_CSP, HEADER_CSP_REPORT_ONLY};
use crate::core::config::CspConfig;
use crate::monitoring::perf::PerformanceTimer;
use crate::security::nonce::RequestNonce;
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::header::HeaderName,
    web::Data,
    Error, HttpMessage,
};
use futures::{
    future::{ready, Ready},
    Future,
};
use std::borrow::Cow;
use std::{pin::Pin, sync::Arc};
use uuid::Uuid;

#[inline(always)]
fn likely(b: bool) -> bool {
    #[cold]
    fn cold() {}

    if !b {
        cold();
    }
    b
}

#[inline(always)]
fn unlikely(b: bool) -> bool {
    #[cold]
    fn cold() {}

    if b {
        cold();
    }
    b
}

pub struct CspMiddleware {
    config: Arc<CspConfig>,
}

impl CspMiddleware {
    #[inline]
    pub fn new(config: CspConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    #[inline]
    pub fn config(&self) -> Arc<CspConfig> {
        self.config.clone()
    }
}

impl<S, B> Transform<S, ServiceRequest> for CspMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + Clone + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = CspMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CspMiddlewareService {
            service,
            config: self.config.clone(),
        }))
    }
}

pub struct CspMiddlewareService<S> {
    service: S,
    config: Arc<CspConfig>,
}

impl<S, B> Service<ServiceRequest> for CspMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + Clone + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        self.config.stats().increment_request_count();

        let config = self.config.clone();
        let service = self.service.clone();

        Box::pin(async move {
            let request_id = Uuid::new_v4()
                .hyphenated()
                .encode_lower(&mut Uuid::encode_buffer())
                .to_owned();

            req.extensions_mut()
                .insert(Cow::<'static, str>::Owned(request_id.clone()));

            if let Some(nonce) = config.get_or_generate_request_nonce(&request_id) {
                req.extensions_mut().insert(RequestNonce(nonce));
            }

            let mut res = service.call(req).await?;

            let timer = PerformanceTimer::new();

            let policy_guard = config.policy();
            let policy = policy_guard.read();

            let hash_timer = PerformanceTimer::new();
            let mut policy_for_hash = policy.clone();
            let policy_hash = policy_for_hash.hash();
            config
                .stats()
                .add_policy_hash_time(hash_timer.elapsed().as_nanos() as usize);

            let headers = res.headers_mut();

            if likely(config.get_cached_policy(policy_hash).is_some()) {
                let cached_policy = config.get_cached_policy(policy_hash).unwrap();
                config.stats().increment_cache_hit_count();
                drop(policy);

                let header_name = if unlikely(cached_policy.is_report_only()) {
                    HeaderName::from_static(HEADER_CSP_REPORT_ONLY)
                } else {
                    HeaderName::from_static(HEADER_CSP)
                };

                let mut policy_clone = cached_policy.as_ref().clone();
                if let Ok(value) =
                    policy_clone.header_value_with_cache_duration(config.cache_duration())
                {
                    headers.insert(header_name, value);
                }
            } else {
                let serialize_timer = PerformanceTimer::new();
                let header_name = policy.header_name();
                let mut policy_clone = policy.clone();
                drop(policy);

                let header_value =
                    policy_clone.header_value_with_cache_duration(config.cache_duration());
                config
                    .stats()
                    .add_policy_serialize_time(serialize_timer.elapsed().as_nanos() as usize);

                if let Ok(value) = header_value {
                    headers.insert(header_name, value);

                    config.cache_policy(policy_hash, policy_clone);
                }
            }

            config
                .stats()
                .add_header_generation_time(timer.elapsed().as_nanos() as usize);
            Ok(res)
        })
    }
}

#[inline]
pub fn csp_middleware(policy: crate::core::policy::CspPolicy) -> CspMiddleware {
    CspMiddleware::new(CspConfig::new(policy))
}

#[inline]
pub fn csp_middleware_with_nonce(
    policy: crate::core::policy::CspPolicy,
    nonce_length: usize,
) -> CspMiddleware {
    CspMiddleware::new(
        crate::core::config::CspConfigBuilder::new()
            .policy(policy)
            .with_nonce_generator(nonce_length)
            .build(),
    )
}

#[inline]
pub fn csp_middleware_with_request_nonce(
    policy: crate::core::policy::CspPolicy,
    nonce_length: usize,
) -> CspMiddleware {
    CspMiddleware::new(
        crate::core::config::CspConfigBuilder::new()
            .policy(policy)
            .with_nonce_generator(nonce_length)
            .with_nonce_per_request(true)
            .build(),
    )
}

pub fn configure_csp(
    policy: crate::core::policy::CspPolicy,
) -> impl FnOnce(&mut actix_web::web::ServiceConfig) {
    move |cfg| {
        let config = CspConfig::new(policy);
        cfg.app_data(Data::new(config.clone()));
        cfg.app_data(Data::new(CspMiddleware::new(config)));
    }
}

pub fn configure_csp_with_reporting<F>(
    policy: crate::core::policy::CspPolicy,
    report_handler: F,
) -> impl FnOnce(&mut actix_web::web::ServiceConfig)
where
    F: Fn(crate::monitoring::report::CspViolationReport) + Send + Sync + 'static + Clone + 'static,
{
    move |cfg| {
        let config = CspConfig::new(policy);
        let stats = config.stats().clone();
        cfg.app_data(Data::new(config.clone()));
        cfg.app_data(Data::new(CspMiddleware::new(config)));
        cfg.app_data(Data::new(
            crate::middleware::reporting::CspReportingMiddleware::new(report_handler.clone())
                .with_stats(stats),
        ));
        cfg.route(
            crate::constants::DEFAULT_REPORT_PATH,
            actix_web::web::post().to(actix_web::HttpResponse::Ok),
        );
    }
}
