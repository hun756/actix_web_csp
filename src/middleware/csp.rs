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
use futures::future::{ready, LocalBoxFuture, Ready};
use std::borrow::Cow;
use std::{rc::Rc, sync::Arc};
use uuid::Uuid;

#[derive(Clone)]
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
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
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
            service: Rc::new(service),
            config: self.config.clone(),
        }))
    }
}

pub struct CspMiddlewareService<S> {
    service: Rc<S>,
    config: Arc<CspConfig>,
}

impl<S, B> Service<ServiceRequest> for CspMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let config = self.config.clone();

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

            config.stats().increment_request_count();

            let mut res = service.call(req).await?;

            let _timer = PerformanceTimer::new();

            let policy_guard = config.policy();
            let policy = policy_guard.read();

            let hash_timer = PerformanceTimer::new();
            let mut policy_for_hash = policy.clone();
            let policy_hash = policy_for_hash.hash();
            config
                .stats()
                .add_policy_hash_time(hash_timer.elapsed().as_nanos() as usize);

            let headers = res.headers_mut();

            if let Some(cached_policy) = config.get_cached_policy(policy_hash) {
                config.stats().increment_cache_hit_count();
                drop(policy);

                let header_name = if cached_policy.is_report_only() {
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

            Ok(res)
        })
    }
}

#[inline]
pub fn csp_middleware(policy: crate::core::policy::CspPolicy) -> CspMiddleware {
    CspMiddleware::new(crate::core::config::CspConfig::new(policy))
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
            .build(),
    )
}

pub fn configure_csp(
    policy: crate::core::policy::CspPolicy,
) -> impl FnOnce(&mut actix_web::web::ServiceConfig) {
    move |cfg| {
        let config = crate::core::config::CspConfig::new(policy);
        cfg.app_data(Data::new(config.clone()));
        cfg.app_data(Data::new(CspMiddleware::new(config)));
    }
}

pub fn configure_csp_with_reporting<F>(
    _policy: crate::core::policy::CspPolicy,
    report_handler: F,
) -> impl FnOnce(&mut actix_web::web::ServiceConfig)
where
    F: Fn(crate::monitoring::report::CspViolationReport) + Send + Sync + 'static + Clone + 'static,
{
    move |cfg| {
        let stats = std::sync::Arc::new(crate::monitoring::stats::CspStats::new());
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

pub fn csp_with_reporting<F>(
    policy: crate::core::policy::CspPolicy,
    report_handler: F,
) -> (
    CspMiddleware,
    impl FnOnce(&mut actix_web::web::ServiceConfig),
)
where
    F: Fn(crate::monitoring::report::CspViolationReport) + Send + Sync + 'static + Clone + 'static,
{
    let middleware = csp_middleware(policy.clone());
    let configurator = configure_csp_with_reporting(policy, report_handler);
    (middleware, configurator)
}
