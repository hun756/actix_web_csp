use crate::config::CspConfig;
use crate::constants::{DEFAULT_MAX_REPORT_SIZE, DEFAULT_REPORT_PATH};
use crate::hash::HashAlgorithm;
use crate::nonce::RequestNonce;
use crate::perf::PerformanceTimer;
use crate::policy::CspPolicy;
use crate::report::CspViolationReport;
use crate::source::Source;
use actix_web::FromRequest;
use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorBadRequest,
    http::{header::HeaderName, Method},
    web::{self, Data},
    Error, HttpMessage, HttpResponse,
};
use futures::{
    future::{ready, Ready},
    Future,
};
use log;
use std::{borrow::Cow, pin::Pin, sync::Arc};
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

pub trait CspExtensions {
    fn get_nonce(&self) -> Option<String>;
    fn generate_hash(&self, algorithm: HashAlgorithm, data: &[u8]) -> String;
    fn generate_hash_source(&self, algorithm: HashAlgorithm, data: &[u8]) -> Source;
}

impl<T> CspExtensions for T
where
    T: HttpMessage,
{
    fn get_nonce(&self) -> Option<String> {
        self.extensions()
            .get::<RequestNonce>()
            .map(|nonce| nonce.0.clone())
    }

    fn generate_hash(&self, algorithm: HashAlgorithm, data: &[u8]) -> String {
        crate::hash::HashGenerator::generate(algorithm, data)
    }

    fn generate_hash_source(&self, algorithm: HashAlgorithm, data: &[u8]) -> Source {
        crate::hash::HashGenerator::generate_source(algorithm, data)
    }
}

type ViolationHandler = Arc<dyn Fn(CspViolationReport) + Send + Sync + 'static>;

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
        // Track request count for statistics
        self.config.stats().increment_request_count();

        // Clone required data for async block
        let config = self.config.clone();
        let service = self.service.clone();

        Box::pin(async move {
            // Generate a unique request ID efficiently
            let request_id = Uuid::new_v4()
                .hyphenated()
                .encode_lower(&mut Uuid::encode_buffer())
                .to_owned();

            // Store request ID in extensions
            req.extensions_mut()
                .insert(Cow::<'static, str>::Owned(request_id.clone()));

            // Generate nonce if needed
            if let Some(nonce) = config.get_or_generate_request_nonce(&request_id) {
                req.extensions_mut().insert(RequestNonce(nonce));
            }

            // Process the request through the service chain
            let mut res = service.call(req).await?;

            // Start timing header generation
            let timer = PerformanceTimer::new();

            // Get policy and calculate hash
            let policy_guard = config.policy();
            let policy = policy_guard.read();

            let hash_timer = PerformanceTimer::new();
            let mut policy_for_hash = policy.clone();
            let policy_hash = policy_for_hash.hash();
            config
                .stats()
                .add_policy_hash_time(hash_timer.elapsed().as_nanos() as usize);

            // Get headers for modification
            let headers = res.headers_mut();

            // Fast path: use cached policy if available
            if likely(config.get_cached_policy(policy_hash).is_some()) {
                let cached_policy = config.get_cached_policy(policy_hash).unwrap();
                config.stats().increment_cache_hit_count();
                drop(policy); // Release the read lock early

                // Determine header name based on policy type
                let header_name = if unlikely(cached_policy.is_report_only()) {
                    HeaderName::from_static(crate::constants::HEADER_CSP_REPORT_ONLY)
                } else {
                    HeaderName::from_static(crate::constants::HEADER_CSP)
                };

                // Generate header value from cached policy
                let mut policy_clone = cached_policy.as_ref().clone();
                if let Ok(value) =
                    policy_clone.header_value_with_cache_duration(config.cache_duration())
                {
                    headers.insert(header_name, value);
                }
            } else {
                // Slow path: generate header value from policy
                let serialize_timer = PerformanceTimer::new();
                let header_name = policy.header_name();
                let mut policy_clone = policy.clone();
                drop(policy); // Release the read lock early

                // Generate and insert header value
                let header_value =
                    policy_clone.header_value_with_cache_duration(config.cache_duration());
                config
                    .stats()
                    .add_policy_serialize_time(serialize_timer.elapsed().as_nanos() as usize);

                if let Ok(value) = header_value {
                    headers.insert(header_name, value);
                    // Cache the policy for future requests
                    config.cache_policy(policy_hash, policy_clone);
                }
            }

            // Record total header generation time
            config
                .stats()
                .add_header_generation_time(timer.elapsed().as_nanos() as usize);
            Ok(res)
        })
    }
}

pub struct CspReportingMiddleware {
    handler: ViolationHandler,
    report_path: Cow<'static, str>,
    max_report_size: usize,
    stats: Arc<crate::stats::CspStats>,
}

impl CspReportingMiddleware {
    pub fn new<F>(handler: F) -> Self
    where
        F: Fn(CspViolationReport) + Send + Sync + 'static,
    {
        Self {
            handler: Arc::new(handler),
            report_path: Cow::Borrowed(DEFAULT_REPORT_PATH),
            max_report_size: DEFAULT_MAX_REPORT_SIZE,
            stats: Arc::new(crate::stats::CspStats::new()),
        }
    }

    #[inline]
    pub fn with_report_path(mut self, path: impl Into<Cow<'static, str>>) -> Self {
        self.report_path = path.into();
        self
    }

    #[inline]
    pub fn with_max_report_size(mut self, size: usize) -> Self {
        self.max_report_size = size;
        self
    }

    #[inline]
    pub fn with_stats(mut self, stats: Arc<crate::stats::CspStats>) -> Self {
        self.stats = stats;
        self
    }

    #[inline]
    pub fn stats(&self) -> &Arc<crate::stats::CspStats> {
        &self.stats
    }
}

impl<S, B> Transform<S, ServiceRequest> for CspReportingMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + Clone + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = CspReportingMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CspReportingMiddlewareService {
            service,
            handler: self.handler.clone(),
            report_path: self.report_path.clone(),
            max_report_size: self.max_report_size,
            stats: self.stats.clone(),
        }))
    }
}

pub struct CspReportingMiddlewareService<S> {
    service: S,
    handler: ViolationHandler,
    report_path: Cow<'static, str>,
    max_report_size: usize,
    stats: Arc<crate::stats::CspStats>,
}

impl<S, B> Service<ServiceRequest> for CspReportingMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + Clone + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if req.path() == self.report_path && req.method() == &Method::POST {
            let handler = self.handler.clone();
            let max_size = self.max_report_size;
            let stats = self.stats.clone();

            Box::pin(async move {
                let (http_req, mut payload) = req.into_parts();
                let body = match web::Bytes::from_request(&http_req, &mut payload).await {
                    Ok(bytes) => {
                        if bytes.len() > max_size {
                            return Err(ErrorBadRequest("CSP report too large"));
                        }
                        bytes
                    }
                    Err(e) => return Err(Error::from(e)),
                };

                match process_violation_report(&body) {
                    Ok(Some(report)) => {
                        stats.increment_violation_count();
                        handler(report);
                    }
                    Ok(None) => {
                        log::debug!("CSP violation report missing 'csp-report' field");
                    }
                    Err(e) => {
                        log::error!("Failed to process CSP violation report: {}", e);
                    }
                }

                let response = HttpResponse::Ok().finish().map_into_right_body();
                Ok(ServiceResponse::new(http_req, response))
            })
        } else {
            let service = self.service.clone();
            Box::pin(async move {
                let res = service.call(req).await?;
                Ok(res.map_into_left_body())
            })
        }
    }
}

#[inline]
fn process_violation_report(bytes: &[u8]) -> Result<Option<CspViolationReport>, serde_json::Error> {
    // Use a more efficient approach to extract just the csp-report field
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let json: serde_json::Value = serde::Deserialize::deserialize(&mut deserializer)?;

    // Check if the csp-report field exists
    if let Some(csp_report) = json.get("csp-report") {
        // Deserialize directly from the csp-report value
        let report = serde_json::from_value::<CspViolationReport>(csp_report.clone())?;
        Ok(Some(report))
    } else {
        Ok(None)
    }
}

#[inline]
pub fn csp_middleware(policy: CspPolicy) -> CspMiddleware {
    CspMiddleware::new(CspConfig::new(policy))
}

#[inline]
pub fn csp_middleware_with_nonce(policy: CspPolicy, nonce_length: usize) -> CspMiddleware {
    CspMiddleware::new(
        crate::config::CspConfigBuilder::new()
            .policy(policy)
            .with_nonce_generator(nonce_length)
            .build(),
    )
}

#[inline]
pub fn csp_middleware_with_request_nonce(policy: CspPolicy, nonce_length: usize) -> CspMiddleware {
    CspMiddleware::new(
        crate::config::CspConfigBuilder::new()
            .policy(policy)
            .with_nonce_generator(nonce_length)
            .with_nonce_per_request(true)
            .build(),
    )
}

#[inline]
#[allow(dead_code)]
pub fn csp_reporting_middleware<F>(handler: F) -> CspReportingMiddleware
where
    F: Fn(CspViolationReport) + Send + Sync + 'static,
{
    CspReportingMiddleware::new(handler)
}

pub fn configure_csp(policy: CspPolicy) -> impl FnOnce(&mut web::ServiceConfig) {
    move |cfg| {
        let config = CspConfig::new(policy);
        cfg.app_data(Data::new(config.clone()));
        cfg.app_data(Data::new(CspMiddleware::new(config)));
    }
}

pub fn configure_csp_with_reporting<F>(
    policy: CspPolicy,
    report_handler: F,
) -> impl FnOnce(&mut web::ServiceConfig)
where
    F: Fn(CspViolationReport) + Send + Sync + 'static + Clone + 'static,
{
    move |cfg| {
        let config = CspConfig::new(policy);
        let stats = config.stats().clone();
        cfg.app_data(Data::new(config.clone()));
        cfg.app_data(Data::new(CspMiddleware::new(config)));
        cfg.app_data(Data::new(
            CspReportingMiddleware::new(report_handler.clone()).with_stats(stats),
        ));
        cfg.route(DEFAULT_REPORT_PATH, web::post().to(HttpResponse::Ok));
    }
}
