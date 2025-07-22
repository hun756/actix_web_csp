use crate::constants::DEFAULT_MAX_REPORT_SIZE;
use crate::constants::DEFAULT_REPORT_PATH;
use crate::monitoring::report::CspViolationReport;
use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorBadRequest,
    http::Method,
    web::{self},
    Error, FromRequest, HttpResponse,
};
use futures::{
    future::{ready, Ready},
    Future,
};
use log;
use std::{borrow::Cow, pin::Pin, sync::Arc};

type ViolationHandler = Arc<dyn Fn(CspViolationReport) + Send + Sync + 'static>;

pub struct CspReportingMiddleware {
    handler: ViolationHandler,
    report_path: Cow<'static, str>,
    max_report_size: usize,
    stats: Arc<crate::monitoring::stats::CspStats>,
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
            stats: Arc::new(crate::monitoring::stats::CspStats::new()),
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
    pub fn with_stats(mut self, stats: Arc<crate::monitoring::stats::CspStats>) -> Self {
        self.stats = stats;
        self
    }

    #[inline]
    pub fn stats(&self) -> &Arc<crate::monitoring::stats::CspStats> {
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
    stats: Arc<crate::monitoring::stats::CspStats>,
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
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let json: serde_json::Value = serde::Deserialize::deserialize(&mut deserializer)?;

    if let Some(csp_report) = json.get("csp-report") {
        let report = serde_json::from_value::<CspViolationReport>(csp_report.clone())?;
        Ok(Some(report))
    } else {
        Ok(None)
    }
}

#[inline]
pub fn csp_reporting_middleware<F>(handler: F) -> CspReportingMiddleware
where
    F: Fn(CspViolationReport) + Send + Sync + 'static,
{
    CspReportingMiddleware::new(handler)
}
