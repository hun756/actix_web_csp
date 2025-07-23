pub mod constants;
pub mod core;
pub mod error;
pub mod middleware;
pub mod monitoring;
pub mod prelude;
pub mod security;
pub mod utils;

// Re-export commonly used types for convenience
pub use core::{CspConfig, CspConfigBuilder, CspPolicy, CspPolicyBuilder, Source};
pub use error::CspError;
pub use middleware::{
    configure_csp, configure_csp_with_reporting, csp_middleware, csp_middleware_with_nonce,
    csp_middleware_with_request_nonce, csp_with_reporting, CspExtensions, CspMiddleware, CspReportingMiddleware,
};
pub use monitoring::{CspStats, CspViolationReport, PerformanceMetrics, PerformanceTimer, AdaptiveCache};
pub use security::{HashAlgorithm, HashGenerator, NonceGenerator, PolicyVerifier, RequestNonce};