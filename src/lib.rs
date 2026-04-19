pub mod constants;
pub mod core;
pub mod error;
pub mod middleware;
pub mod monitoring;
pub mod prelude;
pub mod presets;
pub mod security;
pub mod utils;

// Re-export commonly used types for convenience
pub use core::{
    CompiledCspPolicy, CspConfig, CspConfigBuilder, CspPolicy, CspPolicyBuilder, DirectiveDocument,
    PolicyDocument, Source,
};
pub use error::CspError;
#[allow(deprecated)]
pub use middleware::{
    configure_csp, configure_csp_with_reporting, csp_middleware, csp_middleware_with_nonce,
    csp_middleware_with_request_nonce, csp_with_reporting, CspExtensions, CspMiddleware,
    CspReportingMiddleware,
};
pub use monitoring::{
    AdaptiveCache, CspStats, CspViolationReport, PerformanceMetrics, PerformanceTimer,
};
pub use presets::{preset_policy, CspPreset};
pub use security::{HashAlgorithm, HashGenerator, NonceGenerator, PolicyVerifier, RequestNonce};
