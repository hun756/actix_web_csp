//! Common imports for applications that prefer a compact `prelude::*` style.

pub use crate::core::{
    CspConfig, CspConfigBuilder, CspPolicy, CspPolicyBuilder, DirectiveDocument, PolicyDocument,
    Source,
};
#[allow(deprecated)]
pub use crate::middleware::{
    configure_csp, csp_middleware, csp_middleware_with_nonce, csp_middleware_with_request_nonce,
    CspExtensions, CspMiddleware,
};
pub use crate::monitoring::{CspStats, CspViolationReport};
pub use crate::presets::{preset_policy, CspPreset};
pub use crate::security::{HashAlgorithm, HashGenerator, NonceGenerator, PolicyVerifier};
