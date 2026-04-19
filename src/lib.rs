#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc(html_root_url = "https://docs.rs/actix_web_csp/0.1.0")]
//! Typed Content Security Policy middleware for Actix Web.
//!
//! `actix-web-csp` helps you keep CSP definitions in Rust instead of hand-editing
//! header strings. The crate focuses on three practical jobs:
//!
//! - building policies with typed sources and directives
//! - attaching those policies to Actix responses through middleware
//! - verifying, exporting, and benchmarking policy behavior as the crate grows
//!
//! # Start Here
//!
//! Most applications begin with [`CspPolicyBuilder`] and [`csp_middleware`].
//!
//! ```rust
//! use actix_web_csp::{CspPolicyBuilder, Source};
//! use std::borrow::Cow;
//!
//! let policy = CspPolicyBuilder::new()
//!     .default_src([Source::Self_])
//!     .script_src([
//!         Source::Self_,
//!         Source::Host(Cow::Borrowed("cdn.example.com")),
//!     ])
//!     .style_src([Source::Self_])
//!     .img_src([Source::Self_, Source::Scheme(Cow::Borrowed("https"))])
//!     .object_src([Source::None])
//!     .build()?;
//!
//! let compiled = policy.compile()?;
//! assert_eq!(
//!     compiled.header_name().as_str(),
//!     "content-security-policy"
//! );
//! # Ok::<(), actix_web_csp::CspError>(())
//! ```
//!
//! If you need request-scoped nonces, move one level up to [`CspConfigBuilder`]
//! and build a [`CspMiddleware`] from config.
//!
//! ```rust
//! use actix_web_csp::{CspConfigBuilder, CspMiddleware, CspPolicyBuilder, Source};
//!
//! let policy = CspPolicyBuilder::new()
//!     .default_src([Source::Self_])
//!     .script_src([Source::Self_])
//!     .style_src([Source::Self_])
//!     .build()?;
//!
//! let _middleware = CspMiddleware::new(
//!     CspConfigBuilder::new()
//!         .policy(policy)
//!         .with_nonce_generator(32)
//!         .with_nonce_per_request(true)
//!         .build(),
//! );
//! # Ok::<(), actix_web_csp::CspError>(())
//! ```
//!
//! Presets and JSON interop are available when you want repeatable policy shapes
//! or policy exchange between services and tooling.
//!
//! ```rust
//! use actix_web_csp::{preset_policy, CspPolicy, CspPreset};
//!
//! let policy = preset_policy(CspPreset::Dashboard);
//! let json = policy.to_json_pretty()?;
//! let round_tripped = CspPolicy::from_json_str(&json)?;
//!
//! assert!(round_tripped.get_directive("default-src").is_some());
//! # Ok::<(), actix_web_csp::CspError>(())
//! ```
//!
//! # Feature Flags
//!
//! - `stats`: runtime counters and lightweight metrics
//! - `reporting`: CSP report parsing and reporting middleware helpers
//! - `verify`: [`PolicyVerifier`] support for URI, nonce, and hash checks
//! - `extended-validation`: stricter semantic validation for sources and reporting
//!
//! # Walkthrough Examples
//!
//! The repository includes small, focused examples that are easier to scan than
//! the larger demo servers:
//!
//! - [`walkthrough_basic_policy.rs`](https://github.com/hun756/actix_web_csp/blob/main/examples/walkthrough_basic_policy.rs)
//! - [`walkthrough_nonce_flow.rs`](https://github.com/hun756/actix_web_csp/blob/main/examples/walkthrough_nonce_flow.rs)
//! - [`walkthrough_presets_and_json.rs`](https://github.com/hun756/actix_web_csp/blob/main/examples/walkthrough_presets_and_json.rs)
//!
//! For end-to-end demos, see:
//!
//! - [`real_world_test_fixed.rs`](https://github.com/hun756/actix_web_csp/blob/main/examples/real_world_test_fixed.rs)
//! - [`csp_security_tester.rs`](https://github.com/hun756/actix_web_csp/blob/main/examples/csp_security_tester.rs)
//!
//! # Benchmarks And Profiling
//!
//! The Criterion suite lives in `benches/csp_benchmark.rs` and focuses on policy
//! creation, header generation, nonce and hash generation, compiled snapshot reads,
//! verification, and JSON interop. See `BENCHMARKS.md` in the repository root for
//! commands, baselines, and profiling workflow.

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
