use crate::constants::{
    DEFAULT_BUFFER_CAPACITY, DEFAULT_CACHE_DURATION_SECS, HEADER_CSP, HEADER_CSP_REPORT_ONLY,
    REPORT_TO, REPORT_URI, SEMICOLON_SPACE,
};
use crate::core::directives::{Directive, DirectiveSpec, Sandbox};
use crate::core::source::Source;
use crate::error::CspError;
use crate::utils::{BufferWriter, BytesCache, CachedValue};
use actix_web::http::header::{HeaderName, HeaderValue};
use bytes::BytesMut;
use indexmap::IndexMap;
use rustc_hash::FxHasher;
use std::num::NonZeroU64;
use std::{
    borrow::Cow,
    hash::{Hash, Hasher},
    time::Duration,
};

thread_local! {
    static BYTES_CACHE: std::cell::RefCell<BytesCache<8>> = std::cell::RefCell::new(BytesCache::new());
}

#[derive(Debug, Clone, Default)]
pub struct CspPolicy {
    directives: IndexMap<Cow<'static, str>, Directive>,
    report_only: bool,
    report_uri: Option<Cow<'static, str>>,
    report_to: Option<Cow<'static, str>>,
    cached_header_value: Option<CachedValue<HeaderValue>>,
    estimated_size: usize,
    policy_hash: Option<NonZeroU64>,
}

impl CspPolicy {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_directive(&mut self, directive: Directive) -> &mut Self {
        let size_delta = directive.estimated_size();
        let name = directive.name().to_owned();
        self.directives.insert(Cow::Owned(name), directive);
        self.estimated_size += size_delta;
        self.cached_header_value = None;
        self.policy_hash = None;
        self
    }

    #[inline]
    pub fn set_report_only(&mut self, report_only: bool) -> &mut Self {
        self.report_only = report_only;
        self.cached_header_value = None;
        self.policy_hash = None;
        self
    }

    pub fn set_report_uri(&mut self, uri: impl Into<Cow<'static, str>>) -> &mut Self {
        let uri = uri.into();
        let old_size = self
            .report_uri
            .as_ref()
            .map_or(0, |u| u.len() + REPORT_URI.len() + 1);
        let new_size = uri.len() + REPORT_URI.len() + 1;
        self.estimated_size = self.estimated_size - old_size + new_size;
        self.report_uri = Some(uri);
        self.cached_header_value = None;
        self.policy_hash = None;
        self
    }

    pub fn set_report_to(&mut self, endpoint: impl Into<Cow<'static, str>>) -> &mut Self {
        let endpoint = endpoint.into();
        let old_size = self
            .report_to
            .as_ref()
            .map_or(0, |e| e.len() + REPORT_TO.len() + 1);
        let new_size = endpoint.len() + REPORT_TO.len() + 1;
        self.estimated_size = self.estimated_size - old_size + new_size;
        self.report_to = Some(endpoint);
        self.cached_header_value = None;
        self.policy_hash = None;
        self
    }

    #[inline]
    pub fn header_name(&self) -> HeaderName {
        if self.report_only {
            HeaderName::from_static(HEADER_CSP_REPORT_ONLY)
        } else {
            HeaderName::from_static(HEADER_CSP)
        }
    }

    pub fn header_value(&mut self) -> Result<HeaderValue, CspError> {
        self.header_value_with_cache_duration(Duration::from_secs(DEFAULT_CACHE_DURATION_SECS))
    }

    pub fn header_value_with_cache_duration(
        &mut self,
        ttl: Duration,
    ) -> Result<HeaderValue, CspError> {
        if let Some(cached) = &self.cached_header_value {
            if cached.is_valid() {
                return Ok(cached.value().clone());
            }
        }

        let value = self.generate_header_value()?;
        self.cached_header_value = Some(CachedValue::new(value.clone(), ttl));
        Ok(value)
    }

    fn generate_header_value(&self) -> Result<HeaderValue, CspError> {
        let capacity = self.estimated_size.max(DEFAULT_BUFFER_CAPACITY);
        let mut buffer = BYTES_CACHE.with(|cache| cache.borrow_mut().get(capacity));

        let directives_count = self.directives.len();
        let has_report_uri = self.report_uri.is_some();
        let has_report_to = self.report_to.is_some();

        let total_semicolons = if directives_count > 0 {
            directives_count - 1 + has_report_uri as usize + has_report_to as usize
        } else {
            has_report_uri as usize + has_report_to as usize
        };

        buffer.reserve(self.estimated_size + (total_semicolons * 2));

        let mut first = true;
        for directive in self.directives.values() {
            if !first {
                buffer.extend_from_slice(SEMICOLON_SPACE);
            }
            directive.write_to_buffer(&mut buffer);
            first = false;
        }

        if let Some(uri) = &self.report_uri {
            if !first {
                buffer.extend_from_slice(SEMICOLON_SPACE);
            }
            buffer.extend_from_slice(REPORT_URI.as_bytes());
            buffer.extend_from_slice(b" ");
            buffer.extend_from_slice(uri.as_bytes());
            first = false;
        }

        if let Some(endpoint) = &self.report_to {
            if !first {
                buffer.extend_from_slice(SEMICOLON_SPACE);
            }
            buffer.extend_from_slice(REPORT_TO.as_bytes());
            buffer.extend_from_slice(b" ");
            buffer.extend_from_slice(endpoint.as_bytes());
        }

        let bytes = buffer.freeze();
        let result = HeaderValue::from_maybe_shared(bytes).map_err(|_| {
            CspError::InvalidDirectiveValue("Failed to create header value".to_string())
        });

        BYTES_CACHE.with(|cache| {
            let new_buffer = BytesMut::with_capacity(capacity);
            cache.borrow_mut().recycle(new_buffer);
        });

        result
    }

    pub fn validate(&self) -> Result<(), CspError> {
        for directive in self.directives.values() {
            directive.validate()?;
        }
        Ok(())
    }

    #[inline]
    pub fn get_directive(&self, name: &str) -> Option<&Directive> {
        self.directives.get(name)
    }

    #[inline]
    pub fn is_report_only(&self) -> bool {
        self.report_only
    }

    #[inline]
    pub fn directives(&self) -> impl Iterator<Item = &Directive> {
        self.directives.values()
    }

    #[inline]
    pub fn report_uri(&self) -> Option<&str> {
        self.report_uri.as_deref()
    }

    #[inline]
    pub fn report_to(&self) -> Option<&str> {
        self.report_to.as_deref()
    }

    #[inline]
    pub fn hash(&mut self) -> NonZeroU64 {
        if let Some(hash) = self.policy_hash {
            return hash;
        }

        let mut hasher = FxHasher::default();

        let directive_count = self.directives.len();
        directive_count.hash(&mut hasher);

        for (name, directive) in &self.directives {
            let name_bytes = name.as_bytes();
            hasher.write(name_bytes);

            directive.hash(&mut hasher);
        }

        self.report_only.hash(&mut hasher);

        if let Some(ref uri) = self.report_uri {
            hasher.write(uri.as_bytes());
        }

        if let Some(ref endpoint) = self.report_to {
            hasher.write(endpoint.as_bytes());
        }

        let hash_value = hasher.finish();
        let hash = NonZeroU64::new(hash_value).unwrap_or_else(|| NonZeroU64::new(1).unwrap());

        self.policy_hash = Some(hash);
        hash
    }

    #[inline]
    pub fn contains_nonce(&self) -> bool {
        self.directives.values().any(|d| d.contains_nonce())
    }

    #[inline]
    pub fn contains_hash(&self) -> bool {
        self.directives.values().any(|d| d.contains_hash())
    }
}

impl Hash for CspPolicy {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.directives.len().hash(state);
        for (name, directive) in &self.directives {
            name.hash(state);
            directive.hash(state);
        }
        self.report_only.hash(state);
        self.report_uri.hash(state);
        self.report_to.hash(state);
    }
}

#[derive(Debug, Default)]
pub struct CspPolicyBuilder {
    policy: CspPolicy,
}

impl CspPolicyBuilder {
    #[inline]
    pub fn new() -> Self {
        Self {
            policy: CspPolicy::new(),
        }
    }

    pub fn add_directive<D: DirectiveSpec>(mut self, directive_builder: D) -> Self {
        self.policy.add_directive(directive_builder.build());
        self
    }

    #[inline]
    pub fn with_directive(mut self, directive: Directive) -> Self {
        self.policy.add_directive(directive);
        self
    }

    pub fn default_src(self, sources: impl IntoIterator<Item = Source>) -> Self {
        self.add_directive(crate::core::directives::DefaultSrc::new().add_sources(sources))
    }

    pub fn script_src(self, sources: impl IntoIterator<Item = Source>) -> Self {
        self.add_directive(crate::core::directives::ScriptSrc::new().add_sources(sources))
    }

    pub fn style_src(self, sources: impl IntoIterator<Item = Source>) -> Self {
        self.add_directive(crate::core::directives::StyleSrc::new().add_sources(sources))
    }

    pub fn img_src(self, sources: impl IntoIterator<Item = Source>) -> Self {
        self.add_directive(crate::core::directives::ImgSrc::new().add_sources(sources))
    }

    pub fn connect_src(self, sources: impl IntoIterator<Item = Source>) -> Self {
        self.add_directive(crate::core::directives::ConnectSrc::new().add_sources(sources))
    }

    pub fn font_src(self, sources: impl IntoIterator<Item = Source>) -> Self {
        self.add_directive(crate::core::directives::FontSrc::new().add_sources(sources))
    }

    pub fn object_src(self, sources: impl IntoIterator<Item = Source>) -> Self {
        self.add_directive(crate::core::directives::ObjectSrc::new().add_sources(sources))
    }

    pub fn media_src(self, sources: impl IntoIterator<Item = Source>) -> Self {
        self.add_directive(crate::core::directives::MediaSrc::new().add_sources(sources))
    }

    pub fn frame_src(self, sources: impl IntoIterator<Item = Source>) -> Self {
        self.add_directive(crate::core::directives::FrameSrc::new().add_sources(sources))
    }

    pub fn worker_src(self, sources: impl IntoIterator<Item = Source>) -> Self {
        self.add_directive(crate::core::directives::WorkerSrc::new().add_sources(sources))
    }

    pub fn manifest_src(self, sources: impl IntoIterator<Item = Source>) -> Self {
        self.add_directive(crate::core::directives::ManifestSrc::new().add_sources(sources))
    }

    pub fn child_src(self, sources: impl IntoIterator<Item = Source>) -> Self {
        self.add_directive(crate::core::directives::ChildSrc::new().add_sources(sources))
    }

    pub fn frame_ancestors(self, sources: impl IntoIterator<Item = Source>) -> Self {
        self.add_directive(crate::core::directives::FrameAncestors::new().add_sources(sources))
    }

    pub fn base_uri(self, sources: impl IntoIterator<Item = Source>) -> Self {
        self.add_directive(crate::core::directives::BaseUri::new().add_sources(sources))
    }

    pub fn form_action(self, sources: impl IntoIterator<Item = Source>) -> Self {
        self.add_directive(crate::core::directives::FormAction::new().add_sources(sources))
    }

    pub fn sandbox(self, sandbox_builder: Sandbox) -> Self {
        self.with_directive(sandbox_builder.build())
    }

    pub fn upgrade_insecure_requests(mut self) -> Self {
        self.policy
            .add_directive(Directive::new("upgrade-insecure-requests"));
        self
    }

    pub fn block_all_mixed_content(mut self) -> Self {
        self.policy
            .add_directive(Directive::new("block-all-mixed-content"));
        self
    }

    pub fn require_trusted_types_for(
        self,
        contexts: impl IntoIterator<Item = impl Into<Cow<'static, str>>>,
    ) -> Self {
        let mut directive = Directive::new("require-trusted-types-for");
        for context in contexts {
            directive.add_source(Source::Host(context.into()));
        }
        self.with_directive(directive)
    }

    pub fn trusted_types(
        self,
        policies: impl IntoIterator<Item = impl Into<Cow<'static, str>>>,
    ) -> Self {
        let mut directive = Directive::new("trusted-types");
        for policy in policies {
            directive.add_source(Source::Host(policy.into()));
        }
        self.with_directive(directive)
    }

    #[inline]
    pub fn report_uri(mut self, uri: impl Into<Cow<'static, str>>) -> Self {
        self.policy.set_report_uri(uri);
        self
    }

    #[inline]
    pub fn report_to(mut self, endpoint: impl Into<Cow<'static, str>>) -> Self {
        self.policy.set_report_to(endpoint);
        self
    }

    #[inline]
    pub fn report_only(mut self, enabled: bool) -> Self {
        self.policy.set_report_only(enabled);
        self
    }

    pub fn build(self) -> Result<CspPolicy, CspError> {
        self.policy.validate()?;
        Ok(self.policy)
    }

    #[inline]
    pub fn build_unchecked(self) -> CspPolicy {
        self.policy
    }
}
