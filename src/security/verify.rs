use crate::core::policy::CspPolicy;
use crate::error::CspError;

#[cfg(feature = "verify")]
mod imp {
    use super::*;
    use crate::core::source::Source;
    use rustc_hash::FxHashSet;
    use std::collections::HashMap;
    use url::Url;

    pub struct PolicyVerifier {
        policy: CspPolicy,
        origin: Option<Url>,
        url_cache: HashMap<String, Url>,
        host_cache: FxHashSet<String>,
        verification_cache: lru::LruCache<u64, bool>,
    }

    impl PolicyVerifier {
        #[inline]
        pub fn new(policy: CspPolicy) -> Self {
            Self {
                policy,
                origin: None,
                url_cache: HashMap::with_capacity(256),
                host_cache: FxHashSet::with_capacity_and_hasher(128, Default::default()),
                verification_cache: lru::LruCache::new(
                    std::num::NonZeroUsize::new(512).unwrap(),
                ),
            }
        }

        pub fn with_origin(
            policy: CspPolicy,
            origin: impl AsRef<str>,
        ) -> Result<Self, CspError> {
            let mut verifier = Self::new(policy);
            verifier.set_origin(origin)?;
            Ok(verifier)
        }

        pub fn set_origin(&mut self, origin: impl AsRef<str>) -> Result<(), CspError> {
            let parsed_origin = Url::parse(origin.as_ref()).map_err(|error| {
                CspError::VerificationError(format!(
                    "Invalid origin '{}': {}",
                    origin.as_ref(),
                    error
                ))
            })?;

            self.origin = Some(parsed_origin);
            self.verification_cache.clear();
            Ok(())
        }

        pub fn verify_uri(&mut self, uri: &str, directive_name: &str) -> Result<bool, CspError> {
            let cache_key = {
                let mut hasher = rustc_hash::FxHasher::default();
                std::hash::Hash::hash(&uri, &mut hasher);
                std::hash::Hash::hash(&directive_name, &mut hasher);
                std::hash::Hasher::finish(&hasher)
            };

            if let Some(&cached_result) = self.verification_cache.get(&cache_key) {
                return Ok(cached_result);
            }

            let directive = match self.policy.get_directive(directive_name) {
                Some(d) => d,
                None => {
                    if directive_name != "default-src" {
                        return self.verify_uri(uri, "default-src");
                    } else {
                        let result = true;
                        self.verification_cache.put(cache_key, result);
                        return Ok(result);
                    }
                }
            };

            let parsed_url = if let Some(cached) = self.url_cache.get(uri) {
                cached.clone()
            } else {
                match Url::parse(uri) {
                    Ok(url) => {
                        if self.url_cache.len() < 256 {
                            self.url_cache.insert(uri.to_string(), url.clone());
                        }
                        url
                    }
                    Err(_) => {
                        let result = false;
                        self.verification_cache.put(cache_key, result);
                        return Err(CspError::VerificationError(format!("Invalid URI: {}", uri)));
                    }
                }
            };

            let sources = directive.sources();
            if sources.iter().any(|s| s.is_none()) {
                let result = false;
                self.verification_cache.put(cache_key, result);
                return Ok(result);
            }

            let uri_scheme = parsed_url.scheme();
            let uri_host = parsed_url.host_str();

            for source in sources {
                match source {
                    Source::None => {
                        let result = false;
                        self.verification_cache.put(cache_key, result);
                        return Ok(result);
                    }
                    Source::Self_ => {
                        if self.is_same_origin(&parsed_url) {
                            let result = true;
                            self.verification_cache.put(cache_key, result);
                            return Ok(result);
                        }
                    }
                    Source::Host(host) => {
                        if let Some(host_str) = uri_host {
                            if host_str == host.as_ref() {
                                let result = true;
                                self.verification_cache.put(cache_key, result);
                                return Ok(result);
                            } else if let Some(domain) = host.strip_prefix("*.") {
                                if host_str.ends_with(domain) {
                                    let domain_with_dot = format!(".{}", domain);
                                    if host_str.ends_with(&domain_with_dot) || host_str == domain {
                                        let result = true;
                                        self.verification_cache.put(cache_key, result);
                                        return Ok(result);
                                    }
                                }
                            }
                        }
                    }
                    Source::Scheme(scheme) => {
                        if uri_scheme == scheme.as_ref() {
                            let result = true;
                            self.verification_cache.put(cache_key, result);
                            return Ok(result);
                        }
                    }
                    _ => {}
                }
            }

            let result = false;
            self.verification_cache.put(cache_key, result);
            Ok(result)
        }

        pub fn verify_hash(&self, content: &[u8], directive_name: &str) -> Result<bool, CspError> {
            let directive = match self.policy.get_directive(directive_name) {
                Some(d) => d,
                None => {
                    if directive_name != "default-src" {
                        return self.verify_hash(content, "default-src");
                    } else {
                        return Ok(false);
                    }
                }
            };

            if directive.sources().iter().any(|s| s.is_none()) {
                return Ok(false);
            }

            for source in directive.sources() {
                if let Source::Hash { algorithm, value } = source {
                    let calculated =
                        crate::security::hash::HashGenerator::generate(*algorithm, content);
                    if calculated == value.as_ref() {
                        return Ok(true);
                    }
                }
            }

            Ok(false)
        }

        pub fn verify_nonce(&self, nonce: &str, directive_name: &str) -> Result<bool, CspError> {
            let directive = match self.policy.get_directive(directive_name) {
                Some(d) => d,
                None => {
                    if directive_name != "default-src" {
                        return self.verify_nonce(nonce, "default-src");
                    } else {
                        return Ok(false);
                    }
                }
            };

            if directive.sources().iter().any(|s| s.is_none()) {
                return Ok(false);
            }

            for source in directive.sources() {
                if let Source::Nonce(expected_nonce) = source {
                    if nonce == expected_nonce.as_ref() {
                        return Ok(true);
                    }
                }
            }

            Ok(false)
        }

        #[inline]
        fn is_same_origin(&self, url: &Url) -> bool {
            if let Some(origin) = &self.origin {
                return url.scheme() == origin.scheme()
                    && url.host_str() == origin.host_str()
                    && url.port_or_known_default() == origin.port_or_known_default();
            }

            false
        }

        #[inline]
        #[allow(dead_code)]
        fn match_host(&self, url: &Url, host: &str) -> bool {
            let url_host = match url.host_str() {
                Some(h) => h,
                None => return false,
            };

            if url_host == host {
                return true;
            }

            if host.starts_with("*.") {
                let domain = &host[2..];
                if url_host.len() > domain.len() && url_host.ends_with(domain) {
                    let prefix_len = url_host.len() - domain.len();
                    let prefix = &url_host[..prefix_len];

                    return !prefix.contains('.') && prefix.ends_with('.');
                }
            }

            false
        }

        #[inline]
        pub fn policy(&self) -> &CspPolicy {
            &self.policy
        }

        #[inline]
        pub fn policy_mut(&mut self) -> &mut CspPolicy {
            &mut self.policy
        }

        pub fn clear_caches(&mut self) {
            self.url_cache.clear();
            self.host_cache.clear();
            self.verification_cache.clear();
        }

        pub fn verify_inline_script(
            &self,
            content: &[u8],
            nonce: Option<&str>,
        ) -> Result<bool, CspError> {
            let directive_name = "script-src";
            let default_name = "default-src";

            let directive = self
                .policy
                .get_directive(directive_name)
                .or_else(|| self.policy.get_directive(default_name));

            if let Some(directive) = directive {
                if directive.sources().iter().any(|s| s.is_none()) {
                    return Ok(false);
                }

                if directive.sources().iter().any(|s| s.is_unsafe_inline()) {
                    return Ok(true);
                }

                if let Some(nonce_value) = nonce {
                    if directive.sources().iter().any(|s| {
                        if let Source::Nonce(expected) = s {
                            expected.as_ref() == nonce_value
                        } else {
                            false
                        }
                    }) {
                        return Ok(true);
                    }
                }

                for source in directive.sources() {
                    if let Source::Hash { algorithm, value } = source {
                        let calculated =
                            crate::security::hash::HashGenerator::generate(*algorithm, content);
                        if calculated == value.as_ref() {
                            return Ok(true);
                        }
                    }
                }

                Ok(false)
            } else {
                Ok(true)
            }
        }

        pub fn verify_inline_style(
            &self,
            content: &[u8],
            nonce: Option<&str>,
        ) -> Result<bool, CspError> {
            let directive_name = "style-src";
            let default_name = "default-src";

            let directive = self
                .policy
                .get_directive(directive_name)
                .or_else(|| self.policy.get_directive(default_name));

            if let Some(directive) = directive {
                if directive.sources().iter().any(|s| s.is_none()) {
                    return Ok(false);
                }

                if directive.sources().iter().any(|s| s.is_unsafe_inline()) {
                    return Ok(true);
                }

                if let Some(nonce_value) = nonce {
                    if directive.sources().iter().any(|s| {
                        if let Source::Nonce(expected) = s {
                            expected.as_ref() == nonce_value
                        } else {
                            false
                        }
                    }) {
                        return Ok(true);
                    }
                }

                for source in directive.sources() {
                    if let Source::Hash { algorithm, value } = source {
                        let calculated =
                            crate::security::hash::HashGenerator::generate(*algorithm, content);
                        if calculated == value.as_ref() {
                            return Ok(true);
                        }
                    }
                }

                Ok(false)
            } else {
                Ok(true)
            }
        }

        pub fn blocks_inline_scripts(&self) -> Result<bool, CspError> {
            let directive = self
                .policy
                .get_directive("script-src")
                .or_else(|| self.policy.get_directive("default-src"));

            if let Some(directive) = directive {
                Ok(!directive.sources().iter().any(|s| s.is_unsafe_inline()))
            } else {
                Ok(true)
            }
        }

        pub fn allows_unsafe_eval(&self) -> bool {
            let directive = self
                .policy
                .get_directive("script-src")
                .or_else(|| self.policy.get_directive("default-src"));

            if let Some(directive) = directive {
                directive.sources().iter().any(|s| s.is_unsafe_eval())
            } else {
                false
            }
        }

        pub fn has_report_uri(&self) -> bool {
            self.policy.report_uri().is_some()
        }

        pub fn has_report_to(&self) -> bool {
            self.policy.report_to().is_some()
        }

        pub fn has_directive(&self, directive_name: &str) -> bool {
            self.policy.get_directive(directive_name).is_some()
        }
    }
}

#[cfg(not(feature = "verify"))]
mod imp {
    use super::*;

    pub struct PolicyVerifier {
        policy: CspPolicy,
    }

    impl PolicyVerifier {
        #[inline]
        pub fn new(policy: CspPolicy) -> Self {
            Self { policy }
        }

        pub fn with_origin(
            policy: CspPolicy,
            _origin: impl AsRef<str>,
        ) -> Result<Self, CspError> {
            Ok(Self::new(policy))
        }

        pub fn set_origin(&mut self, _origin: impl AsRef<str>) -> Result<(), CspError> {
            Ok(())
        }

        #[inline]
        pub fn policy(&self) -> &CspPolicy {
            &self.policy
        }

        #[inline]
        pub fn policy_mut(&mut self) -> &mut CspPolicy {
            &mut self.policy
        }

        #[inline]
        pub fn clear_caches(&mut self) {}

        #[inline]
        pub fn verify_uri(
            &mut self,
            _uri: &str,
            _directive_name: &str,
        ) -> Result<bool, CspError> {
            Err(CspError::ConfigError(
                "Policy verification is disabled. Rebuild with the `verify` feature enabled."
                    .to_string(),
            ))
        }

        #[inline]
        pub fn verify_hash(
            &self,
            _content: &[u8],
            _directive_name: &str,
        ) -> Result<bool, CspError> {
            Err(CspError::ConfigError(
                "Hash verification is disabled. Rebuild with the `verify` feature enabled."
                    .to_string(),
            ))
        }

        #[inline]
        pub fn verify_nonce(
            &self,
            _nonce: &str,
            _directive_name: &str,
        ) -> Result<bool, CspError> {
            Err(CspError::ConfigError(
                "Nonce verification is disabled. Rebuild with the `verify` feature enabled."
                    .to_string(),
            ))
        }

        #[inline]
        pub fn verify_inline_script(
            &self,
            _content: &[u8],
            _nonce: Option<&str>,
        ) -> Result<bool, CspError> {
            Err(CspError::ConfigError(
                "Inline script verification is disabled. Rebuild with the `verify` feature enabled."
                    .to_string(),
            ))
        }

        #[inline]
        pub fn verify_inline_style(
            &self,
            _content: &[u8],
            _nonce: Option<&str>,
        ) -> Result<bool, CspError> {
            Err(CspError::ConfigError(
                "Inline style verification is disabled. Rebuild with the `verify` feature enabled."
                    .to_string(),
            ))
        }

        pub fn blocks_inline_scripts(&self) -> Result<bool, CspError> {
            let directive = self
                .policy
                .get_directive("script-src")
                .or_else(|| self.policy.get_directive("default-src"));

            Ok(match directive {
                Some(directive) => !directive.sources().iter().any(|s| s.is_unsafe_inline()),
                None => true,
            })
        }

        pub fn allows_unsafe_eval(&self) -> bool {
            let directive = self
                .policy
                .get_directive("script-src")
                .or_else(|| self.policy.get_directive("default-src"));

            match directive {
                Some(directive) => directive.sources().iter().any(|s| s.is_unsafe_eval()),
                None => false,
            }
        }

        pub fn has_report_uri(&self) -> bool {
            self.policy.report_uri().is_some()
        }

        pub fn has_report_to(&self) -> bool {
            self.policy.report_to().is_some()
        }

        pub fn has_directive(&self, directive_name: &str) -> bool {
            self.policy.get_directive(directive_name).is_some()
        }
    }
}

pub use imp::PolicyVerifier;
