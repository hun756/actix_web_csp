use crate::error::CspError;
use crate::policy::CspPolicy;
use crate::source::Source;
use rustc_hash::FxHashSet;
use std::collections::HashMap;
use url::Url;

pub struct PolicyVerifier {
    policy: CspPolicy,
    url_cache: HashMap<String, Url>,
    host_cache: FxHashSet<String>,
    verification_cache: lru::LruCache<u64, bool>,
}

impl PolicyVerifier {
    #[inline]
    pub fn new(policy: CspPolicy) -> Self {
        Self {
            policy,
            url_cache: HashMap::with_capacity(256),
            host_cache: FxHashSet::with_capacity_and_hasher(128, Default::default()),
            verification_cache: lru::LruCache::new(std::num::NonZeroUsize::new(512).unwrap()),
        }
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

        let uri_url = if let Some(cached) = self.url_cache.get(uri) {
            cached
        } else {
            match Url::parse(uri) {
                Ok(url) => {
                    if self.url_cache.len() < 256 {
                        self.url_cache.insert(uri.to_string(), url.clone());
                    }
                    &self.url_cache[uri]
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

        let uri_scheme = uri_url.scheme();
        let uri_host = uri_url.host_str();

        for source in sources {
            match source {
                Source::None => {
                    let result = false;
                    self.verification_cache.put(cache_key, result);
                    return Ok(result);
                }
                Source::Self_ => {
                    if self.is_same_origin(uri_url) {
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
                            if host_str.len() > domain.len() && host_str.ends_with(domain) {
                                let prefix_len = host_str.len() - domain.len();
                                let prefix = &host_str[..prefix_len];
                                if !prefix.contains('.') && prefix.ends_with('.') {
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
                let calculated = crate::hash::HashGenerator::generate(*algorithm, content);
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
        if let Some(directive) = self.policy.get_directive("origin") {
            for source in directive.sources() {
                if let Source::Host(host) = source {
                    if let Some(url_host) = url.host_str() {
                        if url_host == host.as_ref() {
                            return true;
                        }
                    }

                    if let Ok(origin_url) = Url::parse(&format!("https://{}", host)) {
                        if url.scheme() == origin_url.scheme()
                            && url.host_str() == origin_url.host_str()
                            && url.port() == origin_url.port()
                        {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    #[inline]
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
                    let calculated = crate::hash::HashGenerator::generate(*algorithm, content);
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
                    let calculated = crate::hash::HashGenerator::generate(*algorithm, content);
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
}
