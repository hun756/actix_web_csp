use crate::constants::DEFAULT_POLICY_CACHE_ENTRIES;
use crate::core::directives::DirectiveSpec;
use crate::core::policy::CspPolicy;
use crate::monitoring::perf::PerformanceMetrics;
use crate::monitoring::stats::CspStats;
use crate::security::nonce::NonceGenerator;
use dashmap::DashMap;
use lru::LruCache;
use parking_lot::RwLock;
use std::num::{NonZeroU64, NonZeroUsize};
use std::{
    borrow::Cow,
    sync::{
        atomic::{AtomicBool, AtomicUsize},
        Arc,
    },
    time::Duration,
};

type UpdateFn = Box<dyn Fn(&mut CspPolicy) + Send + Sync + 'static>;

#[derive(Clone)]
pub struct CspConfig {
    policy: Arc<RwLock<CspPolicy>>,
    nonce_generator: Option<Arc<NonceGenerator>>,
    nonce_per_request: Arc<AtomicBool>,
    per_request_nonces: Arc<DashMap<String, String>>,
    nonce_request_header: Option<Cow<'static, str>>,
    cache_duration: Arc<AtomicUsize>,
    stats: Arc<CspStats>,
    perf_metrics: Arc<PerformanceMetrics>,
    update_listeners: Arc<DashMap<usize, UpdateFn>>,
    next_listener_id: Arc<AtomicUsize>,
    policy_cache: Arc<RwLock<LruCache<NonZeroU64, Arc<CspPolicy>>>>,
}

impl CspConfig {
    pub fn new(policy: CspPolicy) -> Self {
        Self {
            policy: Arc::new(RwLock::new(policy)),
            nonce_generator: None,
            nonce_per_request: Arc::new(AtomicBool::new(false)),
            per_request_nonces: Arc::new(DashMap::new()),
            nonce_request_header: None,
            cache_duration: Arc::new(AtomicUsize::new(60)),
            stats: Arc::new(CspStats::new()),
            perf_metrics: Arc::new(PerformanceMetrics::new()),
            update_listeners: Arc::new(DashMap::new()),
            next_listener_id: Arc::new(AtomicUsize::new(0)),
            policy_cache: Arc::new(RwLock::new(LruCache::new(
                NonZeroUsize::new(DEFAULT_POLICY_CACHE_ENTRIES).unwrap(),
            ))),
        }
    }

    pub fn update_policy<F>(&self, f: F)
    where
        F: FnOnce(&mut CspPolicy),
    {
        {
            let mut policy_guard = self.policy.write();
            f(&mut policy_guard);
        }

        if !self.update_listeners.is_empty() {
            for listener in self.update_listeners.iter() {
                let mut policy = self.policy.write();
                listener.value()(&mut policy);
            }
        }

        self.policy_cache.write().clear();
        self.stats.increment_policy_update_count();
    }

    #[inline]
    pub fn policy(&self) -> Arc<RwLock<CspPolicy>> {
        self.policy.clone()
    }

    pub fn generate_nonce(&self) -> Option<String> {
        if let Some(generator) = &self.nonce_generator {
            self.stats.increment_nonce_generation_count();
            Some(generator.generate())
        } else {
            None
        }
    }

    pub fn get_or_generate_request_nonce(&self, request_id: &str) -> Option<String> {
        if !self
            .nonce_per_request
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return None;
        }

        let generator = self.nonce_generator.as_ref()?;

        Some(
            self.per_request_nonces
                .entry(request_id.to_string())
                .or_insert_with(|| {
                    self.stats.increment_nonce_generation_count();
                    generator.generate()
                })
                .value()
                .clone(),
        )
    }

    #[inline]
    pub fn stats(&self) -> &Arc<CspStats> {
        &self.stats
    }

    #[inline]
    pub fn perf_metrics(&self) -> &Arc<PerformanceMetrics> {
        &self.perf_metrics
    }

    pub fn add_update_listener<F>(&self, f: F) -> usize
    where
        F: Fn(&mut CspPolicy) + Send + Sync + 'static,
    {
        let id = self
            .next_listener_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.update_listeners.insert(id, Box::new(f));
        id
    }

    #[inline]
    pub fn remove_update_listener(&self, id: usize) -> bool {
        self.update_listeners.remove(&id).is_some()
    }

    #[inline]
    pub fn clear_request_nonces(&self) {
        self.per_request_nonces.clear();
    }

    #[inline]
    pub fn cache_duration(&self) -> Duration {
        Duration::from_secs(
            self.cache_duration
                .load(std::sync::atomic::Ordering::Relaxed) as u64,
        )
    }

    pub fn get_cached_policy(&self, hash: NonZeroU64) -> Option<Arc<CspPolicy>> {
        let mut cache = self.policy_cache.write();
        cache.get(&hash).cloned()
    }

    pub fn cache_policy(&self, hash: NonZeroU64, policy: CspPolicy) -> Arc<CspPolicy> {
        let policy_arc = Arc::new(policy);
        let mut cache = self.policy_cache.write();
        cache.put(hash, policy_arc.clone());
        policy_arc
    }

    pub fn with_default_directives(self) -> Self {
        {
            let mut policy = self.policy.write();
            if !policy.get_directive("default-src").is_some() {
                use crate::core::directives::DefaultSrc;
                use crate::core::source::Source;
                let directive = DefaultSrc::new().add_source(Source::Self_).build();
                policy.add_directive(directive);
            }

            if !policy.get_directive("object-src").is_some() {
                use crate::core::directives::ObjectSrc;
                use crate::core::source::Source;
                let directive = ObjectSrc::new().add_source(Source::None).build();
                policy.add_directive(directive);
            }
        }
        self
    }
}

#[derive(Default)]
pub struct CspConfigBuilder {
    policy: Option<CspPolicy>,
    nonce_length: Option<usize>,
    nonce_per_request: bool,
    nonce_request_header: Option<Cow<'static, str>>,
    cache_duration: Option<Duration>,
    cache_size: Option<usize>,
    nonce_generator: Option<Arc<NonceGenerator>>,
}

impl CspConfigBuilder {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn policy(mut self, policy: CspPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    #[inline]
    pub fn with_nonce_generator(mut self, length: usize) -> Self {
        self.nonce_length = Some(length);
        self
    }

    #[inline]
    pub fn with_prebuilt_nonce_generator(mut self, generator: Arc<NonceGenerator>) -> Self {
        self.nonce_generator = Some(generator);
        self
    }

    #[inline]
    pub fn with_nonce_per_request(mut self, enabled: bool) -> Self {
        self.nonce_per_request = enabled;
        self
    }

    #[inline]
    pub fn with_nonce_request_header(mut self, header: impl Into<Cow<'static, str>>) -> Self {
        self.nonce_request_header = Some(header.into());
        self
    }

    #[inline]
    pub fn with_cache_duration(mut self, duration: Duration) -> Self {
        self.cache_duration = Some(duration);
        self
    }

    #[inline]
    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache_size = Some(size);
        self
    }

    pub fn build(self) -> CspConfig {
        let policy = self.policy.unwrap_or_default();
        let mut config = CspConfig::new(policy);

        if let Some(generator) = self.nonce_generator {
            config.nonce_generator = Some(generator);
        } else if let Some(length) = self.nonce_length {
            config.nonce_generator = Some(Arc::new(NonceGenerator::with_capacity(32, length)));
        }

        if self.nonce_per_request {
            config
                .nonce_per_request
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }

        if let Some(header) = self.nonce_request_header {
            config.nonce_request_header = Some(header);
        }

        if let Some(duration) = self.cache_duration {
            config.cache_duration.store(
                duration.as_secs() as usize,
                std::sync::atomic::Ordering::Relaxed,
            );
        }

        if let Some(size) = self.cache_size {
            if let Some(non_zero) = NonZeroUsize::new(size) {
                config.policy_cache = Arc::new(RwLock::new(LruCache::new(non_zero)));
            }
        }

        config
    }
}
