use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

#[derive(Debug)]
pub struct CspStats {
    request_count: AtomicUsize,
    nonce_generation_count: AtomicUsize,
    policy_update_count: AtomicUsize,
    header_generation_time_ns: AtomicUsize,
    violation_count: AtomicUsize,
    cache_hit_count: AtomicUsize,
    policy_hash_time_ns: AtomicUsize,
    policy_serialize_time_ns: AtomicUsize,
    policy_validations: AtomicUsize,
    start_time: Instant,
}

impl Default for CspStats {
    fn default() -> Self {
        Self {
            request_count: Default::default(),
            nonce_generation_count: Default::default(),
            policy_update_count: Default::default(),
            header_generation_time_ns: Default::default(),
            violation_count: Default::default(),
            cache_hit_count: Default::default(),
            policy_hash_time_ns: Default::default(),
            policy_serialize_time_ns: Default::default(),
            policy_validations: Default::default(),
            start_time: Instant::now(),
        }
    }
}

impl CspStats {
    #[inline]
    pub fn request_count(&self) -> usize {
        self.request_count.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn nonce_generation_count(&self) -> usize {
        self.nonce_generation_count.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn policy_update_count(&self) -> usize {
        self.policy_update_count.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn avg_header_generation_time_ns(&self) -> f64 {
        let count = self.request_count.load(Ordering::Relaxed);
        if count == 0 {
            0.0
        } else {
            self.header_generation_time_ns.load(Ordering::Relaxed) as f64 / count as f64
        }
    }

    #[inline]
    pub fn violation_count(&self) -> usize {
        self.violation_count.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn cache_hit_count(&self) -> usize {
        self.cache_hit_count.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn total_policy_hash_time_ns(&self) -> usize {
        self.policy_hash_time_ns.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn total_policy_serialize_time_ns(&self) -> usize {
        self.policy_serialize_time_ns.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn policy_validations(&self) -> usize {
        self.policy_validations.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    #[inline]
    pub fn requests_per_second(&self) -> f64 {
        let uptime = self.start_time.elapsed().as_secs_f64();
        if uptime > 0.0 {
            self.request_count() as f64 / uptime
        } else {
            0.0
        }
    }

    #[inline]
    pub(crate) fn increment_request_count(&self) {
        self.request_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn increment_nonce_generation_count(&self) {
        self.nonce_generation_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn increment_policy_update_count(&self) {
        self.policy_update_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn add_header_generation_time(&self, time_ns: usize) {
        self.header_generation_time_ns
            .fetch_add(time_ns, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn increment_violation_count(&self) {
        self.violation_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn increment_cache_hit_count(&self) {
        self.cache_hit_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn add_policy_hash_time(&self, time_ns: usize) {
        self.policy_hash_time_ns
            .fetch_add(time_ns, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn add_policy_serialize_time(&self, time_ns: usize) {
        self.policy_serialize_time_ns
            .fetch_add(time_ns, Ordering::Relaxed);
    }

    #[inline]
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            ..Default::default()
        }
    }

    #[inline]
    pub fn reset(&self) {
        self.request_count.store(0, Ordering::Relaxed);
        self.nonce_generation_count.store(0, Ordering::Relaxed);
        self.policy_update_count.store(0, Ordering::Relaxed);
        self.header_generation_time_ns.store(0, Ordering::Relaxed);
        self.violation_count.store(0, Ordering::Relaxed);
        self.cache_hit_count.store(0, Ordering::Relaxed);
        self.policy_hash_time_ns.store(0, Ordering::Relaxed);
        self.policy_serialize_time_ns.store(0, Ordering::Relaxed);
        self.policy_validations.store(0, Ordering::Relaxed);
    }
}

impl fmt::Display for CspStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "CSP Middleware Statistics:")?;
        writeln!(f, "  Uptime: {} seconds", self.uptime_secs())?;
        writeln!(f, "  Requests processed: {}", self.request_count())?;
        writeln!(
            f,
            "  Requests per second: {:.2}",
            self.requests_per_second()
        )?;
        writeln!(f, "  Nonces generated: {}", self.nonce_generation_count())?;
        writeln!(f, "  Policy updates: {}", self.policy_update_count())?;
        writeln!(f, "  Policy validations: {}", self.policy_validations())?;
        writeln!(
            f,
            "  Average header generation time: {:.2} ns",
            self.avg_header_generation_time_ns()
        )?;
        writeln!(
            f,
            "  Total policy hash time: {} ns",
            self.total_policy_hash_time_ns()
        )?;
        writeln!(
            f,
            "  Total policy serialize time: {} ns",
            self.total_policy_serialize_time_ns()
        )?;
        writeln!(f, "  Violations reported: {}", self.violation_count())?;
        writeln!(f, "  Cache hits: {}", self.cache_hit_count())?;
        Ok(())
    }
}
