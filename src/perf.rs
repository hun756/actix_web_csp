use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct PerformanceMetrics {
    header_generation_samples: AtomicUsize,
    header_generation_total_ns: AtomicU64,
    header_generation_min_ns: AtomicU64,
    header_generation_max_ns: AtomicU64,

    policy_hash_samples: AtomicUsize,
    policy_hash_total_ns: AtomicU64,

    cache_hit_ratio: AtomicUsize,
    cache_miss_ratio: AtomicUsize,

    memory_pressure_events: AtomicUsize,
    gc_events: AtomicUsize,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            header_generation_samples: AtomicUsize::new(0),
            header_generation_total_ns: AtomicU64::new(0),
            header_generation_min_ns: AtomicU64::new(u64::MAX),
            header_generation_max_ns: AtomicU64::new(0),

            policy_hash_samples: AtomicUsize::new(0),
            policy_hash_total_ns: AtomicU64::new(0),

            cache_hit_ratio: AtomicUsize::new(0),
            cache_miss_ratio: AtomicUsize::new(0),

            memory_pressure_events: AtomicUsize::new(0),
            gc_events: AtomicUsize::new(0),
        }
    }
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_header_generation(&self, duration: Duration) {
        let ns = duration.as_nanos() as u64;

        self.header_generation_samples
            .fetch_add(1, Ordering::Relaxed);
        self.header_generation_total_ns
            .fetch_add(ns, Ordering::Relaxed);

        loop {
            let current_min = self.header_generation_min_ns.load(Ordering::Relaxed);
            if ns >= current_min
                || self
                    .header_generation_min_ns
                    .compare_exchange_weak(current_min, ns, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                break;
            }
        }

        loop {
            let current_max = self.header_generation_max_ns.load(Ordering::Relaxed);
            if ns <= current_max
                || self
                    .header_generation_max_ns
                    .compare_exchange_weak(current_max, ns, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                break;
            }
        }

        if ns > 1_000_000 {
            self.memory_pressure_events.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_policy_hash(&self, duration: Duration) {
        let ns = duration.as_nanos() as u64;

        self.policy_hash_samples.fetch_add(1, Ordering::Relaxed);
        self.policy_hash_total_ns.fetch_add(ns, Ordering::Relaxed);
    }

    pub fn record_cache_hit(&self) {
        self.cache_hit_ratio.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_miss_ratio.fetch_add(1, Ordering::Relaxed);
    }

    pub fn avg_header_generation_ns(&self) -> f64 {
        let samples = self.header_generation_samples.load(Ordering::Relaxed);
        if samples == 0 {
            0.0
        } else {
            self.header_generation_total_ns.load(Ordering::Relaxed) as f64 / samples as f64
        }
    }

    pub fn avg_policy_hash_ns(&self) -> f64 {
        let samples = self.policy_hash_samples.load(Ordering::Relaxed);
        if samples == 0 {
            0.0
        } else {
            self.policy_hash_total_ns.load(Ordering::Relaxed) as f64 / samples as f64
        }
    }

    pub fn cache_hit_rate(&self) -> f64 {
        let hits = self.cache_hit_ratio.load(Ordering::Relaxed);
        let misses = self.cache_miss_ratio.load(Ordering::Relaxed);
        let total = hits + misses;

        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    pub fn min_header_generation_ns(&self) -> u64 {
        let min = self.header_generation_min_ns.load(Ordering::Relaxed);
        if min == u64::MAX {
            0
        } else {
            min
        }
    }

    pub fn max_header_generation_ns(&self) -> u64 {
        self.header_generation_max_ns.load(Ordering::Relaxed)
    }

    pub fn reset(&self) {
        self.header_generation_samples.store(0, Ordering::Relaxed);
        self.header_generation_total_ns.store(0, Ordering::Relaxed);
        self.header_generation_min_ns
            .store(u64::MAX, Ordering::Relaxed);
        self.header_generation_max_ns.store(0, Ordering::Relaxed);

        self.policy_hash_samples.store(0, Ordering::Relaxed);
        self.policy_hash_total_ns.store(0, Ordering::Relaxed);

        self.cache_hit_ratio.store(0, Ordering::Relaxed);
        self.cache_miss_ratio.store(0, Ordering::Relaxed);

        self.memory_pressure_events.store(0, Ordering::Relaxed);
        self.gc_events.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub struct PerformanceTimer {
    start: Instant,
}

impl PerformanceTimer {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

impl Default for PerformanceTimer {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AdaptiveCache<K, V> {
    cache: lru::LruCache<K, V>,
    hit_count: AtomicUsize,
    miss_count: AtomicUsize,
    last_resize: Instant,
    resize_threshold: usize,
}

impl<K: std::hash::Hash + Eq, V> AdaptiveCache<K, V> {
    pub fn new(capacity: std::num::NonZeroUsize) -> Self {
        Self {
            cache: lru::LruCache::new(capacity),
            hit_count: AtomicUsize::new(0),
            miss_count: AtomicUsize::new(0),
            last_resize: Instant::now(),
            resize_threshold: 1000,
        }
    }

    pub fn get(&mut self, key: &K) -> Option<&V> {
        let is_hit = self.cache.contains(key);
        if is_hit {
            self.hit_count.fetch_add(1, Ordering::Relaxed);
            self.cache.get(key)
        } else {
            self.miss_count.fetch_add(1, Ordering::Relaxed);
            self.maybe_resize();
            None
        }
    }

    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        self.cache.put(key, value)
    }

    pub fn hit_rate(&self) -> f64 {
        let hits = self.hit_count.load(Ordering::Relaxed);
        let misses = self.miss_count.load(Ordering::Relaxed);
        let total = hits + misses;

        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    fn maybe_resize(&mut self) {
        let total_requests =
            self.hit_count.load(Ordering::Relaxed) + self.miss_count.load(Ordering::Relaxed);

        if total_requests % self.resize_threshold == 0
            && self.last_resize.elapsed() > Duration::from_secs(60)
        {
            let hit_rate = self.hit_rate();
            if hit_rate < 0.7 && self.cache.cap().get() < 512 {
                let new_cap = (self.cache.cap().get() * 2).min(512);
                if let Some(new_capacity) = std::num::NonZeroUsize::new(new_cap) {
                    self.cache.resize(new_capacity);
                    self.last_resize = Instant::now();
                }
            }
        }
    }

    pub fn clear(&mut self) {
        self.cache.clear();
        self.hit_count.store(0, Ordering::Relaxed);
        self.miss_count.store(0, Ordering::Relaxed);
    }
}
