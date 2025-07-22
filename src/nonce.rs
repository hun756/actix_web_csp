use crate::constants::{DEFAULT_NONCE_LENGTH, NONCE_BUFFER_POOL_SIZE};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64, Engine};
use getrandom::getrandom;
use parking_lot::Mutex;
use smallvec::SmallVec;
use std::{
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};

#[derive(Debug)]
pub struct NonceGenerator {
    length: AtomicUsize,
    buffer_pool: Arc<Mutex<SmallVec<[Vec<u8>; NONCE_BUFFER_POOL_SIZE]>>>,
    string_pool: Arc<Mutex<SmallVec<[String; NONCE_BUFFER_POOL_SIZE]>>>,
    stats: Arc<NonceStats>,
    last_cleanup: Arc<AtomicU64>,
}

#[derive(Debug, Default)]
struct NonceStats {
    generated: AtomicUsize,
    buffer_hits: AtomicUsize,
    buffer_misses: AtomicUsize,
}

impl Clone for NonceGenerator {
    fn clone(&self) -> Self {
        Self {
            length: AtomicUsize::new(self.length.load(Ordering::Relaxed)),
            buffer_pool: self.buffer_pool.clone(),
            string_pool: self.string_pool.clone(),
            stats: self.stats.clone(),
            last_cleanup: self.last_cleanup.clone(),
        }
    }
}

impl NonceGenerator {
    #[inline]
    pub fn new(length: usize) -> Self {
        Self {
            length: AtomicUsize::new(length),
            buffer_pool: Arc::new(Mutex::new(SmallVec::new())),
            string_pool: Arc::new(Mutex::new(SmallVec::new())),
            stats: Arc::new(NonceStats::default()),
            last_cleanup: Arc::new(AtomicU64::new(0)),
        }
    }

    #[inline]
    pub fn generate(&self) -> String {
        self.stats.generated.fetch_add(1, Ordering::Relaxed);
        self.maybe_cleanup_pools();

        let length = self.length.load(Ordering::Relaxed);
        let mut buffer = {
            let mut pool = self.buffer_pool.lock();
            if let Some(mut buf) = pool.pop() {
                self.stats.buffer_hits.fetch_add(1, Ordering::Relaxed);
                buf.clear();
                buf.resize(length, 0);
                buf
            } else {
                self.stats.buffer_misses.fetch_add(1, Ordering::Relaxed);
                vec![0u8; length]
            }
        };

        getrandom(&mut buffer).expect("Failed to generate random bytes");
        let encoded = BASE64.encode(&buffer);

        {
            let mut pool = self.buffer_pool.lock();
            if pool.len() < NONCE_BUFFER_POOL_SIZE {
                pool.push(buffer);
            }
        }

        encoded
    }

    #[inline]
    fn maybe_cleanup_pools(&self) {
        let now = Instant::now().elapsed().as_secs();
        let last_cleanup = self.last_cleanup.load(Ordering::Relaxed);

        if now.saturating_sub(last_cleanup) > 300 {
            if self
                .last_cleanup
                .compare_exchange_weak(last_cleanup, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                self.cleanup_pools();
            }
        }
    }

    fn cleanup_pools(&self) {
        {
            let mut buffer_pool = self.buffer_pool.lock();
            buffer_pool.retain(|buf| buf.capacity() <= 1024);
            buffer_pool.shrink_to_fit();
        }

        {
            let mut string_pool = self.string_pool.lock();
            string_pool.retain(|s| s.capacity() <= 256);
            string_pool.shrink_to_fit();
        }
    }

    #[inline]
    pub fn set_length(&self, length: usize) {
        self.length.store(length, Ordering::Relaxed);
    }

    #[inline]
    pub fn length(&self) -> usize {
        self.length.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn default() -> Self {
        Self::new(DEFAULT_NONCE_LENGTH)
    }

    #[inline]
    pub fn with_capacity(capacity: usize, length: usize) -> Self {
        let buffer_pool = Arc::new(Mutex::new({
            let mut buffers = SmallVec::new();
            for _ in 0..capacity.min(NONCE_BUFFER_POOL_SIZE) {
                buffers.push(vec![0u8; length]);
            }
            buffers
        }));

        Self {
            length: AtomicUsize::new(length),
            buffer_pool,
            string_pool: Arc::new(Mutex::new(SmallVec::new())),
            stats: Arc::new(NonceStats::default()),
            last_cleanup: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Default for NonceGenerator {
    fn default() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone)]
pub struct RequestNonce(pub String);

impl Deref for RequestNonce {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RequestNonce {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
