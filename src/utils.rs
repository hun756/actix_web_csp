use bytes::BytesMut;
use parking_lot::Mutex;
use smallvec::SmallVec;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(crate) struct BytesCache<const N: usize> {
    buffers: SmallVec<[BytesMut; N]>,
    hit_count: usize,
    miss_count: usize,
}

impl<const N: usize> BytesCache<N> {
    #[inline]
    pub fn new() -> Self {
        Self {
            buffers: SmallVec::new(),
            hit_count: 0,
            miss_count: 0,
        }
    }

    #[inline]
    pub fn get(&mut self, capacity: usize) -> BytesMut {
        if let Some(mut buf) = self.buffers.pop() {
            self.hit_count += 1;
            buf.clear();
            if buf.capacity() < capacity {
                buf.reserve(capacity.saturating_sub(buf.capacity()));
            }
            buf
        } else {
            self.miss_count += 1;
            BytesMut::with_capacity(capacity.max(1024))
        }
    }

    #[inline]
    pub fn recycle(&mut self, mut buffer: BytesMut) {
        if self.buffers.len() < N && buffer.capacity() >= 512 {
            buffer.clear();
            self.buffers.push(buffer);
        }
    }
}

impl<const N: usize> Default for BytesCache<N> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) trait BufferWriter {
    fn write_to_buffer(&self, buffer: &mut BytesMut);
}

#[derive(Debug, Clone)]
pub(crate) struct CachedValue<T> {
    value: T,
    timestamp: Instant,
    ttl: Duration,
}

impl<T> CachedValue<T> {
    #[inline]
    pub fn new(value: T, ttl: Duration) -> Self {
        Self {
            value,
            timestamp: Instant::now(),
            ttl,
        }
    }

    #[inline]
    pub fn is_valid(&self) -> bool {
        self.timestamp.elapsed() < self.ttl
    }

    #[inline]
    pub fn value(&self) -> &T {
        &self.value
    }
}

use rustc_hash::FxHashMap;
use std::sync::OnceLock;

static COMMON_STRINGS: &[&str] = &[
    "'self'",
    "'none'",
    "'unsafe-inline'",
    "'unsafe-eval'",
    "'strict-dynamic'",
    "'report-sample'",
    "'wasm-unsafe-eval'",
    "'unsafe-hashes'",
    "https:",
    "http:",
    "data:",
    "blob:",
    "filesystem:",
    "ws:",
    "wss:",
    "'unsafe-allow-redirects'",
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "connect-src",
    "font-src",
    "object-src",
    "media-src",
    "frame-src",
    "worker-src",
    "manifest-src",
    "child-src",
    "frame-ancestors",
    "base-uri",
    "form-action",
    "sandbox",
];

static STRING_INTERN_MAP: OnceLock<FxHashMap<&'static str, &'static str>> = OnceLock::new();

#[inline]
pub fn intern_string(s: &str) -> Option<&'static str> {
    let map = STRING_INTERN_MAP.get_or_init(|| {
        let mut map = FxHashMap::with_capacity_and_hasher(COMMON_STRINGS.len(), Default::default());
        for &common in COMMON_STRINGS {
            map.insert(common, common);
        }
        map
    });
    map.get(s).copied()
}

pub struct PooledItem<T> {
    item: Option<T>,
    pool: Arc<Mutex<SmallVec<[T; 64]>>>,
    reset_fn: fn(&mut T),
    max_size: usize,
}

impl<T> std::ops::Deref for PooledItem<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe { self.item.as_ref().unwrap_unchecked() }
    }
}

impl<T> std::ops::DerefMut for PooledItem<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.item.as_mut().unwrap_unchecked() }
    }
}

impl<T> Drop for PooledItem<T> {
    fn drop(&mut self) {
        if let Some(mut item) = self.item.take() {
            (self.reset_fn)(&mut item);
            let mut pool = self.pool.lock();
            if pool.len() < self.max_size {
                pool.push(item);
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

pub struct FastStringBuilder {
    buffer: BytesMut,
}

impl FastStringBuilder {
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(capacity),
        }
    }

    #[inline]
    pub fn push_str(&mut self, s: &str) {
        self.buffer.extend_from_slice(s.as_bytes());
    }

    #[inline]
    pub fn push_static(&mut self, s: &'static str) {
        self.buffer.extend_from_slice(s.as_bytes());
    }

    #[inline]
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    #[inline]
    pub fn push_char(&mut self, c: char) {
        let mut buf = [0; 4];
        let s = c.encode_utf8(&mut buf);
        self.buffer.extend_from_slice(s.as_bytes());
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    #[inline]
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    #[inline]
    pub fn finish(self) -> BytesMut {
        self.buffer
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        self.buffer.reserve(additional);
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn simd_copy_aligned(src: &[u8], dst: &mut [u8]) {
        if src.len() >= 32 && dst.len() >= 32 {
            let chunks = src.len() / 32;
            for i in 0..chunks {
                let src_ptr = src.as_ptr().add(i * 32);
                let dst_ptr = dst.as_mut_ptr().add(i * 32);
                let data = _mm256_loadu_si256(src_ptr as *const __m256i);
                _mm256_storeu_si256(dst_ptr as *mut __m256i, data);
            }

            let remainder = src.len() % 32;
            if remainder > 0 {
                let start = chunks * 32;
                dst[start..start + remainder].copy_from_slice(&src[start..start + remainder]);
            }
        } else {
            dst[..src.len()].copy_from_slice(src);
        }
    }

    #[inline]
    pub fn fast_bulk_copy(&mut self, sources: &[&[u8]]) {
        let total_len: usize = sources.iter().map(|s| s.len()).sum();
        self.reserve(total_len);

        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") && total_len >= 128 {
                for &src in sources {
                    if src.len() >= 32 {
                        let remaining_capacity = self.buffer.capacity() - self.buffer.len();
                        if remaining_capacity >= src.len() {
                            let dst_start = self.buffer.len();
                            self.buffer.resize(dst_start + src.len(), 0);
                            let dst_slice = &mut self.buffer[dst_start..dst_start + src.len()];
                            unsafe {
                                Self::simd_copy_aligned(src, dst_slice);
                            }
                            continue;
                        }
                    }
                    self.buffer.extend_from_slice(src);
                }
                return;
            }
        }

        for &src in sources {
            self.buffer.extend_from_slice(src);
        }
    }
}

impl Default for FastStringBuilder {
    #[inline]
    fn default() -> Self {
        Self::with_capacity(1024)
    }
}

#[derive(Debug, Clone)]
pub struct CompactString {
    data: SmallVec<[u8; 24]>,
}

impl CompactString {
    #[inline]
    pub fn new() -> Self {
        Self {
            data: SmallVec::new(),
        }
    }

    #[inline]
    pub fn from_str(s: &str) -> Self {
        let mut data = SmallVec::new();
        data.extend_from_slice(s.as_bytes());
        Self { data }
    }

    #[inline]
    pub fn from_static(s: &'static str) -> Self {
        Self::from_str(s)
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(&self.data) }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    #[inline]
    pub fn push_str(&mut self, s: &str) {
        self.data.extend_from_slice(s.as_bytes());
    }

    #[inline]
    pub fn clear(&mut self) {
        self.data.clear();
    }

    #[inline]
    pub fn is_inline(&self) -> bool {
        self.data.spilled()
    }
}

impl Default for CompactString {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for CompactString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq<str> for CompactString {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for CompactString {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq for CompactString {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl Eq for CompactString {}

impl std::hash::Hash for CompactString {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}

#[inline]
pub fn fast_string_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    #[cfg(target_arch = "x86_64")]
    {
        if a_bytes.len() >= 32 && is_x86_feature_detected!("avx2") {
            return unsafe { simd_string_compare_avx2(a_bytes, b_bytes) };
        }
    }

    a_bytes == b_bytes
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn simd_string_compare_avx2(a: &[u8], b: &[u8]) -> bool {
    let len = a.len();
    let chunks = len / 32;

    for i in 0..chunks {
        let a_ptr = a.as_ptr().add(i * 32);
        let b_ptr = b.as_ptr().add(i * 32);

        let a_vec = _mm256_loadu_si256(a_ptr as *const __m256i);
        let b_vec = _mm256_loadu_si256(b_ptr as *const __m256i);

        let cmp = _mm256_cmpeq_epi8(a_vec, b_vec);
        let mask = _mm256_movemask_epi8(cmp);

        if mask != -1 {
            return false;
        }
    }

    let remainder = len % 32;
    if remainder > 0 {
        let start = chunks * 32;
        return a[start..].eq(&b[start..]);
    }

    true
}

pub struct AtomicCounter {
    value: AtomicUsize,
}

impl AtomicCounter {
    #[inline]
    pub const fn new(initial: usize) -> Self {
        Self {
            value: AtomicUsize::new(initial),
        }
    }

    #[inline]
    pub fn get(&self) -> usize {
        self.value.load(Ordering::Relaxed)
    }
}

impl Default for AtomicCounter {
    #[inline]
    fn default() -> Self {
        Self::new(0)
    }
}

impl std::fmt::Debug for AtomicCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtomicCounter")
            .field("value", &self.get())
            .finish()
    }
}
