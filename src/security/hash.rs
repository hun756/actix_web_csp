use crate::constants::{HASH_PREFIX_SHA256, HASH_PREFIX_SHA384, HASH_PREFIX_SHA512};
use crate::core::source::Source;
use crate::error::CspError;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ring::digest::{self, Context, SHA256, SHA384, SHA512};
use smallvec::SmallVec;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    #[inline(always)]
    pub fn digest_algorithm(&self) -> &'static digest::Algorithm {
        match self {
            HashAlgorithm::Sha256 => &SHA256,
            HashAlgorithm::Sha384 => &SHA384,
            HashAlgorithm::Sha512 => &SHA512,
        }
    }

    #[inline(always)]
    pub const fn name(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha384 => "sha384",
            HashAlgorithm::Sha512 => "sha512",
        }
    }

    #[inline(always)]
    pub const fn prefix(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => HASH_PREFIX_SHA256,
            HashAlgorithm::Sha384 => HASH_PREFIX_SHA384,
            HashAlgorithm::Sha512 => HASH_PREFIX_SHA512,
        }
    }

    #[inline]
    pub fn from_digest_algorithm(algo: &'static digest::Algorithm) -> Option<Self> {
        if algo == &SHA256 {
            Some(Self::Sha256)
        } else if algo == &SHA384 {
            Some(Self::Sha384)
        } else if algo == &SHA512 {
            Some(Self::Sha512)
        } else {
            None
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl TryFrom<&str> for HashAlgorithm {
    type Error = CspError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "sha256" => Ok(HashAlgorithm::Sha256),
            "sha384" => Ok(HashAlgorithm::Sha384),
            "sha512" => Ok(HashAlgorithm::Sha512),
            _ => Err(CspError::InvalidHashAlgorithm(s.to_string())),
        }
    }
}

thread_local! {
    static HASH_CONTEXTS: std::cell::RefCell<HashContextPool> = std::cell::RefCell::new(HashContextPool::new());
}

struct HashContextPool {
    sha256_contexts: SmallVec<[Context; 4]>,
    sha384_contexts: SmallVec<[Context; 4]>,
    sha512_contexts: SmallVec<[Context; 4]>,
}

impl HashContextPool {
    fn new() -> Self {
        Self {
            sha256_contexts: SmallVec::new(),
            sha384_contexts: SmallVec::new(),
            sha512_contexts: SmallVec::new(),
        }
    }

    fn get_context(&mut self, algorithm: HashAlgorithm) -> Context {
        match algorithm {
            HashAlgorithm::Sha256 => self
                .sha256_contexts
                .pop()
                .unwrap_or_else(|| Context::new(&SHA256)),
            HashAlgorithm::Sha384 => self
                .sha384_contexts
                .pop()
                .unwrap_or_else(|| Context::new(&SHA384)),
            HashAlgorithm::Sha512 => self
                .sha512_contexts
                .pop()
                .unwrap_or_else(|| Context::new(&SHA512)),
        }
    }

    fn return_context(&mut self, _context: Context, algorithm: HashAlgorithm) {
        match algorithm {
            HashAlgorithm::Sha256 => {
                if self.sha256_contexts.len() < 4 {
                    let new_context = Context::new(&SHA256);
                    self.sha256_contexts.push(new_context);
                }
            }
            HashAlgorithm::Sha384 => {
                if self.sha384_contexts.len() < 4 {
                    let new_context = Context::new(&SHA384);
                    self.sha384_contexts.push(new_context);
                }
            }
            HashAlgorithm::Sha512 => {
                if self.sha512_contexts.len() < 4 {
                    let new_context = Context::new(&SHA512);
                    self.sha512_contexts.push(new_context);
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct HashGenerator;

impl HashGenerator {
    #[inline]
    pub fn generate(algorithm: HashAlgorithm, data: &[u8]) -> String {
        if data.len() < 64 {
            Self::generate_small(algorithm, data)
        } else {
            Self::generate_large(algorithm, data)
        }
    }

    #[inline]
    fn generate_small(algorithm: HashAlgorithm, data: &[u8]) -> String {
        let digest = digest::digest(algorithm.digest_algorithm(), data);
        BASE64.encode(digest.as_ref())
    }

    #[inline]
    fn generate_large(algorithm: HashAlgorithm, data: &[u8]) -> String {
        HASH_CONTEXTS.with(|pool| {
            let mut pool = pool.borrow_mut();
            let mut context = pool.get_context(algorithm);

            const CHUNK_SIZE: usize = 16384;
            if data.len() > CHUNK_SIZE {
                for chunk in data.chunks(CHUNK_SIZE) {
                    context.update(chunk);
                }
            } else {
                context.update(data);
            }

            let digest = context.finish();
            let result = BASE64.encode(digest.as_ref());
            pool.return_context(Context::new(algorithm.digest_algorithm()), algorithm);
            result
        })
    }

    #[inline]
    pub fn generate_source(algorithm: HashAlgorithm, data: &[u8]) -> Source {
        let hash = Self::generate(algorithm, data);
        Source::Hash {
            algorithm,
            value: hash.into(),
        }
    }

    #[inline]
    pub fn generate_multiple(requests: &[(HashAlgorithm, &[u8])]) -> Vec<String> {
        let mut results = Vec::with_capacity(requests.len());

        HASH_CONTEXTS.with(|pool| {
            let mut pool = pool.borrow_mut();

            for &(algorithm, data) in requests {
                let mut context = pool.get_context(algorithm);
                context.update(data);
                let digest = context.finish();
                results.push(BASE64.encode(digest.as_ref()));
                pool.return_context(Context::new(algorithm.digest_algorithm()), algorithm);
            }
        });

        results
    }

    #[inline]
    pub fn verify_hash(algorithm: HashAlgorithm, data: &[u8], hash: &str) -> bool {
        let calculated = Self::generate(algorithm, data);
        crate::utils::fast_string_compare(&calculated, hash)
    }

    #[inline]
    pub fn generate_with_nonce(algorithm: HashAlgorithm, data: &[u8], nonce: &str) -> String {
        HASH_CONTEXTS.with(|pool| {
            let mut pool = pool.borrow_mut();
            let mut context = pool.get_context(algorithm);
            context.update(data);
            context.update(nonce.as_bytes());
            let digest = context.finish();
            let result = BASE64.encode(digest.as_ref());
            pool.return_context(Context::new(algorithm.digest_algorithm()), algorithm);
            result
        })
    }

    #[inline]
    pub fn batch_verify(requests: &[(HashAlgorithm, &[u8], &str)]) -> Vec<bool> {
        if requests.is_empty() {
            return Vec::new();
        }

        let mut results = Vec::with_capacity(requests.len());

        let mut sha256_requests = Vec::new();
        let mut sha384_requests = Vec::new();
        let mut sha512_requests = Vec::new();

        for (i, &(algorithm, data, expected_hash)) in requests.iter().enumerate() {
            match algorithm {
                HashAlgorithm::Sha256 => sha256_requests.push((i, data, expected_hash)),
                HashAlgorithm::Sha384 => sha384_requests.push((i, data, expected_hash)),
                HashAlgorithm::Sha512 => sha512_requests.push((i, data, expected_hash)),
            }
        }

        results.resize(requests.len(), false);

        HASH_CONTEXTS.with(|pool| {
            let mut pool = pool.borrow_mut();

            if !sha256_requests.is_empty() {
                let mut context = pool.get_context(HashAlgorithm::Sha256);
                for &(i, data, expected_hash) in &sha256_requests {
                    context.update(data);
                    let digest = context.finish();
                    let calculated = BASE64.encode(digest.as_ref());
                    results[i] = crate::utils::fast_string_compare(&calculated, expected_hash);

                    context = Context::new(&SHA256);
                }
                pool.return_context(context, HashAlgorithm::Sha256);
            }

            if !sha384_requests.is_empty() {
                let mut context = pool.get_context(HashAlgorithm::Sha384);
                for &(i, data, expected_hash) in &sha384_requests {
                    context.update(data);
                    let digest = context.finish();
                    let calculated = BASE64.encode(digest.as_ref());
                    results[i] = crate::utils::fast_string_compare(&calculated, expected_hash);

                    context = Context::new(&SHA384);
                }
                pool.return_context(context, HashAlgorithm::Sha384);
            }

            if !sha512_requests.is_empty() {
                let mut context = pool.get_context(HashAlgorithm::Sha512);
                for &(i, data, expected_hash) in &sha512_requests {
                    context.update(data);
                    let digest = context.finish();
                    let calculated = BASE64.encode(digest.as_ref());
                    results[i] = crate::utils::fast_string_compare(&calculated, expected_hash);

                    context = Context::new(&SHA512);
                }
                pool.return_context(context, HashAlgorithm::Sha512);
            }
        });

        results
    }

    #[inline]
    pub fn generate_hash(&self, content: &str) -> Result<String, CspError> {
        Ok(Self::generate(HashAlgorithm::Sha256, content.as_bytes()))
    }
}
