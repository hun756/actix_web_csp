use crate::constants::{
    NONCE_PREFIX, NONE_SOURCE, REPORT_SAMPLE_SOURCE, SELF_SOURCE, STRICT_DYNAMIC_SOURCE,
    SUFFIX_QUOTE, UNSAFE_EVAL_SOURCE, UNSAFE_HASHES_SOURCE, UNSAFE_INLINE_SOURCE,
    WASM_UNSAFE_EVAL_SOURCE,
};
use crate::security::hash::HashAlgorithm;
use crate::utils::BufferWriter;
use bytes::BytesMut;
use std::{
    borrow::Cow,
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    None,
    Self_,
    UnsafeInline,
    UnsafeEval,
    StrictDynamic,
    ReportSample,
    WasmUnsafeEval,
    UnsafeHashes,
    Host(Cow<'static, str>),
    Scheme(Cow<'static, str>),
    Nonce(Cow<'static, str>),
    Hash {
        algorithm: HashAlgorithm,
        value: Cow<'static, str>,
    },
}

impl Source {
    #[inline(always)]
    pub const fn is_none(&self) -> bool {
        matches!(self, Source::None)
    }

    #[inline(always)]
    pub const fn is_self(&self) -> bool {
        matches!(self, Source::Self_)
    }

    #[inline(always)]
    pub const fn is_unsafe_inline(&self) -> bool {
        matches!(self, Source::UnsafeInline)
    }

    #[inline(always)]
    pub const fn is_unsafe_eval(&self) -> bool {
        matches!(self, Source::UnsafeEval)
    }

    #[inline]
    pub const fn as_static_str(&self) -> Option<&'static str> {
        match self {
            Source::None => Some(NONE_SOURCE),
            Source::Self_ => Some(SELF_SOURCE),
            Source::UnsafeInline => Some(UNSAFE_INLINE_SOURCE),
            Source::UnsafeEval => Some(UNSAFE_EVAL_SOURCE),
            Source::StrictDynamic => Some(STRICT_DYNAMIC_SOURCE),
            Source::ReportSample => Some(REPORT_SAMPLE_SOURCE),
            Source::WasmUnsafeEval => Some(WASM_UNSAFE_EVAL_SOURCE),
            Source::UnsafeHashes => Some(UNSAFE_HASHES_SOURCE),
            _ => None,
        }
    }

    #[inline]
    pub fn estimated_size(&self) -> usize {
        match self {
            Source::None => NONE_SOURCE.len(),
            Source::Self_ => SELF_SOURCE.len(),
            Source::UnsafeInline => UNSAFE_INLINE_SOURCE.len(),
            Source::UnsafeEval => UNSAFE_EVAL_SOURCE.len(),
            Source::StrictDynamic => STRICT_DYNAMIC_SOURCE.len(),
            Source::ReportSample => REPORT_SAMPLE_SOURCE.len(),
            Source::WasmUnsafeEval => WASM_UNSAFE_EVAL_SOURCE.len(),
            Source::UnsafeHashes => UNSAFE_HASHES_SOURCE.len(),
            Source::Host(host) => host.len(),
            Source::Scheme(scheme) => scheme.len() + 1,
            Source::Nonce(nonce) => NONCE_PREFIX.len() + nonce.len() + SUFFIX_QUOTE.len(),
            Source::Hash { algorithm, value } => {
                algorithm.prefix().len() + value.len() + SUFFIX_QUOTE.len()
            }
        }
    }

    #[inline]
    pub fn contains_nonce(&self) -> bool {
        matches!(self, Source::Nonce(_))
    }

    #[inline]
    pub fn contains_hash(&self) -> bool {
        matches!(self, Source::Hash { .. })
    }

    #[inline]
    pub fn scheme(&self) -> Option<&str> {
        match self {
            Source::Scheme(scheme) => Some(scheme),
            _ => None,
        }
    }

    #[inline]
    pub fn host(&self) -> Option<&str> {
        match self {
            Source::Host(host) => Some(host),
            _ => None,
        }
    }

    #[inline]
    pub fn nonce(&self) -> Option<&str> {
        match self {
            Source::Nonce(nonce) => Some(nonce),
            _ => None,
        }
    }

    #[inline]
    pub fn hash_value(&self) -> Option<(&str, HashAlgorithm)> {
        match self {
            Source::Hash { algorithm, value } => Some((value, *algorithm)),
            _ => None,
        }
    }
}

impl Hash for Source {
    fn hash<H: Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Source::None
            | Source::Self_
            | Source::UnsafeInline
            | Source::UnsafeEval
            | Source::StrictDynamic
            | Source::ReportSample
            | Source::WasmUnsafeEval
            | Source::UnsafeHashes => {}
            Source::Host(host) => host.hash(state),
            Source::Scheme(scheme) => scheme.hash(state),
            Source::Nonce(nonce) => nonce.hash(state),
            Source::Hash { algorithm, value } => {
                algorithm.hash(state);
                value.hash(state);
            }
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::None => f.write_str(NONE_SOURCE),
            Source::Self_ => f.write_str(SELF_SOURCE),
            Source::UnsafeInline => f.write_str(UNSAFE_INLINE_SOURCE),
            Source::UnsafeEval => f.write_str(UNSAFE_EVAL_SOURCE),
            Source::StrictDynamic => f.write_str(STRICT_DYNAMIC_SOURCE),
            Source::ReportSample => f.write_str(REPORT_SAMPLE_SOURCE),
            Source::WasmUnsafeEval => f.write_str(WASM_UNSAFE_EVAL_SOURCE),
            Source::UnsafeHashes => f.write_str(UNSAFE_HASHES_SOURCE),
            Source::Host(host) => f.write_str(host),
            Source::Scheme(scheme) => write!(f, "{scheme}:"),
            Source::Nonce(nonce) => write!(f, "{NONCE_PREFIX}{nonce}{SUFFIX_QUOTE}"),
            Source::Hash { algorithm, value } => {
                write!(f, "{}{}{}", algorithm.prefix(), value, SUFFIX_QUOTE)
            }
        }
    }
}

impl BufferWriter for Source {
    fn write_to_buffer(&self, buffer: &mut BytesMut) {
        match self {
            Source::None => buffer.extend_from_slice(NONE_SOURCE.as_bytes()),
            Source::Self_ => buffer.extend_from_slice(SELF_SOURCE.as_bytes()),
            Source::UnsafeInline => buffer.extend_from_slice(UNSAFE_INLINE_SOURCE.as_bytes()),
            Source::UnsafeEval => buffer.extend_from_slice(UNSAFE_EVAL_SOURCE.as_bytes()),
            Source::StrictDynamic => buffer.extend_from_slice(STRICT_DYNAMIC_SOURCE.as_bytes()),
            Source::ReportSample => buffer.extend_from_slice(REPORT_SAMPLE_SOURCE.as_bytes()),
            Source::WasmUnsafeEval => buffer.extend_from_slice(WASM_UNSAFE_EVAL_SOURCE.as_bytes()),
            Source::UnsafeHashes => buffer.extend_from_slice(UNSAFE_HASHES_SOURCE.as_bytes()),
            Source::Host(host) => {
                if let Some(interned) = crate::utils::intern_string(host) {
                    buffer.extend_from_slice(interned.as_bytes());
                } else {
                    buffer.extend_from_slice(host.as_bytes());
                }
            }
            Source::Scheme(scheme) => {
                buffer.extend_from_slice(scheme.as_bytes());
                buffer.extend_from_slice(b":");
            }
            Source::Nonce(nonce) => {
                buffer.reserve(NONCE_PREFIX.len() + nonce.len() + SUFFIX_QUOTE.len());
                buffer.extend_from_slice(NONCE_PREFIX.as_bytes());
                buffer.extend_from_slice(nonce.as_bytes());
                buffer.extend_from_slice(SUFFIX_QUOTE.as_bytes());
            }
            Source::Hash { algorithm, value } => {
                let prefix = algorithm.prefix();
                buffer.reserve(prefix.len() + value.len() + SUFFIX_QUOTE.len());
                buffer.extend_from_slice(prefix.as_bytes());
                buffer.extend_from_slice(value.as_bytes());
                buffer.extend_from_slice(SUFFIX_QUOTE.as_bytes());
            }
        }
    }
}

impl FromStr for Source {
    type Err = crate::error::CspError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();

        if value.is_empty() {
            return Err(crate::error::CspError::InvalidDirectiveValue(
                "Source value cannot be empty".to_string(),
            ));
        }

        let source = match value {
            NONE_SOURCE => Source::None,
            SELF_SOURCE => Source::Self_,
            UNSAFE_INLINE_SOURCE => Source::UnsafeInline,
            UNSAFE_EVAL_SOURCE => Source::UnsafeEval,
            STRICT_DYNAMIC_SOURCE => Source::StrictDynamic,
            REPORT_SAMPLE_SOURCE => Source::ReportSample,
            WASM_UNSAFE_EVAL_SOURCE => Source::WasmUnsafeEval,
            UNSAFE_HASHES_SOURCE => Source::UnsafeHashes,
            _ => {
                if let Some(nonce) = value
                    .strip_prefix(NONCE_PREFIX)
                    .and_then(|value| value.strip_suffix(SUFFIX_QUOTE))
                {
                    Source::Nonce(Cow::Owned(nonce.to_owned()))
                } else if let Some((algorithm, hash_value)) = parse_hash_source(value)? {
                    Source::Hash {
                        algorithm,
                        value: Cow::Owned(hash_value),
                    }
                } else if let Some(scheme) = value.strip_suffix(':') {
                    Source::Scheme(Cow::Owned(scheme.to_owned()))
                } else {
                    Source::Host(Cow::Owned(value.to_owned()))
                }
            }
        };

        Ok(source)
    }
}

impl TryFrom<&str> for Source {
    type Error = crate::error::CspError;

    #[inline]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

fn parse_hash_source(
    value: &str,
) -> Result<Option<(HashAlgorithm, String)>, crate::error::CspError> {
    for algorithm in [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ] {
        if let Some(hash_value) = value
            .strip_prefix(algorithm.prefix())
            .and_then(|value| value.strip_suffix(SUFFIX_QUOTE))
        {
            return Ok(Some((algorithm, hash_value.to_owned())));
        }
    }

    if value.starts_with("'sha") && value.ends_with(SUFFIX_QUOTE) {
        return Err(crate::error::CspError::InvalidDirectiveValue(format!(
            "Unsupported hash source: {value}"
        )));
    }

    Ok(None)
}
