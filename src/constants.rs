pub(crate) const HEADER_CSP: &str = "content-security-policy";
pub(crate) const HEADER_CSP_REPORT_ONLY: &str = "content-security-policy-report-only";

pub(crate) const DEFAULT_SRC: &str = "default-src";
pub(crate) const SCRIPT_SRC: &str = "script-src";
pub(crate) const STYLE_SRC: &str = "style-src";
pub(crate) const IMG_SRC: &str = "img-src";
pub(crate) const CONNECT_SRC: &str = "connect-src";
pub(crate) const FONT_SRC: &str = "font-src";
pub(crate) const OBJECT_SRC: &str = "object-src";
pub(crate) const MEDIA_SRC: &str = "media-src";
pub(crate) const FRAME_SRC: &str = "frame-src";
pub(crate) const WORKER_SRC: &str = "worker-src";
pub(crate) const MANIFEST_SRC: &str = "manifest-src";
pub(crate) const CHILD_SRC: &str = "child-src";
pub(crate) const FRAME_ANCESTORS: &str = "frame-ancestors";
pub(crate) const BASE_URI: &str = "base-uri";
pub(crate) const FORM_ACTION: &str = "form-action";
pub(crate) const SANDBOX: &str = "sandbox";
pub(crate) const SCRIPT_SRC_ELEM: &str = "script-src-elem";
pub(crate) const SCRIPT_SRC_ATTR: &str = "script-src-attr";
pub(crate) const STYLE_SRC_ELEM: &str = "style-src-elem";
pub(crate) const STYLE_SRC_ATTR: &str = "style-src-attr";
pub(crate) const PREFETCH_SRC: &str = "prefetch-src";

pub(crate) const REPORT_URI: &str = "report-uri";
pub(crate) const REPORT_TO: &str = "report-to";

pub(crate) const NONE_SOURCE: &str = "'none'";
pub(crate) const SELF_SOURCE: &str = "'self'";
pub(crate) const UNSAFE_INLINE_SOURCE: &str = "'unsafe-inline'";
pub(crate) const UNSAFE_EVAL_SOURCE: &str = "'unsafe-eval'";
pub(crate) const STRICT_DYNAMIC_SOURCE: &str = "'strict-dynamic'";
pub(crate) const REPORT_SAMPLE_SOURCE: &str = "'report-sample'";
pub(crate) const WASM_UNSAFE_EVAL_SOURCE: &str = "'wasm-unsafe-eval'";
pub(crate) const UNSAFE_HASHES_SOURCE: &str = "'unsafe-hashes'";
pub(crate) const NONCE_PREFIX: &str = "'nonce-";
pub(crate) const HASH_PREFIX_SHA256: &str = "'sha256-";
pub(crate) const HASH_PREFIX_SHA384: &str = "'sha384-";
pub(crate) const HASH_PREFIX_SHA512: &str = "'sha512-";
pub(crate) const SUFFIX_QUOTE: &str = "'";

pub(crate) const DEFAULT_NONCE_LENGTH: usize = 16;
pub(crate) const DEFAULT_CACHE_DURATION_SECS: u64 = 60;
pub(crate) const DEFAULT_MAX_REPORT_SIZE: usize = 16 * 1024;
pub(crate) const DEFAULT_REPORT_PATH: &str = "/csp-report";
pub(crate) const SEMICOLON_SPACE: &[u8] = b"; ";

pub(crate) const DEFAULT_BUFFER_CAPACITY: usize = 1024;
pub(crate) const DEFAULT_POLICY_CACHE_ENTRIES: usize = 64;
pub(crate) const NONCE_BUFFER_POOL_SIZE: usize = 32;
