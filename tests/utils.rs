use actix_web_csp::utils::intern_string;
use bytes::BytesMut;
use std::time::Duration;

#[derive(Debug, Clone)]
struct TestCachedValue<T> {
    value: T,
    timestamp: std::time::Instant,
    ttl: Duration,
}

impl<T> TestCachedValue<T> {
    fn new(value: T, ttl: Duration) -> Self {
        Self {
            value,
            timestamp: std::time::Instant::now(),
            ttl,
        }
    }

    fn is_valid(&self) -> bool {
        self.timestamp.elapsed() < self.ttl
    }

    fn value(&self) -> &T {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intern_string_common_values() {
        assert!(intern_string("'self'").is_some());
        assert!(intern_string("'none'").is_some());
        assert!(intern_string("'unsafe-inline'").is_some());
        assert!(intern_string("'unsafe-eval'").is_some());
        assert!(intern_string("'strict-dynamic'").is_some());

        assert!(intern_string("default-src").is_some());
        assert!(intern_string("script-src").is_some());
        assert!(intern_string("style-src").is_some());
        assert!(intern_string("img-src").is_some());

        assert!(intern_string("https:").is_some());
        assert!(intern_string("http:").is_some());
        assert!(intern_string("data:").is_some());
        assert!(intern_string("blob:").is_some());
    }

    #[test]
    fn test_intern_string_uncommon_values() {
        assert!(intern_string("custom-value").is_none());
        assert!(intern_string("example.com").is_none());
        assert!(intern_string("random-string").is_none());
    }

    #[test]
    fn test_intern_string_returns_same_reference() {
        let interned1 = intern_string("'self'").unwrap();
        let interned2 = intern_string("'self'").unwrap();

        assert_eq!(interned1.as_ptr(), interned2.as_ptr());
    }

    #[test]
    fn test_intern_string_case_sensitive() {
        assert!(intern_string("'SELF'").is_none());
        assert!(intern_string("'Self'").is_none());
        assert!(intern_string("'self'").is_some());
    }

    #[test]
    fn test_cached_value_creation() {
        let value = "test_value";
        let ttl = Duration::from_secs(60);
        let cached = TestCachedValue::new(value, ttl);

        assert_eq!(cached.value(), &value);
        assert!(cached.is_valid());
    }

    #[test]
    fn test_cached_value_expiration() {
        let value = "test_value";
        let ttl = Duration::from_millis(1);
        let cached = TestCachedValue::new(value, ttl);

        assert!(cached.is_valid());

        std::thread::sleep(Duration::from_millis(10));

        assert!(!cached.is_valid());
    }

    #[test]
    fn test_cached_value_clone() {
        let value = "test_value";
        let ttl = Duration::from_secs(60);
        let cached1 = TestCachedValue::new(value, ttl);
        let cached2 = cached1.clone();

        assert_eq!(cached1.value(), cached2.value());
        assert!(cached1.is_valid());
        assert!(cached2.is_valid());
    }

    #[test]
    fn test_cached_value_different_types() {
        let string_cached = TestCachedValue::new("string".to_string(), Duration::from_secs(60));
        let int_cached = TestCachedValue::new(42i32, Duration::from_secs(60));
        let vec_cached = TestCachedValue::new(vec![1, 2, 3], Duration::from_secs(60));

        assert_eq!(string_cached.value(), &"string".to_string());
        assert_eq!(int_cached.value(), &42i32);
        assert_eq!(vec_cached.value(), &vec![1, 2, 3]);
    }

    #[test]
    fn test_intern_string_all_common_strings() {
        let common_strings = [
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

        for &common_str in &common_strings {
            assert!(
                intern_string(common_str).is_some(),
                "String '{}' should be interned",
                common_str
            );
        }
    }

    #[test]
    fn test_intern_string_performance() {
        let test_string = "'self'";

        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = intern_string(test_string);
        }
        let duration = start.elapsed();

        assert!(duration < Duration::from_millis(1));
    }

    #[test]
    fn test_intern_string_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let handles: Vec<_> = (0..10)
            .map(|_| {
                thread::spawn(|| {
                    for _ in 0..100 {
                        let result = intern_string("'self'");
                        assert!(result.is_some());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_cached_value_zero_ttl() {
        let value = "test";
        let cached = TestCachedValue::new(value, Duration::from_secs(0));

        assert!(!cached.is_valid());
    }

    #[test]
    fn test_cached_value_long_ttl() {
        let value = "test";
        let cached = TestCachedValue::new(value, Duration::from_secs(3600));

        assert!(cached.is_valid());

        std::thread::sleep(Duration::from_millis(1));
        assert!(cached.is_valid());
    }

    #[test]
    fn test_intern_string_empty_string() {
        assert!(intern_string("").is_none());
    }

    #[test]
    fn test_intern_string_whitespace() {
        assert!(intern_string(" ").is_none());
        assert!(intern_string("\t").is_none());
        assert!(intern_string("\n").is_none());
        assert!(intern_string("  ").is_none());
    }

    #[test]
    fn test_intern_string_partial_matches() {
        assert!(intern_string("'sel").is_none());
        assert!(intern_string("self'").is_none());
        assert!(intern_string("default").is_none());
        assert!(intern_string("src").is_none());
    }
}
