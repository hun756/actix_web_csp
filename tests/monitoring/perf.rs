use actix_web_csp::monitoring::{AdaptiveCache, PerformanceMetrics, PerformanceTimer};
use std::num::NonZeroUsize;
use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_metrics_creation() {
        let metrics = PerformanceMetrics::new();

        assert_eq!(metrics.avg_header_generation_ns(), 0.0);
        assert_eq!(metrics.avg_policy_hash_ns(), 0.0);
        assert_eq!(metrics.cache_hit_rate(), 0.0);
        assert_eq!(metrics.min_header_generation_ns(), 0);
        assert_eq!(metrics.max_header_generation_ns(), 0);
    }

    #[test]
    fn test_performance_metrics_default() {
        let metrics = PerformanceMetrics::default();

        assert_eq!(metrics.avg_header_generation_ns(), 0.0);
        assert_eq!(metrics.avg_policy_hash_ns(), 0.0);
        assert_eq!(metrics.cache_hit_rate(), 0.0);
    }

    #[test]
    fn test_performance_metrics_record_header_generation() {
        let metrics = PerformanceMetrics::new();

        metrics.record_header_generation(Duration::from_nanos(1000));
        assert_eq!(metrics.avg_header_generation_ns(), 1000.0);
        assert_eq!(metrics.min_header_generation_ns(), 1000);
        assert_eq!(metrics.max_header_generation_ns(), 1000);

        metrics.record_header_generation(Duration::from_nanos(2000));
        assert_eq!(metrics.avg_header_generation_ns(), 1500.0);
        assert_eq!(metrics.min_header_generation_ns(), 1000);
        assert_eq!(metrics.max_header_generation_ns(), 2000);
    }

    #[test]
    fn test_performance_metrics_record_policy_hash() {
        let metrics = PerformanceMetrics::new();

        assert_eq!(metrics.avg_policy_hash_ns(), 0.0);

        metrics.record_policy_hash(Duration::from_nanos(500));
        assert_eq!(metrics.avg_policy_hash_ns(), 500.0);

        metrics.record_policy_hash(Duration::from_nanos(1500));
        assert_eq!(metrics.avg_policy_hash_ns(), 1000.0);
    }

    #[test]
    fn test_performance_metrics_cache_hit_rate() {
        let metrics = PerformanceMetrics::new();

        assert_eq!(metrics.cache_hit_rate(), 0.0);

        metrics.record_cache_hit();
        metrics.record_cache_hit();
        metrics.record_cache_hit();
        metrics.record_cache_miss();

        assert_eq!(metrics.cache_hit_rate(), 0.75);
    }

    #[test]
    fn test_performance_metrics_reset() {
        let metrics = PerformanceMetrics::new();

        metrics.record_header_generation(Duration::from_nanos(1000));
        metrics.record_policy_hash(Duration::from_nanos(500));
        metrics.record_cache_hit();
        metrics.record_cache_miss();

        assert!(metrics.avg_header_generation_ns() > 0.0);
        assert!(metrics.avg_policy_hash_ns() > 0.0);
        assert!(metrics.cache_hit_rate() > 0.0);

        metrics.reset();

        assert_eq!(metrics.avg_header_generation_ns(), 0.0);
        assert_eq!(metrics.avg_policy_hash_ns(), 0.0);
        assert_eq!(metrics.cache_hit_rate(), 0.0);
        assert_eq!(metrics.min_header_generation_ns(), 0);
        assert_eq!(metrics.max_header_generation_ns(), 0);
    }

    #[test]
    fn test_performance_timer_creation() {
        let timer = PerformanceTimer::new();

        let elapsed = timer.elapsed();
        assert!(elapsed >= Duration::from_nanos(0));
    }

    #[test]
    fn test_performance_timer_default() {
        let timer = PerformanceTimer::default();

        let elapsed = timer.elapsed();
        assert!(elapsed >= Duration::from_nanos(0));
    }

    #[test]
    fn test_performance_timer_elapsed() {
        let timer = PerformanceTimer::new();

        std::thread::sleep(Duration::from_millis(1));

        let elapsed = timer.elapsed();
        assert!(elapsed >= Duration::from_millis(1));
    }

    #[test]
    fn test_adaptive_cache_creation() {
        let capacity = NonZeroUsize::new(10).unwrap();
        let cache: AdaptiveCache<String, i32> = AdaptiveCache::new(capacity);

        assert_eq!(cache.hit_rate(), 0.0);
    }

    #[test]
    fn test_adaptive_cache_put_and_get() {
        let capacity = NonZeroUsize::new(3).unwrap();
        let mut cache = AdaptiveCache::new(capacity);

        cache.put("key1".to_string(), 100);

        let value = cache.get(&"key1".to_string());
        assert_eq!(value, Some(&100));

        let missing = cache.get(&"key2".to_string());
        assert_eq!(missing, None);
    }

    #[test]
    fn test_adaptive_cache_hit_rate() {
        let capacity = NonZeroUsize::new(5).unwrap();
        let mut cache = AdaptiveCache::new(capacity);

        cache.put("key1".to_string(), 100);
        cache.put("key2".to_string(), 200);

        cache.get(&"key1".to_string());
        cache.get(&"key2".to_string());

        cache.get(&"key3".to_string());
        cache.get(&"key4".to_string());

        assert_eq!(cache.hit_rate(), 0.5);
    }

    #[test]
    fn test_adaptive_cache_clear() {
        let capacity = NonZeroUsize::new(5).unwrap();
        let mut cache = AdaptiveCache::new(capacity);

        cache.put("key1".to_string(), 100);
        cache.get(&"key1".to_string());
        cache.get(&"key2".to_string());

        assert!(cache.hit_rate() > 0.0);

        cache.clear();

        assert_eq!(cache.hit_rate(), 0.0);

        assert_eq!(cache.get(&"key1".to_string()), None);
    }

    #[test]
    fn test_adaptive_cache_lru_behavior() {
        let capacity = NonZeroUsize::new(2).unwrap();
        let mut cache = AdaptiveCache::new(capacity);

        cache.put("key1".to_string(), 100);
        cache.put("key2".to_string(), 200);

        assert_eq!(cache.get(&"key1".to_string()), Some(&100));
        assert_eq!(cache.get(&"key2".to_string()), Some(&200));

        cache.put("key3".to_string(), 300);

        assert_eq!(cache.get(&"key1".to_string()), None);
        assert_eq!(cache.get(&"key2".to_string()), Some(&200));
        assert_eq!(cache.get(&"key3".to_string()), Some(&300));
    }

    #[test]
    fn test_performance_metrics_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let metrics = Arc::new(PerformanceMetrics::new());
        let mut handles = vec![];

        for i in 0..5 {
            let metrics_clone = Arc::clone(&metrics);
            let handle = thread::spawn(move || {
                for j in 0..10 {
                    let duration = Duration::from_nanos((i * 100 + j * 10) as u64);
                    metrics_clone.record_header_generation(duration);
                    metrics_clone.record_policy_hash(duration);

                    if j % 2 == 0 {
                        metrics_clone.record_cache_hit();
                    } else {
                        metrics_clone.record_cache_miss();
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert!(metrics.avg_header_generation_ns() > 0.0);
        assert!(metrics.avg_policy_hash_ns() > 0.0);
        assert_eq!(metrics.cache_hit_rate(), 0.5);
    }
}
