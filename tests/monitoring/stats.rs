use actix_web_csp::monitoring::CspStats;
use std::thread;
use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csp_stats_creation() {
        let stats = CspStats::new();

        assert_eq!(stats.request_count(), 0);
        assert_eq!(stats.nonce_generation_count(), 0);
        assert_eq!(stats.policy_update_count(), 0);
        assert_eq!(stats.violation_count(), 0);
        assert_eq!(stats.cache_hit_count(), 0);
        assert_eq!(stats.policy_validations(), 0);
    }

    #[test]
    fn test_csp_stats_default() {
        let stats = CspStats::default();

        assert_eq!(stats.request_count(), 0);
        assert_eq!(stats.nonce_generation_count(), 0);
        assert_eq!(stats.policy_update_count(), 0);
    }

    #[test]
    fn test_csp_stats_initial_values() {
        let stats = CspStats::new();

        assert_eq!(stats.request_count(), 0);
        assert_eq!(stats.nonce_generation_count(), 0);
        assert_eq!(stats.policy_update_count(), 0);
        assert_eq!(stats.violation_count(), 0);
        assert_eq!(stats.cache_hit_count(), 0);
        assert_eq!(stats.policy_validations(), 0);
        assert_eq!(stats.avg_header_generation_time_ns(), 0.0);
        assert_eq!(stats.total_policy_hash_time_ns(), 0);
        assert_eq!(stats.total_policy_serialize_time_ns(), 0);
    }

    #[test]
    fn test_csp_stats_uptime() {
        let stats = CspStats::new();

        assert_eq!(stats.uptime_secs(), 0);

        thread::sleep(Duration::from_millis(10));

        assert_eq!(stats.uptime_secs(), 0);
    }

    #[test]
    fn test_csp_stats_requests_per_second() {
        let stats = CspStats::new();

        let initial_rps = stats.requests_per_second();
        assert!(initial_rps >= 0.0);
    }

    #[test]
    fn test_csp_stats_reset() {
        let stats = CspStats::new();

        stats.reset();

        assert_eq!(stats.request_count(), 0);
        assert_eq!(stats.nonce_generation_count(), 0);
        assert_eq!(stats.policy_update_count(), 0);
        assert_eq!(stats.violation_count(), 0);
        assert_eq!(stats.cache_hit_count(), 0);
        assert_eq!(stats.total_policy_hash_time_ns(), 0);
        assert_eq!(stats.total_policy_serialize_time_ns(), 0);
        assert_eq!(stats.policy_validations(), 0);
    }

    #[test]
    fn test_csp_stats_display() {
        let stats = CspStats::new();

        let display_str = format!("{}", stats);

        assert!(display_str.contains("CSP Middleware Statistics:"));
        assert!(display_str.contains("Uptime:"));
        assert!(display_str.contains("Requests processed:"));
        assert!(display_str.contains("Nonces generated:"));
        assert!(display_str.contains("Violations reported:"));
        assert!(display_str.contains("Policy updates:"));
        assert!(display_str.contains("Cache hits:"));
    }

    #[test]
    fn test_csp_stats_avg_header_generation_time_empty() {
        let stats = CspStats::new();

        assert_eq!(stats.avg_header_generation_time_ns(), 0.0);
    }

    #[test]
    fn test_csp_stats_debug_format() {
        let stats = CspStats::new();

        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("CspStats"));
    }

    #[test]
    fn test_csp_stats_thread_safety() {
        use std::sync::Arc;

        let stats = Arc::new(CspStats::new());
        let stats_clone = Arc::clone(&stats);

        let handle = thread::spawn(move || {
            let _count = stats_clone.request_count();
            let _uptime = stats_clone.uptime_secs();
            let _rps = stats_clone.requests_per_second();
        });

        handle.join().unwrap();

        assert_eq!(stats.request_count(), 0);
    }

    #[test]
    fn test_csp_stats_multiple_instances() {
        let stats1 = CspStats::new();
        let stats2 = CspStats::new();

        assert_eq!(stats1.request_count(), stats2.request_count());

        thread::sleep(Duration::from_millis(1));
        assert!(stats1.uptime_secs() >= 0);
        assert!(stats2.uptime_secs() >= 0);
    }
}
