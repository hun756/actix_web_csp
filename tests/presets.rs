use actix_web_csp::{preset_policy, CspPreset};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_presets_validate() {
        let presets = [
            CspPreset::Strict,
            CspPreset::Api,
            CspPreset::SinglePageApp,
            CspPreset::Dashboard,
            CspPreset::Payments,
        ];

        for preset in presets {
            let policy = preset.validated().unwrap();
            assert!(policy.get_directive("object-src").is_some());
        }
    }

    #[test]
    fn test_strict_preset_is_locked_down() {
        let policy = preset_policy(CspPreset::Strict);

        assert!(policy.to_string().contains("default-src 'none'"));
        assert!(policy.to_string().contains("frame-ancestors 'none'"));
    }

    #[test]
    fn test_spa_preset_allows_realtime_and_assets() {
        let policy = preset_policy(CspPreset::SinglePageApp);
        let rendered = policy.to_string();

        assert!(rendered.contains("connect-src 'self' https: wss:"));
        assert!(rendered.contains("img-src 'self' data: https:"));
    }

    #[test]
    fn test_preset_parser_accepts_aliases() {
        assert_eq!("spa".parse::<CspPreset>().unwrap(), CspPreset::SinglePageApp);
        assert_eq!("api-only".parse::<CspPreset>().unwrap(), CspPreset::Api);
    }
}
