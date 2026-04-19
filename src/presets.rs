use crate::core::{CspPolicy, CspPolicyBuilder, Source};
use crate::error::CspError;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CspPreset {
    Strict,
    Api,
    SinglePageApp,
    Dashboard,
    Payments,
}

impl CspPreset {
    #[inline]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Api => "api",
            Self::SinglePageApp => "single-page-app",
            Self::Dashboard => "dashboard",
            Self::Payments => "payments",
        }
    }

    pub fn build(self) -> CspPolicy {
        match self {
            Self::Strict => CspPolicyBuilder::new()
                .default_src([Source::None])
                .script_src([Source::Self_])
                .style_src([Source::Self_])
                .img_src([Source::Self_])
                .connect_src([Source::Self_])
                .font_src([Source::Self_])
                .object_src([Source::None])
                .base_uri([Source::Self_])
                .form_action([Source::Self_])
                .frame_ancestors([Source::None])
                .upgrade_insecure_requests()
                .build_unchecked(),
            Self::Api => CspPolicyBuilder::new()
                .default_src([Source::None])
                .base_uri([Source::None])
                .form_action([Source::None])
                .frame_ancestors([Source::None])
                .object_src([Source::None])
                .build_unchecked(),
            Self::SinglePageApp => CspPolicyBuilder::new()
                .default_src([Source::Self_])
                .script_src([Source::Self_, Source::Scheme("https".into())])
                .style_src([
                    Source::Self_,
                    Source::UnsafeInline,
                    Source::Scheme("https".into()),
                ])
                .img_src([
                    Source::Self_,
                    Source::Scheme("data".into()),
                    Source::Scheme("https".into()),
                ])
                .font_src([
                    Source::Self_,
                    Source::Scheme("data".into()),
                    Source::Scheme("https".into()),
                ])
                .connect_src([
                    Source::Self_,
                    Source::Scheme("https".into()),
                    Source::Scheme("wss".into()),
                ])
                .object_src([Source::None])
                .base_uri([Source::Self_])
                .form_action([Source::Self_])
                .frame_ancestors([Source::None])
                .build_unchecked(),
            Self::Dashboard => CspPolicyBuilder::new()
                .default_src([Source::Self_])
                .script_src([Source::Self_, Source::Scheme("https".into())])
                .style_src([Source::Self_, Source::Scheme("https".into())])
                .img_src([
                    Source::Self_,
                    Source::Scheme("data".into()),
                    Source::Scheme("https".into()),
                ])
                .font_src([Source::Self_, Source::Scheme("https".into())])
                .connect_src([
                    Source::Self_,
                    Source::Scheme("https".into()),
                    Source::Scheme("wss".into()),
                ])
                .frame_src([Source::Self_, Source::Scheme("https".into())])
                .object_src([Source::None])
                .base_uri([Source::Self_])
                .form_action([Source::Self_])
                .frame_ancestors([Source::Self_])
                .build_unchecked(),
            Self::Payments => CspPolicyBuilder::new()
                .default_src([Source::Self_])
                .script_src([Source::Self_, Source::Scheme("https".into())])
                .style_src([Source::Self_, Source::Scheme("https".into())])
                .img_src([
                    Source::Self_,
                    Source::Scheme("data".into()),
                    Source::Scheme("https".into()),
                ])
                .connect_src([Source::Self_, Source::Scheme("https".into())])
                .frame_src([Source::Self_, Source::Scheme("https".into())])
                .font_src([Source::Self_, Source::Scheme("https".into())])
                .object_src([Source::None])
                .base_uri([Source::Self_])
                .form_action([Source::Self_])
                .frame_ancestors([Source::Self_])
                .upgrade_insecure_requests()
                .build_unchecked(),
        }
    }

    pub fn validated(self) -> Result<CspPolicy, CspError> {
        let policy = self.build();
        policy.validate()?;
        Ok(policy)
    }
}

impl fmt::Display for CspPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for CspPreset {
    type Err = CspError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "strict" => Ok(Self::Strict),
            "api" | "api-only" => Ok(Self::Api),
            "single-page-app" | "spa" => Ok(Self::SinglePageApp),
            "dashboard" => Ok(Self::Dashboard),
            "payments" | "payment" => Ok(Self::Payments),
            other => Err(CspError::ConfigError(format!(
                "Unknown CSP preset '{other}'"
            ))),
        }
    }
}

impl TryFrom<&str> for CspPreset {
    type Error = CspError;

    #[inline]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

#[inline]
pub fn preset_policy(preset: CspPreset) -> CspPolicy {
    preset.build()
}
