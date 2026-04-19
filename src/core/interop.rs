use crate::core::directives::Directive;
use crate::core::policy::CspPolicy;
use crate::core::source::Source;
use crate::error::CspError;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PolicyDocument {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directives: Vec<DirectiveDocument>,
    #[serde(default)]
    pub report_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DirectiveDocument {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback_sources: Vec<String>,
}

impl From<&CspPolicy> for PolicyDocument {
    fn from(policy: &CspPolicy) -> Self {
        Self {
            directives: policy.directives().map(DirectiveDocument::from).collect(),
            report_only: policy.is_report_only(),
            report_uri: policy.report_uri().map(str::to_owned),
            report_to: policy.report_to().map(str::to_owned),
        }
    }
}

impl TryFrom<PolicyDocument> for CspPolicy {
    type Error = CspError;

    fn try_from(document: PolicyDocument) -> Result<Self, Self::Error> {
        let mut policy = CspPolicy::new();

        for directive in document.directives {
            policy.add_directive(Directive::try_from(directive)?);
        }

        policy.set_report_only(document.report_only);

        if let Some(report_uri) = document.report_uri {
            policy.set_report_uri(report_uri);
        }

        if let Some(report_to) = document.report_to {
            policy.set_report_to(report_to);
        }

        policy.validate()?;
        Ok(policy)
    }
}

impl From<&Directive> for DirectiveDocument {
    fn from(directive: &Directive) -> Self {
        Self {
            name: directive.name().to_owned(),
            sources: directive
                .sources()
                .iter()
                .map(ToString::to_string)
                .collect(),
            fallback_sources: directive
                .fallback_sources()
                .into_iter()
                .flatten()
                .map(ToString::to_string)
                .collect(),
        }
    }
}

impl TryFrom<DirectiveDocument> for Directive {
    type Error = CspError;

    fn try_from(document: DirectiveDocument) -> Result<Self, Self::Error> {
        if document.name.trim().is_empty() {
            return Err(CspError::InvalidDirectiveName(
                "Directive document requires a non-empty name".to_string(),
            ));
        }

        let mut directive = Directive::new(document.name);
        for source in document.sources {
            directive.add_source(Source::from_str(&source)?);
        }

        if !document.fallback_sources.is_empty() {
            let parsed_fallbacks = document
                .fallback_sources
                .into_iter()
                .map(|source| Source::from_str(&source))
                .collect::<Result<Vec<_>, _>>()?;
            directive.add_fallback_sources(parsed_fallbacks);
        }

        directive.validate()?;
        Ok(directive)
    }
}
