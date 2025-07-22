use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CspViolationReport {
    #[serde(rename = "document-uri")]
    pub document_uri: String,

    #[serde(rename = "referrer")]
    pub referrer: String,

    #[serde(rename = "blocked-uri")]
    pub blocked_uri: String,

    #[serde(rename = "violated-directive")]
    pub violated_directive: String,

    #[serde(rename = "effective-directive")]
    pub effective_directive: String,

    #[serde(rename = "original-policy")]
    pub original_policy: String,

    #[serde(rename = "disposition")]
    pub disposition: String,

    #[serde(rename = "source-file", skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,

    #[serde(rename = "line-number", skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,

    #[serde(rename = "column-number", skip_serializing_if = "Option::is_none")]
    pub column_number: Option<u32>,

    #[serde(rename = "status-code", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,

    #[serde(rename = "script-sample", skip_serializing_if = "Option::is_none")]
    pub script_sample: Option<String>,
}

impl CspViolationReport {
    #[inline]
    pub fn new(
        document_uri: String,
        referrer: String,
        blocked_uri: String,
        violated_directive: String,
        effective_directive: String,
        original_policy: String,
        disposition: String,
    ) -> Self {
        Self {
            document_uri,
            referrer,
            blocked_uri,
            violated_directive,
            effective_directive,
            original_policy,
            disposition,
            source_file: None,
            line_number: None,
            column_number: None,
            status_code: None,
            script_sample: None,
        }
    }

    #[inline]
    pub fn with_source_file(mut self, source_file: String) -> Self {
        self.source_file = Some(source_file);
        self
    }

    #[inline]
    pub fn with_line_number(mut self, line_number: u32) -> Self {
        self.line_number = Some(line_number);
        self
    }

    #[inline]
    pub fn with_column_number(mut self, column_number: u32) -> Self {
        self.column_number = Some(column_number);
        self
    }

    #[inline]
    pub fn with_status_code(mut self, status_code: u16) -> Self {
        self.status_code = Some(status_code);
        self
    }

    #[inline]
    pub fn with_script_sample(mut self, script_sample: String) -> Self {
        self.script_sample = Some(script_sample);
        self
    }

    #[inline]
    pub fn is_enforce(&self) -> bool {
        self.disposition == "enforce"
    }

    #[inline]
    pub fn is_report(&self) -> bool {
        self.disposition == "report"
    }
}

impl TryFrom<&serde_json::Value> for CspViolationReport {
    type Error = serde_json::Error;

    fn try_from(value: &serde_json::Value) -> Result<Self, Self::Error> {
        serde_json::from_value(value.clone())
    }
}
