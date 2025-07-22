use actix_web::http::StatusCode;
use actix_web::ResponseError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CspError {
    #[error("Invalid directive value: {0}")]
    InvalidDirectiveValue(String),

    #[error("Invalid directive name: {0}")]
    InvalidDirectiveName(String),

    #[error("Invalid hash algorithm: {0}")]
    InvalidHashAlgorithm(String),

    #[error("Invalid nonce value: {0}")]
    InvalidNonceValue(String),

    #[error("Invalid report URI: {0}")]
    InvalidReportUri(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Header processing error: {0}")]
    HeaderError(String),

    #[error("Policy validation error: {0}")]
    ValidationError(String),

    #[error("Report processing error: {0}")]
    ReportError(String),

    #[error("Policy verification error: {0}")]
    VerificationError(String),

    #[error("Config error: {0}")]
    ConfigError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

impl ResponseError for CspError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidDirectiveValue(_)
            | Self::InvalidDirectiveName(_)
            | Self::InvalidHashAlgorithm(_)
            | Self::InvalidNonceValue(_)
            | Self::InvalidReportUri(_)
            | Self::ValidationError(_)
            | Self::VerificationError(_)
            | Self::ConfigError(_) => StatusCode::BAD_REQUEST,

            Self::CryptoError(_)
            | Self::SerializationError(_)
            | Self::HeaderError(_)
            | Self::ReportError(_)
            | Self::IoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
