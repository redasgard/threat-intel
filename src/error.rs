//! Error types for the threat intelligence library

use thiserror::Error;

/// Errors that can occur in threat intelligence operations
#[derive(Error, Debug)]
pub enum ThreatIntelError {
    #[error("Source not found: {0}")]
    SourceNotFound(String),

    #[error("Failed to fetch from source: {0}")]
    FetchError(String),

    #[error("Failed to parse response: {0}")]
    ParseError(String),

    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Result type alias using ThreatIntelError
pub type ThreatIntelResult<T> = Result<T, ThreatIntelError>;

