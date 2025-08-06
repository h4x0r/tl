//! Error types and handling for the TL application.

use std::fmt;

/// Custom error type for TL operations
#[derive(Debug)]
pub enum Error {
    /// I/O related errors
    Io(std::io::Error),
    /// ZIP archive related errors
    Zip(zip::result::ZipError),
    /// JSON serialization/deserialization errors
    Json(serde_json::Error),
    /// CSV writing errors
    Csv(csv::Error),
    /// Generic error with message
    Generic(String),
    /// MFT parsing specific errors
    MftParsing(String),
    /// Windows API errors
    #[cfg(windows)]
    WindowsApi(String),
    /// Invalid input format
    InvalidInput(String),
    /// Authentication/permission errors
    AccessDenied(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "I/O error: {}", err),
            Error::Zip(err) => write!(f, "ZIP error: {}", err),
            Error::Json(err) => write!(f, "JSON error: {}", err),
            Error::Csv(err) => write!(f, "CSV error: {}", err),
            Error::Generic(msg) => write!(f, "{}", msg),
            Error::MftParsing(msg) => write!(f, "MFT parsing error: {}", msg),
            #[cfg(windows)]
            Error::WindowsApi(msg) => write!(f, "Windows API error: {}", msg),
            Error::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            Error::AccessDenied(msg) => write!(f, "Access denied: {}", msg),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(err) => Some(err),
            Error::Zip(err) => Some(err),
            Error::Json(err) => Some(err),
            Error::Csv(err) => Some(err),
            _ => None,
        }
    }
}

// Convenient conversion traits
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<zip::result::ZipError> for Error {
    fn from(err: zip::result::ZipError) -> Self {
        Error::Zip(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Json(err)
    }
}

impl From<csv::Error> for Error {
    fn from(err: csv::Error) -> Self {
        Error::Csv(err)
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Error::Generic(err.to_string())
    }
}

/// Convenient Result type alias
pub type Result<T> = std::result::Result<T, Error>;