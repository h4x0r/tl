//! # TL (Timeline) - NTFS Master File Table Parser
//!
//! A high-performance CLI tool for parsing NTFS Master File Table records from extracted MFT files.
//! Supports both dense and sparse formats with optional two-pass processing for complete directory
//! path reconstruction.
//!
//! ## Features
//!
//! - Parse MFT records from various formats (.mft, .zip, .gz)
//! - Live system access on Windows (requires Administrator privileges)
//! - Two-pass processing for complete directory path reconstruction
//! - Alternative Data Stream (ADS) support
//! - Multiple output formats (human-readable, JSON, CSV)
//! - Parallel processing for improved performance
//!
//! ## Author
//!
//! Albert Hui <albert@securityronin.com>

pub mod app;
pub mod benchmark;
pub mod cli;
pub mod container;
pub mod datetime;
pub mod error;
pub mod fast_formatter;
pub mod interactive;
pub mod jumplist;
pub mod live_registry;
pub mod lnk_parser;
pub mod mft;
pub mod ole;
pub mod output;
pub mod property_store;
pub mod registry;
pub mod shell_item;
pub mod simd_optimize;
pub mod types;

#[cfg(windows)]
pub mod windows;

pub use error::{Error, Result};
pub use mft::MftParser;
pub use output::{OutputFormat, OutputWriter};
pub use types::{AlternateDataStream, Event, EventTimestamps};

#[cfg(windows)]
pub use windows::LiveSystemAccess;

/// Parse drive letter from input string
///
/// # Arguments
/// * `input` - Input string (e.g., "C:", "D:")
///
/// # Returns
/// Some(char) if valid drive letter format, None otherwise
pub fn parse_drive_letter(input: &str) -> Option<char> {
    if input.len() == 2 && input.ends_with(':') {
        input.chars().next()?.to_ascii_uppercase().into()
    } else {
        None
    }
}