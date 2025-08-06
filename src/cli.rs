//! Command-line interface definitions and parsing.

use clap::Parser;

/// tl (Timeline) - Parse NTFS Master File Table
/// Author: Albert Hui <albert@securityronin.com>
#[derive(Parser)]
#[command(name = "tl")]
#[command(about = "tl (Timeline) - Parse NTFS Master File Table\nAuthor: Albert Hui <albert@securityronin.com>", version)]
#[command(long_about = "A fast CLI tool for parsing NTFS Master File Table records from extracted MFT files.
Supports both dense and sparse formats with two-pass processing for complete directory path reconstruction.")]
pub struct Args {
    /// MFT file path (.mft, .zip, .gz), or drive letter for live system access (e.g., "C:", "mft.bin", "evidence.zip", "$MFT.gz")
    pub mft_file: Option<String>,

    /// Filter by filename and location (supports regex patterns)
    #[arg(long)]
    pub filter: Option<String>,

    /// Show records with timestamps after this date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
    #[arg(long)]
    pub after: Option<String>,

    /// Show records with timestamps before this date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
    #[arg(long)]
    pub before: Option<String>,

    /// Output file (use "-" for stdout, default: stdout)
    #[arg(long)]
    pub output: Option<String>,

    /// Display timestamps in specified timezone (e.g., "UTC+8", "UTC-5", "UTC")  
    #[arg(long, default_value = "UTC")]
    pub timezone: String,

    /// Password for encrypted ZIP archives (for forensic collections)
    #[arg(long)]
    pub password: Option<String>,
}

/// Parsed and validated CLI configuration
#[derive(Debug)]
pub struct Config {
    pub mft_input: String,
    pub filter_regex: Option<regex::Regex>,
    pub after_date: Option<chrono::DateTime<chrono::Utc>>,
    pub before_date: Option<chrono::DateTime<chrono::Utc>>,
    pub output: Option<String>,
    pub timezone: chrono_tz::Tz,
    pub password: Option<String>,
}

impl Config {
    /// Parse and validate CLI arguments into a configuration
    pub fn from_args(args: Args) -> crate::error::Result<Self> {
        let mft_input = args.mft_file
            .ok_or_else(|| crate::error::Error::InvalidInput("MFT file path or drive letter required".to_string()))?;

        // Parse timezone
        let timezone = crate::datetime::parse_timezone(&args.timezone)?;

        // Compile regex filter if provided
        let filter_regex = if let Some(filter_pattern) = &args.filter {
            eprintln!("🔍 Compiling regex filter: {}", filter_pattern);
            Some(regex::RegexBuilder::new(filter_pattern)
                .case_insensitive(true)
                .build()
                .map_err(|e| {
                    crate::error::Error::InvalidInput(format!("Invalid regex pattern '{}': {}", filter_pattern, e))
                })?)
        } else {
            None
        };

        // Parse date filters
        let after_date = if let Some(ref after_str) = args.after {
            Some(crate::datetime::parse_date_filter(after_str)?)
        } else {
            None
        };

        let before_date = if let Some(ref before_str) = args.before {
            Some(crate::datetime::parse_date_filter(before_str)?)
        } else {
            None
        };

        Ok(Config {
            mft_input,
            filter_regex,
            after_date,
            before_date,
            output: args.output,
            timezone,
            password: args.password,
        })
    }
}