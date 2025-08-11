//! Command-line interface definitions and parsing.

use clap::Parser;

/// Input file types supported by the tool
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InputType {
    /// MFT file (.mft, .gz)
    Mft,
    /// LNK file (.lnk)
    Lnk,
    /// Automatic Destinations jumplist (.automaticDestinations-ms)
    AutomaticDestinations,
    /// Custom Destinations jumplist (.customDestinations-ms)
    CustomDestinations,
    /// Registry hive (NTUSER.DAT, SYSTEM, SOFTWARE, etc.)
    Registry,
    /// Windows drive letter (C:, D:, etc.)
    LiveSystem,
    /// ZIP archive container (.zip)
    ZipContainer,
    /// E01 Expert Witness format (.e01)
    E01Container,
    /// Raw disk image (.dd, .raw, .img)
    RawContainer,
}

/// tl (Timeline) - Parse NTFS Master File Table
/// Author: Albert Hui <albert@securityronin.com>
#[derive(Parser)]
#[command(name = "tl")]
#[command(about = "tl (Timeline) - High-Performance Forensic Timeline Generator\nAuthor: Albert Hui <albert@securityronin.com>", version)]
#[command(long_about = "A high-performance forensic timeline generator supporting multiple Windows artifacts:
• MFT files (.mft, .gz) with dense/sparse format support
• Container archives (.zip, .e01, .dd, .raw, .img) containing MFT data
• LNK files (.lnk) - Windows shortcuts and shell links  
• Jumplist files (.automaticDestinations-ms, .customDestinations-ms)
• Registry hives (NTUSER.DAT, SYSTEM, SOFTWARE) with MRU extraction
• Live system access (Windows drives: C:, D:, etc.)

Features ultra-fast parallel processing, interactive TUI viewer, and multiple output formats.")]
pub struct Args {
    /// Input file path - supports MFT (.mft, .gz), containers (.zip, .e01, .dd, .raw, .img), LNK (.lnk), Jumplist (.automaticDestinations-ms, .customDestinations-ms), Registry (NTUSER.DAT), or drive letter (e.g., "C:", "mft.bin", "evidence.zip", "image.e01", "disk.dd")
    pub input_file: Option<String>,

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
    pub input_file: String,
    pub input_type: InputType,
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
        let input_file = args.input_file
            .ok_or_else(|| crate::error::Error::InvalidInput("Input file path or drive letter required".to_string()))?;
        
        let input_type = Self::detect_input_type(&input_file)?;

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
            input_file,
            input_type,
            filter_regex,
            after_date,
            before_date,
            output: args.output,
            timezone,
            password: args.password,
        })
    }
    
    /// Detect input file type based on file extension and content
    fn detect_input_type(input_file: &str) -> crate::error::Result<InputType> {
        // Check for drive letter format (C:, D:, etc.)
        if input_file.len() == 2 && input_file.ends_with(':') && input_file.chars().next().unwrap().is_ascii_alphabetic() {
            return Ok(InputType::LiveSystem);
        }
        
        // Check file extension
        let path = std::path::Path::new(input_file);
        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        
        match extension.as_str() {
            "lnk" => Ok(InputType::Lnk),
            "dat" => {
                // Check if it's a registry file
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
                if filename.contains("ntuser") || filename.contains("system") || 
                   filename.contains("software") || filename.contains("sam") || 
                   filename.contains("security") {
                    Ok(InputType::Registry)
                } else {
                    // Default to MFT for .dat files
                    Ok(InputType::Mft)
                }
            },
            "mft" | "bin" | "gz" => Ok(InputType::Mft),
            "zip" => Ok(InputType::ZipContainer),
            "e01" => Ok(InputType::E01Container),
            "dd" | "raw" | "img" => Ok(InputType::RawContainer),
            "ms" => {
                // Check for jumplist files
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if filename.ends_with(".automaticDestinations-ms") {
                    Ok(InputType::AutomaticDestinations)
                } else if filename.ends_with(".customDestinations-ms") {
                    Ok(InputType::CustomDestinations)
                } else {
                    Err(crate::error::Error::InvalidInput(format!("Unknown .ms file type: {}", filename)))
                }
            },
            _ => {
                // Try to detect by filename patterns
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
                if filename.contains("automaticDestinations") {
                    Ok(InputType::AutomaticDestinations)
                } else if filename.contains("customDestinations") {
                    Ok(InputType::CustomDestinations)
                } else if filename.contains("ntuser") {
                    Ok(InputType::Registry)
                } else if filename.contains("$mft") {
                    Ok(InputType::Mft)
                } else {
                    // Default to MFT for unknown files
                    Ok(InputType::Mft)
                }
            }
        }
    }
}