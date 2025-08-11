//! Output formatting functionality for different export formats.

use crate::datetime::{convert_to_timezone, format_timestamp_human};
use crate::error::Result;
use crate::types::{Event, TimelineEvent};
use chrono::{DateTime, Utc, Offset};
use chrono_tz::Tz;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde_json;
use std::io::{BufWriter, Write};

/// Supported output formats
#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable format with detailed information
    Human,
    /// JSON format for programmatic consumption
    Json,
    /// CSV format for spreadsheet analysis
    Csv,
    /// Timeline format with ascending chronological order
    Timeline,
}

/// Handles output formatting and writing
pub struct OutputWriter;

impl OutputWriter {
    /// Write records in the specified format with timezone conversion
    pub fn write_records(
        records: Vec<Event>,
        format: OutputFormat,
        writer: Box<dyn Write>,
        timezone: Tz,
    ) -> Result<()> {
        match format {
            OutputFormat::Human => Self::write_human(records, writer, timezone),
            OutputFormat::Json => Self::write_json(records, writer, timezone),
            OutputFormat::Csv => Self::write_csv(records, writer, timezone),
            OutputFormat::Timeline => Self::write_timeline(records, writer, timezone),
        }
    }

    /// Write records in ascending timeline format with optimized performance
    pub fn write_timeline(records: Vec<Event>, writer: Box<dyn Write>, timezone: Tz) -> Result<()> {
        eprintln!("⏰ Building timeline from {} records...", records.len());
        
        // Step 1: Extract all timeline events from all records using parallel processing
        eprintln!("🔄 Extracting timestamp events...");
        let pb_extract = ProgressBar::new(records.len() as u64);
        pb_extract.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}) {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=>-"));
        pb_extract.set_message("Extracting events");
        
        // This parallelizes the extraction to improve performance on multi-core systems
        let events: Vec<TimelineEvent> = records
            .par_iter()
            .map(|record| {
                pb_extract.inc(1);
                record.extract_timeline_events()
            })
            .flat_map(|events| events)
            .collect();
        
        pb_extract.finish_with_message(format!("Extracted {} timeline events", events.len()));

        // Step 2: Sort by timestamp in ascending order (optimized using Rust's Timsort)
        eprintln!("📊 Sorting {} events chronologically...", events.len());
        let pb_sort = ProgressBar::new_spinner();
        pb_sort.set_style(ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()));
        pb_sort.set_message("Sorting timeline");
        
        // Timsort is excellent for real-world data with existing order
        // Multi-level sort ensures proper chronological order:
        // 1) Primary: by timestamp (ascending chronological order)
        // 2) Secondary: by timestamp type priority when timestamps are identical
        //    Order: Created > Modified > MFT Modified > Accessed
        // 3) Tertiary: by timestamp source (SI before FN) for same type and time
        let mut sorted_events = events;
        sorted_events.sort_unstable_by(|a, b| {
            // Primary sort: by timestamp
            let timestamp_cmp = a.timestamp.cmp(&b.timestamp);
            if timestamp_cmp != std::cmp::Ordering::Equal {
                return timestamp_cmp;
            }
            
            // Secondary sort: by timestamp type priority (Created > Modified > MftModified > Accessed)
            let type_cmp = a.timestamp_type.sort_priority().cmp(&b.timestamp_type.sort_priority());
            if type_cmp != std::cmp::Ordering::Equal {
                return type_cmp;
            }
            
            // Tertiary sort: by timestamp source (SI before FN for same type and time)
            a.timestamp_source.short_form().cmp(&b.timestamp_source.short_form())
        });
        pb_sort.finish_with_message("Timeline sorted");

        // Step 3: Output timeline events
        eprintln!("📝 Writing timeline...");
        let pb_write = ProgressBar::new(sorted_events.len() as u64);
        pb_write.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}) {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=>-"));
        pb_write.set_message("Writing events");
        
        // Pre-allocate buffer for better I/O performance
        let mut buffered_writer = BufWriter::new(writer);

        // Format and write each event with minimal allocations
        for event in sorted_events {
            let converted_time = convert_to_timezone(event.timestamp, timezone);
            let formatted_time = Self::format_timeline_timestamp(&converted_time, timezone);
            let timestamp_type_with_source = if event.event_source.as_deref() == Some("LNK") {
                // For LNK events, don't include the timestamp source information
                event.timestamp_type.display_name_for_source(event.event_source.as_deref()).to_string()
            } else {
                format!("{} ({})", 
                    event.timestamp_type.display_name_for_source(event.event_source.as_deref()),
                    event.timestamp_source.short_form()
                )
            };

            // Properly escape CSV fields with quotes and handle special characters
            let escaped_filename = Self::escape_csv_field(&event.filename);
            let escaped_location = Self::escape_csv_field(&event.location);
            
            // Format file size - use 0 for directories or if size is unavailable
            let file_size = if event.is_directory {
                0
            } else {
                event.file_size.unwrap_or(0)
            };

            writeln!(
                buffered_writer,
                "{},{},{},{},{}",
                escaped_filename,
                formatted_time,
                timestamp_type_with_source,
                file_size,
                escaped_location
            )?;
            
            pb_write.inc(1);
        }

        pb_write.finish_with_message("Timeline complete");
        
        // Ensure all data is written
        buffered_writer.flush()?;
        Ok(())
    }

    /// Escape a field for CSV output with proper quoting
    fn escape_csv_field(field: &str) -> String {
        // Check if the field contains special characters that require quoting
        let needs_quoting = field.contains(',') || 
                           field.contains('"') || 
                           field.contains('\n') || 
                           field.contains('\r') ||
                           field.starts_with(' ') ||
                           field.ends_with(' ');
        
        if needs_quoting {
            // Escape internal double quotes by doubling them
            let escaped = field.replace('"', "\"\"");
            format!("\"{}\"", escaped)
        } else {
            // Simple case - just add quotes for consistency
            format!("\"{}\"", field)
        }
    }

    /// Format timestamp for timeline output (Wed 2024-11-02 UTC+8 format)
    fn format_timeline_timestamp(timestamp: &DateTime<Tz>, timezone: Tz) -> String {
        // Format as "Wed 2024-11-02 HH:MM:SS UTC+offset"
        let offset_str = if timezone.name() == "UTC" {
            "UTC".to_string()
        } else {
            // Extract offset from timezone
            let offset = timestamp.offset().fix().local_minus_utc();
            let hours = offset / 3600;
            if hours >= 0 {
                format!("UTC+{}", hours)
            } else {
                format!("UTC{}", hours)
            }
        };
        
        format!("{} {}", 
            timestamp.format("%a %Y-%m-%d %H:%M:%S"),
            offset_str
        )
    }

    /// Write records in human-readable format with timezone conversion
    fn write_human(records: Vec<Event>, mut writer: Box<dyn Write>, timezone: Tz) -> Result<()> {
        for record in records {
            let filename = record.filename.as_deref().unwrap_or("N/A");
            
            // Deleted status is now shown through filename strikethrough in interactive mode
            // For text output, we'll omit the DELETED flag to keep it clean
            let flags_str = String::new();

            writeln!(writer, "{} ({}){}", filename, record.record_number, flags_str)?;

            // Location - show "\" for root directory or full path
            let location = record.location.as_deref().unwrap_or("\\");
            writeln!(writer, "  {:<17} {}", "Location:", location)?;

            // Timestamps with both SI and FN values, converted to specified timezone
            Self::write_timestamp_pair(
                &mut writer,
                "Created:",
                &record.timestamps.created,
                &record.fn_timestamps.created,
                timezone,
            )?;

            Self::write_timestamp_pair(
                &mut writer,
                "Modified:",
                &record.timestamps.modified,
                &record.fn_timestamps.modified,
                timezone,
            )?;

            Self::write_timestamp_pair(
                &mut writer,
                "MFT Modified:",
                &record.timestamps.mft_modified,
                &record.fn_timestamps.mft_modified,
                timezone,
            )?;

            Self::write_timestamp_pair(
                &mut writer,
                "Accessed:",
                &record.timestamps.accessed,
                &record.fn_timestamps.accessed,
                timezone,
            )?;

            // Size
            if record.is_directory {
                writeln!(writer, "  {:<17} (folder)", "Size:")?;
            } else {
                let size = record.file_size.unwrap_or(0);
                writeln!(writer, "  {:<17} {} bytes", "Size:", size)?;
            }

            // Alternative Data Streams
            if !record.alternate_data_streams.is_empty() {
                writeln!(
                    writer,
                    "  {:<17} {} stream(s)",
                    "ADS:",
                    record.alternate_data_streams.len()
                )?;
                for ads in &record.alternate_data_streams {
                    writeln!(writer, "    {} ({} bytes)", ads.name, ads.size)?;
                }
            }

            writeln!(writer)?;
        }

        Ok(())
    }

    /// Write a timestamp pair (SI and FN) if available with timezone conversion
    fn write_timestamp_pair(
        writer: &mut Box<dyn Write>,
        label: &str,
        si_timestamp: &Option<DateTime<Utc>>,
        fn_timestamp: &Option<DateTime<Utc>>,
        timezone: Tz,
    ) -> Result<()> {
        if let Some(si_time) = si_timestamp {
            let si_converted = convert_to_timezone(si_time.clone(), timezone);
            let si_formatted = format_timestamp_human(&si_converted);
            
            let fn_time_str = fn_timestamp
                .as_ref()
                .map(|t| {
                    let fn_converted = convert_to_timezone(t.clone(), timezone);
                    format!("{}(FN)", format_timestamp_human(&fn_converted))
                })
                .unwrap_or_else(|| "N/A(FN)".to_string());
            
            writeln!(writer, "  {:<17} {}(SI) {}", label, si_formatted, fn_time_str)?;
        }
        Ok(())
    }

    /// Write records in JSON format (timestamps remain in UTC for programmatic use)
    fn write_json(records: Vec<Event>, mut writer: Box<dyn Write>, _timezone: Tz) -> Result<()> {
        // For JSON output, keep timestamps in UTC for better programmatic interoperability
        serde_json::to_writer_pretty(&mut writer, &records)?;
        writeln!(writer)?;
        Ok(())
    }

    /// Write records in CSV format with timezone conversion
    fn write_csv(records: Vec<Event>, writer: Box<dyn Write>, timezone: Tz) -> Result<()> {
        let mut csv_writer = csv::Writer::from_writer(writer);

        // Write header
        csv_writer.write_record(&[
            "record_number",
            "sequence_number",
            "filename",
            "file_size",
            "is_directory",
            "is_deleted",
            "location",
            "created",
            "modified",
            "mft_modified",
            "accessed",
            "fn_created",
            "fn_modified",
            "fn_mft_modified",
            "fn_accessed",
            "ads_count",
            "ads_names",
        ])?;

        // Write records
        for record in records {
            let ads_names = record
                .alternate_data_streams
                .iter()
                .map(|ads| format!("{}:{}", ads.name, ads.size))
                .collect::<Vec<_>>()
                .join(";");

            csv_writer.write_record(&[
                record.record_number.to_string(),
                record.sequence_number.to_string(),
                record.filename.unwrap_or_default(),
                record.file_size.unwrap_or(0).to_string(),
                record.is_directory.to_string(),
                record.is_deleted.to_string(),
                record.location.unwrap_or_default(),
                Self::format_optional_timestamp_with_tz(&record.timestamps.created, timezone),
                Self::format_optional_timestamp_with_tz(&record.timestamps.modified, timezone),
                Self::format_optional_timestamp_with_tz(&record.timestamps.mft_modified, timezone),
                Self::format_optional_timestamp_with_tz(&record.timestamps.accessed, timezone),
                Self::format_optional_timestamp_with_tz(&record.fn_timestamps.created, timezone),
                Self::format_optional_timestamp_with_tz(&record.fn_timestamps.modified, timezone),
                Self::format_optional_timestamp_with_tz(&record.fn_timestamps.mft_modified, timezone),
                Self::format_optional_timestamp_with_tz(&record.fn_timestamps.accessed, timezone),
                record.alternate_data_streams.len().to_string(),
                ads_names,
            ])?;
        }

        csv_writer.flush()?;
        Ok(())
    }

    /// Format optional timestamp with timezone conversion for CSV output
    fn format_optional_timestamp_with_tz(timestamp: &Option<DateTime<Utc>>, timezone: Tz) -> String {
        timestamp
            .map(|t| {
                let converted = convert_to_timezone(t.clone(), timezone);
                format_timestamp_human(&converted)
            })
            .unwrap_or_else(|| "N/A".to_string())
    }
}

/// Create appropriate writer based on output option
pub fn create_writer(output_file: Option<String>) -> Result<Box<dyn Write>> {
    let writer: Box<dyn Write> = if let Some(output_file) = output_file {
        if output_file == "-" {
            Box::new(std::io::stdout())
        } else {
            Box::new(BufWriter::new(std::fs::File::create(output_file)?))
        }
    } else {
        Box::new(std::io::stdout())
    };

    Ok(writer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EventTimestamps, AlternateDataStream};
    use chrono::Utc;

    fn create_test_record() -> Event {
        Event {
            record_number: 123,
            sequence_number: 1,
            filename: Some("test.txt".to_string()),
            file_size: Some(1024),
            allocated_size: Some(1024),
            is_directory: false,
            is_deleted: false,
            link_count: Some(1),
            parent_directory: Some(5),
            timestamps: EventTimestamps {
                created: Some(Utc::now()),
                modified: Some(Utc::now()),
                mft_modified: Some(Utc::now()),
                accessed: Some(Utc::now()),
            },
            fn_timestamps: EventTimestamps::default(),
            alternate_data_streams: vec![AlternateDataStream {
                name: "Zone.Identifier".to_string(),
                size: 26,
                resident: true,
            }],
            location: Some("Users\\TestUser".to_string()),
        }
    }

    #[test]
    fn test_json_output() {
        let records = vec![create_test_record()];
        let output = Vec::new();

        let result = OutputWriter::write_json(records, Box::new(output), chrono_tz::UTC);
        assert!(result.is_ok());

        // For a more complete test, we would need to capture the output differently
        // But this at least verifies the function doesn't panic
    }

    #[test]
    fn test_csv_output() {
        let records = vec![create_test_record()];
        let output = Vec::new();

        let result = OutputWriter::write_csv(records, Box::new(output), chrono_tz::UTC);
        assert!(result.is_ok());

        // For a more complete test, we would need to capture the output differently
        // But this at least verifies the function doesn't panic
    }

    #[test]
    fn test_csv_escaping() {
        // Test various problematic characters in CSV fields
        
        // Test simple field (should still get quotes for consistency)
        assert_eq!(OutputWriter::escape_csv_field("simple.txt"), "\"simple.txt\"");
        
        // Test field with comma
        assert_eq!(OutputWriter::escape_csv_field("file,with,commas.txt"), "\"file,with,commas.txt\"");
        
        // Test field with double quotes
        assert_eq!(OutputWriter::escape_csv_field("file\"with\"quotes.txt"), "\"file\"\"with\"\"quotes.txt\"");
        
        // Test field with newlines
        assert_eq!(OutputWriter::escape_csv_field("file\nwith\nnewlines.txt"), "\"file\nwith\nnewlines.txt\"");
        
        // Test field with leading/trailing spaces
        assert_eq!(OutputWriter::escape_csv_field(" spaced file.txt "), "\" spaced file.txt \"");
        
        // Test complex case with multiple special characters
        assert_eq!(
            OutputWriter::escape_csv_field("complex,file\"name\nwith\rspecial.txt"), 
            "\"complex,file\"\"name\nwith\rspecial.txt\""
        );
        
        // Test typical Windows path
        assert_eq!(OutputWriter::escape_csv_field("C:\\Users\\Test\\file.txt"), "\"C:\\Users\\Test\\file.txt\"");
        
        // Test orphaned path format
        assert_eq!(
            OutputWriter::escape_csv_field("[Orphaned]...\\(Record#105710)\\Extensions\\test.txt"), 
            "\"[Orphaned]...\\(Record#105710)\\Extensions\\test.txt\""
        );
    }
}