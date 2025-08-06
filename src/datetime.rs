//! Date and time handling utilities including timezone conversion and parsing.

use crate::error::{Error, Result};
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, Offset, TimeZone, Timelike, Utc, Weekday};
use chrono_tz::Tz;

/// Parse timezone string into a Tz object
/// Accepts "UTC" or UTC offset notation like "UTC+8", "UTC-5"
pub fn parse_timezone(timezone_str: &str) -> Result<Tz> {
    match timezone_str {
        "UTC" => Ok(Tz::UTC),
        _ if timezone_str.starts_with("UTC") => {
            // Parse UTC offset notation like "UTC+8", "UTC-5"
            let offset_part = &timezone_str[3..];
            if offset_part.is_empty() {
                return Ok(Tz::UTC);
            }
            
            let offset_hours: i32 = offset_part.parse().map_err(|_| {
                Error::InvalidInput(format!(
                    "Invalid UTC offset '{}'. Use format like 'UTC+8' or 'UTC-5'",
                    timezone_str
                ))
            })?;
            
            // Map UTC offset to appropriate timezone
            // This is a simplified mapping for common offsets
            match offset_hours {
                0 => Ok(Tz::UTC),
                1 => Ok(Tz::Europe__London), // CET/CEST averages to UTC+1
                2 => Ok(Tz::Europe__Berlin), // CET/CEST
                3 => Ok(Tz::Europe__Moscow), // MSK
                4 => Ok(Tz::Asia__Dubai),    // GST
                5 => Ok(Tz::Asia__Karachi),  // PKT
                6 => Ok(Tz::Asia__Dhaka),    // BST
                7 => Ok(Tz::Asia__Bangkok),  // ICT
                8 => Ok(Tz::Asia__Hong_Kong), // HKT
                9 => Ok(Tz::Asia__Tokyo),    // JST
                10 => Ok(Tz::Australia__Sydney), // AEST/AEDT
                -5 => Ok(Tz::America__New_York), // EST/EDT
                -6 => Ok(Tz::America__Chicago),  // CST/CDT
                -7 => Ok(Tz::America__Denver),   // MST/MDT
                -8 => Ok(Tz::America__Los_Angeles), // PST/PDT
                -10 => Ok(Tz::Pacific__Honolulu), // HST
                _ => Err(Error::InvalidInput(format!(
                    "Unsupported UTC offset '{}'. Supported: UTC+8, UTC-5, etc.",
                    timezone_str
                )))
            }
        }
        _ => Err(Error::InvalidInput(format!(
            "Invalid timezone '{}'. Use 'UTC' or UTC offset notation like 'UTC+8'",
            timezone_str
        )))
    }
}

/// Convert UTC datetime to specified timezone
pub fn convert_to_timezone(utc_dt: DateTime<Utc>, tz: Tz) -> DateTime<Tz> {
    utc_dt.with_timezone(&tz)
}

/// Parse date string in various formats (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
pub fn parse_date_filter(date_str: &str) -> Result<DateTime<Utc>> {
    // Try parsing as date with time first
    if let Ok(naive_dt) = NaiveDateTime::parse_from_str(date_str, "%Y-%m-%d %H:%M:%S") {
        return Ok(Utc.from_utc_datetime(&naive_dt));
    }

    // Try parsing as date only
    if let Ok(naive_date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
        let naive_dt = naive_date.and_hms_opt(0, 0, 0).ok_or_else(|| {
            Error::InvalidInput("Invalid date format".to_string())
        })?;
        return Ok(Utc.from_utc_datetime(&naive_dt));
    }

    Err(Error::InvalidInput(format!(
        "Invalid date format '{}'. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS",
        date_str
    )))
}

/// Format timestamp with full precision, always showing nanoseconds
pub fn format_timestamp_full_precision<T: TimeZone>(dt: &DateTime<T>) -> String
where
    T::Offset: std::fmt::Display,
{
    // Extract nanoseconds and ensure exactly 9 digits with trailing zeros
    let nanos = dt.nanosecond();
    let base_format = dt.format("%Y-%m-%d %H:%M:%S");
    let utc_offset = format_utc_offset(dt);
    format!("{}.{:09} {}", base_format, nanos, utc_offset)
}

/// Format timestamp for human-readable output with timezone
pub fn format_timestamp_human<T: TimeZone>(dt: &DateTime<T>) -> String
where
    T::Offset: std::fmt::Display,
{
    // Extract components
    let nanos = dt.nanosecond();
    let weekday = format_weekday(dt.weekday());
    let base_format = dt.format("%Y-%m-%d %H:%M:%S");
    let utc_offset = format_utc_offset(dt);
    
    format!("{} {}.{:09} {}", weekday, base_format, nanos, utc_offset)
}

/// Format weekday as three-letter abbreviation
fn format_weekday(weekday: Weekday) -> &'static str {
    match weekday {
        Weekday::Mon => "Mon",
        Weekday::Tue => "Tue", 
        Weekday::Wed => "Wed",
        Weekday::Thu => "Thu",
        Weekday::Fri => "Fri",
        Weekday::Sat => "Sat",
        Weekday::Sun => "Sun",
    }
}

/// Format UTC offset with proper padding (e.g., "UTC+8 ", "UTC-10", "UTC   ")
fn format_utc_offset<T: TimeZone>(dt: &DateTime<T>) -> String
where
    T::Offset: std::fmt::Display,
{
    let offset_seconds = dt.offset().fix().local_minus_utc();
    let offset_hours = offset_seconds / 3600;
    let offset_minutes = (offset_seconds.abs() % 3600) / 60;
    
    if offset_minutes == 0 {
        if offset_hours == 0 {
            "UTC   ".to_string()  // UTC gets 3 spaces for alignment
        } else if offset_hours > 0 {
            if offset_hours < 10 {
                format!("UTC+{} ", offset_hours)  // Single digit gets trailing space
            } else {
                format!("UTC+{}", offset_hours)   // Double digit no trailing space
            }
        } else {
            if offset_hours > -10 {
                format!("UTC{} ", offset_hours)   // Single digit negative gets trailing space
            } else {
                format!("UTC{}", offset_hours)    // Double digit negative no trailing space
            }
        }
    } else {
        // Handle offsets with minutes (e.g., UTC+5:30)
        if offset_hours >= 0 {
            format!("UTC+{}:{:02}", offset_hours, offset_minutes)
        } else {
            format!("UTC{}:{:02}", offset_hours, offset_minutes)
        }
    }
}

/// Check if a timestamp falls within the specified date range
pub fn timestamp_in_range(
    timestamp: &Option<DateTime<Utc>>,
    after: &Option<DateTime<Utc>>,
    before: &Option<DateTime<Utc>>,
) -> bool {
    if let Some(ts) = timestamp {
        // Check after filter
        if let Some(after_dt) = after {
            if ts < after_dt {
                return false;
            }
        }

        // Check before filter
        if let Some(before_dt) = before {
            if ts > before_dt {
                return false;
            }
        }

        true
    } else {
        // If timestamp is None, only include if no filters are set
        after.is_none() && before.is_none()
    }
}

/// Check if any timestamp in an MFT record falls within the specified range
pub fn record_in_date_range(
    record: &crate::types::MftRecord,
    after: &Option<DateTime<Utc>>,
    before: &Option<DateTime<Utc>>,
) -> bool {
    // Check all timestamps - if any fall within range, include the record
    timestamp_in_range(&record.timestamps.created, after, before)
        || timestamp_in_range(&record.timestamps.modified, after, before)
        || timestamp_in_range(&record.timestamps.mft_modified, after, before)
        || timestamp_in_range(&record.timestamps.accessed, after, before)
        || timestamp_in_range(&record.fn_timestamps.created, after, before)
        || timestamp_in_range(&record.fn_timestamps.modified, after, before)
        || timestamp_in_range(&record.fn_timestamps.mft_modified, after, before)
        || timestamp_in_range(&record.fn_timestamps.accessed, after, before)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_timezone() {
        assert!(parse_timezone("UTC").is_ok());
        assert!(parse_timezone("UTC+8").is_ok());
        assert!(parse_timezone("UTC-5").is_ok());
        assert!(parse_timezone("UTC+0").is_ok());
        assert!(parse_timezone("Invalid/Timezone").is_err());
        assert!(parse_timezone("America/New_York").is_err()); // No longer supported
        assert!(parse_timezone("UTC+25").is_err()); // Invalid offset
    }

    #[test]
    fn test_parse_date_filter() {
        // Test date only format
        let result = parse_date_filter("2023-12-25");
        assert!(result.is_ok());
        let dt = result.unwrap();
        assert_eq!(dt.format("%Y-%m-%d %H:%M:%S").to_string(), "2023-12-25 00:00:00");

        // Test date with time format
        let result = parse_date_filter("2023-12-25 15:30:45");
        assert!(result.is_ok());
        let dt = result.unwrap();
        assert_eq!(dt.format("%Y-%m-%d %H:%M:%S").to_string(), "2023-12-25 15:30:45");

        // Test invalid format
        assert!(parse_date_filter("invalid-date").is_err());
        assert!(parse_date_filter("2023/12/25").is_err());
    }

    #[test]
    fn test_timestamp_in_range() {
        let ts = Some(chrono::NaiveDate::from_ymd_opt(2023, 12, 25).unwrap().and_hms_opt(12, 0, 0).unwrap().and_utc());
        let after = Some(chrono::NaiveDate::from_ymd_opt(2023, 12, 20).unwrap().and_hms_opt(0, 0, 0).unwrap().and_utc());
        let before = Some(chrono::NaiveDate::from_ymd_opt(2023, 12, 30).unwrap().and_hms_opt(0, 0, 0).unwrap().and_utc());

        assert!(timestamp_in_range(&ts, &after, &before));

        // Test outside range
        let early_after = Some(chrono::NaiveDate::from_ymd_opt(2023, 12, 26).unwrap().and_hms_opt(0, 0, 0).unwrap().and_utc());
        assert!(!timestamp_in_range(&ts, &early_after, &before));
    }

    #[test]
    fn test_format_timestamp_full_precision() {
        let dt = chrono::NaiveDate::from_ymd_opt(2023, 12, 25).unwrap().and_hms_nano_opt(12, 30, 45, 123456789).unwrap().and_utc();
        let formatted = format_timestamp_full_precision(&dt);
        println!("Full precision: {}", formatted);
        assert!(formatted.contains("2023-12-25 12:30:45.123456789"));
        assert!(formatted.contains("UTC   "));
    }

    #[test]
    fn test_format_timestamp_zero_nanoseconds() {
        // Test that zero nanoseconds are still displayed
        let dt_zero = chrono::NaiveDate::from_ymd_opt(2023, 12, 25).unwrap().and_hms_opt(12, 30, 45).unwrap().and_utc();
        let formatted = format_timestamp_full_precision(&dt_zero);
        println!("Zero nanoseconds: {}", formatted);
        assert!(formatted.contains("2023-12-25 12:30:45.000000000"));
        assert!(formatted.contains("UTC   "));

        // Test timezone conversion maintains precision
        let ny_dt = convert_to_timezone(dt_zero, Tz::America__New_York);
        let ny_formatted = format_timestamp_human(&ny_dt);
        println!("Zero nanoseconds (NY): {}", ny_formatted);
        assert!(ny_formatted.contains(".000000000"));
        assert!(ny_formatted.contains("UTC-5 ") || ny_formatted.contains("UTC-4 ")); // EST/EDT
    }

    #[test]
    fn test_format_matches_new_reference() {
        // Test new format: "Wed 2024-04-01 08:43:34.364272500 GMT+8 "
        let dt = chrono::NaiveDate::from_ymd_opt(2024, 4, 1)
            .unwrap()
            .and_hms_nano_opt(8, 43, 34, 364272500)
            .unwrap()
            .and_utc();
        
        // Convert to UTC+8 (Hong Kong time)
        let hk_dt = convert_to_timezone(dt, Tz::Asia__Hong_Kong);
        let formatted = format_timestamp_human(&hk_dt);
        println!("New reference format test: {}", formatted);
        
        // Should match: "Mon 2024-04-01 16:43:34.364272500 UTC+8 " (UTC+8 hours ahead)
        assert!(formatted.contains("Mon")); // April 1, 2024 is Monday
        assert!(formatted.contains("16:43:34.364272500")); // 8:43 UTC + 8 hours
        assert!(formatted.contains("UTC+8 "));
    }

    #[test]
    fn test_utc_offset_formatting() {
        // Test various UTC offset formats
        let base_dt = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_utc();

        // UTC should show "UTC   " with 3 spaces
        let utc_formatted = format_timestamp_full_precision(&base_dt);
        println!("UTC: '{}'", utc_formatted);
        assert!(utc_formatted.ends_with("UTC   "));

        // UTC+8 should have trailing space (single digit)
        let hk_dt = convert_to_timezone(base_dt, Tz::Asia__Hong_Kong);
        let hk_formatted = format_timestamp_full_precision(&hk_dt);
        println!("UTC+8: '{}'", hk_formatted);
        assert!(hk_formatted.ends_with("UTC+8 "));

        // UTC-10 should NOT have trailing space (double digit)
        let hawaii_dt = convert_to_timezone(base_dt, Tz::Pacific__Honolulu);
        let hawaii_formatted = format_timestamp_full_precision(&hawaii_dt);
        println!("UTC-10: '{}'", hawaii_formatted);
        assert!(hawaii_formatted.ends_with("UTC-10"));
    }

    #[test]
    fn test_utc_offset_parsing() {
        // Test parsing UTC offset notation
        assert!(parse_timezone("UTC+8").is_ok());
        assert!(parse_timezone("UTC-5").is_ok());
        assert!(parse_timezone("UTC").is_ok());
        assert!(parse_timezone("UTC+0").is_ok());
        
        // Test that the parsed timezone produces correct offset
        let hk_tz = parse_timezone("UTC+8").unwrap();
        let base_dt = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_utc();
        let hk_dt = convert_to_timezone(base_dt, hk_tz);
        let formatted = format_timestamp_full_precision(&hk_dt);
        assert!(formatted.contains("20:00:00")); // 12:00 UTC + 8 hours
        assert!(formatted.ends_with("UTC+8 "));
    }
}