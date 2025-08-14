//! Event formatting module - provides unified formatting for all output modes
//! Implements the View layer in MVC architecture

use crate::types::{TimelineEvent, Event};
use chrono_tz::Tz;
use std::collections::HashMap;

/// Pre-formatted row for display
#[derive(Clone, Debug)]
pub struct FormattedRow {
    pub filename: String,
    pub timestamp: String,
    pub type_source: String,
    pub record: String,
    pub size: String,
    pub location: String,
    pub full_path: String,
    pub is_deleted: bool,
}

/// Unified event formatter for all output modes
pub struct EventFormatter {
    timezone: Tz,
    record_lookup: HashMap<u64, bool>, // Record number -> is_deleted
}

impl EventFormatter {
    /// Create a new formatter with timezone and record context
    pub fn new(timezone: Tz, records: &[Event]) -> Self {
        let mut record_lookup = HashMap::with_capacity(records.len());
        for record in records {
            if record.is_deleted {
                record_lookup.insert(record.record_number, true);
            }
        }

        Self {
            timezone,
            record_lookup,
        }
    }

    /// Format a collection of timeline events
    pub fn format_events(&self, events: &[TimelineEvent]) -> Vec<FormattedRow> {
        events.iter().map(|event| self.format_single_event(event)).collect()
    }

    /// Format a single timeline event
    fn format_single_event(&self, event: &TimelineEvent) -> FormattedRow {
        // Format timestamp
        let formatted_time = {
            let converted_time = crate::datetime::convert_to_timezone(event.timestamp, self.timezone);
            crate::datetime::format_timestamp_human(&converted_time)
        };

        // Format type and source
        let type_source = if event.event_source.as_deref() == Some("LNK") {
            // For LNK events, don't include the timestamp source information
            event.timestamp_type.display_name_for_source(event.event_source.as_deref()).to_string()
        } else {
            format!("{} ({})", 
                event.timestamp_type.display_name_for_source(event.event_source.as_deref()),
                event.timestamp_source.short_form()
            )
        };

        // Format record column with emojis for special sources
        let record = match event.event_source.as_deref() {
            Some("LNK") => "🔗".to_string(),
            Some("Jumplist") => "🔖".to_string(),
            _ => event.mft_record_number.to_string(),
        };

        // Format size
        let size = if event.is_directory {
            format!("{}📁", " ".repeat(11)) // Folder emoji with padding
        } else {
            match event.file_size {
                Some(s) => format!("{:>13}", format_number_with_commas(s)),
                None => "       Unknown".to_string(),
            }
        };

        // Build full path
        let full_path = if event.location.is_empty() || event.location == "\\" {
            event.filename.clone()
        } else if event.location.ends_with('\\') {
            format!("{}{}", event.location, event.filename)
        } else {
            format!("{}\\{}", event.location, event.filename)
        };

        // Check if record is deleted
        let is_deleted = self.record_lookup.contains_key(&event.mft_record_number);

        FormattedRow {
            filename: event.filename.clone(),
            timestamp: formatted_time,
            type_source,
            record,
            size,
            location: event.location.clone(),
            full_path,
            is_deleted,
        }
    }
}

/// Format number with comma separators
fn format_number_with_commas(mut num: u64) -> String {
    if num == 0 {
        return "0".to_string();
    }
    
    let mut result = String::new();
    let mut count = 0;
    
    while num > 0 {
        if count > 0 && count % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, (b'0' + (num % 10) as u8) as char);
        num /= 10;
        count += 1;
    }
    
    result
}

/// Public API for event formatting
pub fn format_events(events: &[TimelineEvent], records: &[Event], timezone: Tz) -> Vec<FormattedRow> {
    let formatter = EventFormatter::new(timezone, records);
    formatter.format_events(events)
}