//! Ultra-fast event formatting with aggressive optimizations

use crate::types::{TimelineEvent, Event, TimestampType, TimestampSource};
use crate::interactive::FormattedRow;
use chrono_tz::Tz;
use dashmap::DashMap;
use rayon::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Pre-computed string cache for common values
pub struct StringCache {
    /// Cached timestamp type strings
    timestamp_types: [Arc<str>; 4],
    /// Cached timestamp source strings  
    timestamp_sources: [Arc<str>; 2],
    /// Cached size strings for common sizes
    size_cache: DashMap<u64, Arc<str>>,
    /// Cached formatted timestamps
    timestamp_cache: DashMap<i64, Arc<str>>,
    /// Common strings
    unknown_size: Arc<str>,
    folder_size: Arc<str>,
    empty_string: Arc<str>,
    backslash: Arc<str>,
}

impl StringCache {
    pub fn new() -> Self {
        Self {
            timestamp_types: [
                Arc::from("File/folder created"),
                Arc::from("File/folder modified"),
                Arc::from("File/folder index record modified"),
                Arc::from("File/folder accessed"),
            ],
            timestamp_sources: [
                Arc::from("$STANDARD_INFORMATION"),
                Arc::from("$FILE_NAME"),
            ],
            size_cache: DashMap::with_capacity(10000),
            timestamp_cache: DashMap::with_capacity(100000),
            unknown_size: Arc::from("       Unknown"),
            folder_size: Arc::from("           📁"),
            empty_string: Arc::from(""),
            backslash: Arc::from("\\"),
        }
    }

    #[inline(always)]
    fn get_timestamp_type(&self, tt: TimestampType) -> Arc<str> {
        self.timestamp_types[tt.sort_priority() as usize].clone()
    }

    #[inline(always)]
    fn get_timestamp_source(&self, ts: TimestampSource) -> Arc<str> {
        match ts {
            TimestampSource::StandardInformation => self.timestamp_sources[0].clone(),
            TimestampSource::FileName => self.timestamp_sources[1].clone(),
        }
    }

    #[inline(always)]
    fn format_size(&self, size: Option<u64>, is_directory: bool) -> Arc<str> {
        if is_directory {
            return self.folder_size.clone();
        }
        
        match size {
            None => self.unknown_size.clone(),
            Some(s) => {
                // Check cache first
                if let Some(cached) = self.size_cache.get(&s) {
                    return cached.clone();
                }
                
                // Format and cache
                let formatted: Arc<str> = Arc::from(format!("{:>13}", format_number_with_commas(s)).as_str());
                self.size_cache.insert(s, formatted.clone());
                formatted
            }
        }
    }
}

/// Format number with commas (optimized version)
#[inline(always)]
fn format_number_with_commas(mut num: u64) -> String {
    if num == 0 {
        return "0".to_string();
    }
    
    // Pre-allocate with expected size (max 20 digits + 6 commas)
    let mut result = String::with_capacity(26);
    let mut digits = Vec::with_capacity(20);
    
    // Extract digits
    while num > 0 {
        digits.push((num % 10) as u8);
        num /= 10;
    }
    
    // Build string with commas
    for (i, &digit) in digits.iter().rev().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push((b'0' + digit) as char);
    }
    
    result
}

/// Pre-computed lookup tables for fast formatting
pub struct LookupTables {
    /// Pre-formatted type+source combinations (only 8 possible)
    type_source_combos: [[Arc<str>; 2]; 4],
    /// Deletion status lookup  
    deletion_map: DashMap<u64, bool>,
}

impl LookupTables {
    pub fn new(records: &[Event]) -> Self {
        // Pre-compute all type+source combinations
        let types = ["File/folder created", "File/folder modified", 
                     "File/folder index record modified", "File/folder accessed"];
        let sources = ["$STANDARD_INFORMATION", "$FILE_NAME"];
        
        let mut type_source_combos: [[Arc<str>; 2]; 4] = [
            [Arc::from(""), Arc::from("")],
            [Arc::from(""), Arc::from("")],
            [Arc::from(""), Arc::from("")],
            [Arc::from(""), Arc::from("")],
        ];
        
        for (i, type_str) in types.iter().enumerate() {
            for (j, source_str) in sources.iter().enumerate() {
                type_source_combos[i][j] = Arc::from(format!("{} ({})", type_str, source_str).as_str());
            }
        }
        
        // Build deletion map
        let deletion_map = DashMap::with_capacity(records.len());
        records.par_iter()
            .filter(|r| r.is_deleted)
            .for_each(|r| {
                deletion_map.insert(r.record_number, true);
            });
        
        Self {
            type_source_combos,
            deletion_map,
        }
    }
    
    #[inline(always)]
    pub fn get_type_source(&self, tt: TimestampType, ts: TimestampSource) -> Arc<str> {
        let type_idx = tt.sort_priority() as usize;
        let source_idx = match ts {
            TimestampSource::StandardInformation => 0,
            TimestampSource::FileName => 1,
        };
        self.type_source_combos[type_idx][source_idx].clone()
    }
    
    #[inline(always)]
    pub fn is_deleted(&self, record_number: u64) -> bool {
        self.deletion_map.contains_key(&record_number)
    }
}

/// Batch timestamp formatter using SIMD where possible
pub struct BatchTimestampFormatter {
    timezone: Tz,
    cache: DashMap<i64, Arc<str>>,
}

impl BatchTimestampFormatter {
    pub fn new(timezone: Tz) -> Self {
        Self {
            timezone,
            cache: DashMap::with_capacity(100000),
        }
    }
    
    /// Format timestamps in batch for better cache locality
    pub fn format_batch(&self, timestamps: &[chrono::DateTime<chrono::Utc>]) -> Vec<Arc<str>> {
        timestamps.par_iter()
            .map(|ts| self.format_single(*ts))
            .collect()
    }
    
    #[inline(always)]
    fn format_single(&self, timestamp: chrono::DateTime<chrono::Utc>) -> Arc<str> {
        let unix_time = timestamp.timestamp();
        
        // Check cache
        if let Some(cached) = self.cache.get(&unix_time) {
            return cached.clone();
        }
        
        // Convert and format
        let converted = crate::datetime::convert_to_timezone(timestamp, self.timezone);
        let formatted: Arc<str> = Arc::from(crate::datetime::format_timestamp_human(&converted).as_str());
        
        // Cache for reuse
        self.cache.insert(unix_time, formatted.clone());
        formatted
    }
}

/// Ultra-fast parallel formatter with all optimizations
pub struct FastFormatter {
    string_cache: Arc<StringCache>,
    lookup_tables: Arc<LookupTables>,
    timestamp_formatter: Arc<BatchTimestampFormatter>,
    progress: Arc<AtomicUsize>,
}

impl FastFormatter {
    pub fn new(records: &[Event], timezone: Tz) -> Self {
        Self {
            string_cache: Arc::new(StringCache::new()),
            lookup_tables: Arc::new(LookupTables::new(records)),
            timestamp_formatter: Arc::new(BatchTimestampFormatter::new(timezone)),
            progress: Arc::new(AtomicUsize::new(0)),
        }
    }
    
    pub fn format_events(&self, events: &[TimelineEvent]) -> Vec<FormattedRow> {
        let total = events.len();
        
        // Process in large parallel chunks for maximum throughput
        let chunk_size = 50000; // Larger chunks for better cache locality
        let formatted: Vec<FormattedRow> = events
            .par_chunks(chunk_size)
            .flat_map(|chunk| {
                let chunk_results: Vec<FormattedRow> = chunk
                    .iter()
                    .map(|event| self.format_single_event(event))
                    .collect();
                
                // Update progress
                let completed = self.progress.fetch_add(chunk.len(), Ordering::Relaxed) + chunk.len();
                if completed % 100000 == 0 || completed == total {
                    let progress = (completed as f32 / total as f32 * 100.0) as usize;
                    let bar_width = 30;
                    let filled = (progress * bar_width / 100).min(bar_width);
                    let bar = "█".repeat(filled) + &"░".repeat(bar_width - filled);
                    eprint!("\r🎨 Pre-formatting [{}/{}] [{}] {}%", completed, total, bar, progress);
                }
                
                chunk_results
            })
            .collect();
        
        eprintln!(); // New line after progress
        formatted
    }
    
    #[inline(always)]
    fn format_single_event(&self, event: &TimelineEvent) -> FormattedRow {
        // Use cached formatted timestamp
        let formatted_time = self.timestamp_formatter.format_single(event.timestamp);
        
        // Use pre-computed type+source combo, but handle LNK files specially
        let type_source = if event.event_source.as_deref() == Some("LNK") {
            // For LNK events, don't include the timestamp source information
            Arc::from(event.timestamp_type.display_name_for_source(event.event_source.as_deref()))
        } else {
            self.lookup_tables.get_type_source(
                event.timestamp_type,
                event.timestamp_source
            )
        };
        
        // Use Arc strings to avoid allocations
        let record: Arc<str> = if event.event_source.as_deref() == Some("LNK") {
            Arc::from("🔗")  // Use link emoji for LNK files
        } else {
            Arc::from(event.mft_record_number.to_string().as_str())
        };
        
        // Use cached size formatting
        let size = self.string_cache.format_size(event.file_size, event.is_directory);
        
        // Check deletion status from lookup table
        let is_deleted = self.lookup_tables.is_deleted(event.mft_record_number);
        
        // Build full path efficiently (minimize allocations)
        let full_path = if event.location.is_empty() || event.location == "\\" {
            event.filename.clone()
        } else if event.location.ends_with('\\') {
            format!("{}{}", event.location, event.filename)
        } else {
            format!("{}\\{}", event.location, event.filename)
        };
        
        FormattedRow {
            filename: event.filename.clone(),
            timestamp: formatted_time.to_string(),
            type_source: type_source.to_string(),
            record: record.to_string(),
            size: size.to_string(),
            location: event.location.clone(),
            full_path,
            is_deleted,
        }
    }
}

/// Public API for fast formatting
pub fn format_events_ultra_fast(
    events: &[TimelineEvent],
    records: &[Event], 
    timezone: Tz
) -> Vec<FormattedRow> {
    let formatter = FastFormatter::new(records, timezone);
    formatter.format_events(events)
}