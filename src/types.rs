//! Core data types for MFT records and related structures.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents a single MFT record with all parsed metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MftRecord {
    /// MFT record number (unique identifier)
    pub record_number: u64,
    /// Sequence number for record reuse tracking
    pub sequence_number: u16,
    /// Primary filename (long name preferred over 8.3)
    pub filename: Option<String>,
    /// File size in bytes
    pub file_size: Option<u64>,
    /// Allocated size on disk
    pub allocated_size: Option<u64>,
    /// Whether this record represents a directory
    pub is_directory: bool,
    /// Whether this record has been deleted
    pub is_deleted: bool,
    /// Number of hard links to this file
    pub link_count: Option<u16>,
    /// Parent directory MFT record number
    pub parent_directory: Option<u64>,
    /// Timestamps from STANDARD_INFORMATION attribute
    pub timestamps: MftTimestamps,
    /// Timestamps from FILE_NAME attribute
    pub fn_timestamps: MftTimestamps,
    /// Alternative Data Streams associated with this file
    pub alternate_data_streams: Vec<AlternateDataStream>,
    /// Full directory path (available in two-pass mode)
    pub location: Option<String>,
}

/// NTFS timestamp collection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MftTimestamps {
    /// File creation time
    pub created: Option<DateTime<Utc>>,
    /// Last modification time
    pub modified: Option<DateTime<Utc>>,
    /// MFT record modification time
    pub mft_modified: Option<DateTime<Utc>>,
    /// Last access time
    pub accessed: Option<DateTime<Utc>>,
}

/// Alternative Data Stream information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlternateDataStream {
    /// Stream name
    pub name: String,
    /// Stream size in bytes
    pub size: u64,
    /// Whether the stream is resident (stored in MFT record)
    pub resident: bool,
}

/// ATTRIBUTE_LIST entry pointing to attributes in other MFT records
#[derive(Debug, Clone)]
pub struct AttributeListEntry {
    /// Attribute type (e.g., 0x80 for DATA)
    pub attribute_type: u32,
    /// Length of this attribute list entry
    pub length: u16,
    /// Length of the attribute name in characters
    pub name_length: u8,
    /// Offset to the attribute name within this entry
    pub name_offset: u8,
    /// Starting VCN if the attribute is non-resident
    pub start_vcn: u64,
    /// MFT record number containing the attribute
    pub mft_reference: u64,
    /// Attribute ID
    pub attribute_id: u16,
    /// Attribute name (if present)
    pub name: String,
}

/// MFT file format detection result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MftFormat {
    /// Dense format with records at fixed 1024-byte intervals
    Dense,
    /// Sparse format with only valid records present
    Sparse,
}

/// A single timeline event extracted from MFT record timestamps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// Filename from the MFT record
    pub filename: String,
    /// The timestamp for this event
    pub timestamp: DateTime<Utc>,
    /// Type of timestamp (Created/Modified/MftModified/Accessed)
    pub timestamp_type: TimestampType,
    /// Source of timestamp ($STANDARD_INFORMATION or $FILE_NAME)
    pub timestamp_source: TimestampSource,
    /// MFT record number
    pub mft_record_number: u64,
    /// Full path/location of the file
    pub location: String,
    /// File size in bytes (for display purposes)
    pub file_size: Option<u64>,
    /// Whether this record represents a directory
    pub is_directory: bool,
}

/// Type of timestamp in the timeline
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimestampType {
    Created,
    Modified,
    MftModified,
    Accessed,
}

/// Source of the timestamp
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimestampSource {
    StandardInformation,
    FileName,
}

impl TimestampType {
    /// Get the display name for the timestamp type
    pub fn display_name(&self) -> &'static str {
        match self {
            TimestampType::Created => "File/folder created",
            TimestampType::Modified => "File/folder modified", 
            TimestampType::MftModified => "File/folder index record modified",
            TimestampType::Accessed => "File/folder accessed",
        }
    }

    /// Get the priority order for sorting (lower number = higher priority)
    /// Order: Created (0) > Modified (1) > MftModified (2) > Accessed (3)
    pub fn sort_priority(&self) -> u8 {
        match self {
            TimestampType::Created => 0,
            TimestampType::Modified => 1,
            TimestampType::MftModified => 2,
            TimestampType::Accessed => 3,
        }
    }
}

impl TimestampSource {
    /// Get the short form for display
    pub fn short_form(&self) -> &'static str {
        match self {
            TimestampSource::StandardInformation => "$STANDARD_INFORMATION",
            TimestampSource::FileName => "$FILE_NAME",
        }
    }
}

/// Configuration for MFT parsing behavior
#[derive(Debug, Clone)]
pub struct ParsingConfig {
    /// Maximum recursion depth for path building
    pub max_path_depth: usize,
    /// Enable parallel processing
    pub parallel_processing: bool,
}

impl Default for ParsingConfig {
    fn default() -> Self {
        Self {
            max_path_depth: 50,
            parallel_processing: true,
        }
    }
}

impl ParsingConfig {
    /// Create a configuration optimized for maximum performance
    pub fn optimized() -> Self {
        Self {
            max_path_depth: 30,
            parallel_processing: true,
        }
    }

    /// Create a configuration for fast processing
    pub fn fast() -> Self {
        Self {
            max_path_depth: 20,
            parallel_processing: true,
        }
    }
}

impl MftRecord {
    /// Extract all timeline events from this MFT record
    /// Returns up to 8 events (4 from SI, 4 from FN) if timestamps are present
    pub fn extract_timeline_events(&self) -> Vec<TimelineEvent> {
        let mut events = Vec::new();
        let filename = self.filename.as_deref().unwrap_or("N/A").to_string();
        let location = self.location.as_deref().unwrap_or("\\").to_string();

        // Extract SI timestamps
        if let Some(ts) = self.timestamps.created {
            events.push(TimelineEvent {
                filename: filename.clone(),
                timestamp: ts,
                timestamp_type: TimestampType::Created,
                timestamp_source: TimestampSource::StandardInformation,
                mft_record_number: self.record_number,
                location: location.clone(),
                file_size: self.file_size,
                is_directory: self.is_directory,
            });
        }

        if let Some(ts) = self.timestamps.modified {
            events.push(TimelineEvent {
                filename: filename.clone(),
                timestamp: ts,
                timestamp_type: TimestampType::Modified,
                timestamp_source: TimestampSource::StandardInformation,
                mft_record_number: self.record_number,
                location: location.clone(),
                file_size: self.file_size,
                is_directory: self.is_directory,
            });
        }

        if let Some(ts) = self.timestamps.mft_modified {
            events.push(TimelineEvent {
                filename: filename.clone(),
                timestamp: ts,
                timestamp_type: TimestampType::MftModified,
                timestamp_source: TimestampSource::StandardInformation,
                mft_record_number: self.record_number,
                location: location.clone(),
                file_size: self.file_size,
                is_directory: self.is_directory,
            });
        }

        if let Some(ts) = self.timestamps.accessed {
            events.push(TimelineEvent {
                filename: filename.clone(),
                timestamp: ts,
                timestamp_type: TimestampType::Accessed,
                timestamp_source: TimestampSource::StandardInformation,
                mft_record_number: self.record_number,
                location: location.clone(),
                file_size: self.file_size,
                is_directory: self.is_directory,
            });
        }

        // Extract FN timestamps
        if let Some(ts) = self.fn_timestamps.created {
            events.push(TimelineEvent {
                filename: filename.clone(),
                timestamp: ts,
                timestamp_type: TimestampType::Created,
                timestamp_source: TimestampSource::FileName,
                mft_record_number: self.record_number,
                location: location.clone(),
                file_size: self.file_size,
                is_directory: self.is_directory,
            });
        }

        if let Some(ts) = self.fn_timestamps.modified {
            events.push(TimelineEvent {
                filename: filename.clone(),
                timestamp: ts,
                timestamp_type: TimestampType::Modified,
                timestamp_source: TimestampSource::FileName,
                mft_record_number: self.record_number,
                location: location.clone(),
                file_size: self.file_size,
                is_directory: self.is_directory,
            });
        }

        if let Some(ts) = self.fn_timestamps.mft_modified {
            events.push(TimelineEvent {
                filename: filename.clone(),
                timestamp: ts,
                timestamp_type: TimestampType::MftModified,
                timestamp_source: TimestampSource::FileName,
                mft_record_number: self.record_number,
                location: location.clone(),
                file_size: self.file_size,
                is_directory: self.is_directory,
            });
        }

        if let Some(ts) = self.fn_timestamps.accessed {
            events.push(TimelineEvent {
                filename: filename.clone(),
                timestamp: ts,
                timestamp_type: TimestampType::Accessed,
                timestamp_source: TimestampSource::FileName,
                mft_record_number: self.record_number,
                location: location.clone(),
                file_size: self.file_size,
                is_directory: self.is_directory,
            });
        }

        events
    }
}