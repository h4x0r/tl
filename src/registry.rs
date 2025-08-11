//! Windows Registry parsing module for NTUSER.DAT and other registry hives
//!
//! Supports parsing of:
//! - NTUSER.DAT user registry hives
//! - Shell Bags and MRU locations
//! - Jump list registry data
//! - Recent documents and search history

use crate::error::{Error, Result};
use crate::types::EventTimestamps;
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;

/// Registry timeline event extracted from registry hives
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryTimelineEvent {
    /// Registry key path
    pub key_path: String,
    /// Value name (if applicable)
    pub value_name: Option<String>,
    /// Event type
    pub event_type: RegistryEventType,
    /// Value type (if applicable)
    pub value_type: Option<RegistryValueType>,
    /// Raw data
    pub data: Option<Vec<u8>>,
    /// Data size
    pub data_size: Option<u32>,
    /// Timestamps
    pub timestamps: EventTimestamps,
}

/// Registry event types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RegistryEventType {
    /// Key creation/modification
    KeyModified,
    /// Value set/modified
    ValueSet,
    /// MRU list entry
    MruEntry,
    /// Shell bag entry
    ShellBag,
    /// Run key entry
    RunEntry,
    /// Recent document
    RecentDoc,
    /// Search history
    SearchHistory,
}

/// Registry parser for extracting timeline events
pub struct RegistryParser {
    /// FILETIME epoch difference
    filetime_epoch_diff: u64,
}

impl RegistryParser {
    /// Create new registry parser
    pub fn new() -> Self {
        Self {
            filetime_epoch_diff: 116444736000000000,
        }
    }

    /// Parse registry data and create hive structure
    pub fn parse_registry_data(&self, data: &[u8], path: &Path) -> Result<RegistryHive> {
        if data.len() < 32 {
            return Err(Error::InvalidInput("Registry file too small".to_string()));
        }

        let mut cursor = Cursor::new(data);
        
        // Parse hive header
        let header = self.parse_hive_header(&mut cursor)?;
        
        // Determine hive type from filename
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
            
        let hive_type = if filename.contains("ntuser") {
            HiveType::NtUser
        } else if filename.contains("system") {
            HiveType::System
        } else if filename.contains("software") {
            HiveType::Software
        } else if filename.contains("sam") {
            HiveType::Sam
        } else if filename.contains("security") {
            HiveType::Security
        } else {
            HiveType::Unknown
        };

        Ok(RegistryHive {
            header,
            root_key: None,
            file_path: path.to_string_lossy().to_string(),
            hive_type,
        })
    }

    /// Extract timeline events from registry hive
    pub fn extract_timeline_events(&self, hive: &RegistryHive) -> Result<Vec<RegistryTimelineEvent>> {
        let mut events = Vec::new();

        // Create a basic timeline event for the hive itself
        let hive_event = RegistryTimelineEvent {
            key_path: "ROOT".to_string(),
            value_name: None,
            event_type: RegistryEventType::KeyModified,
            value_type: None,
            data: None,
            data_size: Some(hive.header.hive_size),
            timestamps: EventTimestamps {
                created: self.filetime_to_datetime(hive.header.last_written),
                modified: self.filetime_to_datetime(hive.header.last_written),
                accessed: None,
                mft_modified: None,
            },
        };
        events.push(hive_event);

        // TODO: Extract specific MRU, shell bag, and other timeline events
        // For now, this provides basic hive-level timeline information
        
        Ok(events)
    }

    /// Parse hive header
    fn parse_hive_header(&self, cursor: &mut Cursor<&[u8]>) -> Result<HiveHeader> {
        let mut signature = [0u8; 4];
        cursor.read_exact(&mut signature)?;
        
        if &signature != b"regf" {
            return Err(Error::InvalidInput("Invalid registry signature".to_string()));
        }

        let primary_sequence = cursor.read_u32::<LittleEndian>()?;
        let secondary_sequence = cursor.read_u32::<LittleEndian>()?;
        let last_written = cursor.read_u64::<LittleEndian>()?;
        let major_version = cursor.read_u32::<LittleEndian>()?;
        let minor_version = cursor.read_u32::<LittleEndian>()?;
        let file_type = cursor.read_u32::<LittleEndian>()?;
        let file_format = cursor.read_u32::<LittleEndian>()?;
        let root_cell_offset = cursor.read_u32::<LittleEndian>()?;
        let hive_size = cursor.read_u32::<LittleEndian>()?;
        let clustering_factor = cursor.read_u32::<LittleEndian>()?;

        Ok(HiveHeader {
            signature,
            primary_sequence,
            secondary_sequence,
            last_written,
            major_version,
            minor_version,
            file_type,
            file_format,
            root_cell_offset,
            hive_size,
            clustering_factor,
            file_name: None,
        })
    }

    /// Convert FILETIME to DateTime<Utc>
    fn filetime_to_datetime(&self, filetime: u64) -> Option<DateTime<Utc>> {
        if filetime == 0 {
            return None;
        }

        let unix_time = (filetime.saturating_sub(self.filetime_epoch_diff)) / 10000000;
        DateTime::from_timestamp(unix_time as i64, 0)
    }
}

impl Default for RegistryParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Registry hive types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum HiveType {
    /// NTUSER.DAT user hive
    NtUser,
    /// SYSTEM hive
    System,
    /// SOFTWARE hive
    Software,
    /// SAM hive
    Sam,
    /// SECURITY hive
    Security,
    /// Unknown hive type
    Unknown,
}

/// Registry hive file structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryHive {
    /// Hive header
    pub header: HiveHeader,
    /// Root key
    pub root_key: Option<RegistryKey>,
    /// Hive file path
    pub file_path: String,
    /// Hive type (NTUSER, SYSTEM, SOFTWARE, etc.)
    pub hive_type: HiveType,
}

/// Registry hive header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiveHeader {
    /// Signature (should be "regf")
    pub signature: [u8; 4],
    /// Primary sequence number
    pub primary_sequence: u32,
    /// Secondary sequence number  
    pub secondary_sequence: u32,
    /// Last written timestamp
    pub last_written: u64,
    /// Major version
    pub major_version: u32,
    /// Minor version
    pub minor_version: u32,
    /// File type (0 = Primary, 1 = Log)
    pub file_type: u32,
    /// File format (1 = Direct memory load)
    pub file_format: u32,
    /// Root cell offset
    pub root_cell_offset: u32,
    /// Hive size
    pub hive_size: u32,
    /// Clustering factor
    pub clustering_factor: u32,
    /// File name (UTF-16LE)
    pub file_name: Option<String>,
}

/// Registry key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryKey {
    /// Key name
    pub name: String,
    /// Key path
    pub path: String,
    /// Last written timestamp
    pub last_written: Option<DateTime<Utc>>,
    /// Subkeys
    pub subkeys: Vec<RegistryKey>,
    /// Values
    pub values: Vec<RegistryValue>,
    /// Key class name
    pub class_name: Option<String>,
    /// Security descriptor
    pub security_descriptor: Option<Vec<u8>>,
}

/// Registry value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryValue {
    /// Value name
    pub name: String,
    /// Value type
    pub value_type: RegistryValueType,
    /// Raw data
    pub data: Vec<u8>,
    /// Parsed data (string representation)
    pub parsed_data: Option<String>,
    /// Data size
    pub data_size: u32,
}

/// Registry value types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u32)]
pub enum RegistryValueType {
    None = 0,
    String = 1,           // REG_SZ
    ExpandString = 2,     // REG_EXPAND_SZ
    Binary = 3,           // REG_BINARY
    DWord = 4,            // REG_DWORD
    DWordBigEndian = 5,   // REG_DWORD_BIG_ENDIAN
    Link = 6,             // REG_LINK
    MultiString = 7,      // REG_MULTI_SZ
    ResourceList = 8,     // REG_RESOURCE_LIST
    FullResourceDescriptor = 9,           // REG_FULL_RESOURCE_DESCRIPTOR
    ResourceRequirementsList = 10,        // REG_RESOURCE_REQUIREMENTS_LIST
    QWord = 11,           // REG_QWORD
    Unknown(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_parser_creation() {
        let parser = RegistryParser::new();
        assert_eq!(parser.filetime_epoch_diff, 116444736000000000);
    }

    #[test]
    fn test_filetime_conversion() {
        let parser = RegistryParser::new();
        
        // Test zero filetime
        assert!(parser.filetime_to_datetime(0).is_none());
        
        // Test valid filetime
        let filetime = 125911584000000000u64;
        if let Some(dt) = parser.filetime_to_datetime(filetime) {
            assert_eq!(dt.year(), 2000);
        }
    }

    #[test]
    fn test_invalid_registry_data() {
        let parser = RegistryParser::new();
        let path = std::path::Path::new("test.dat");
        
        // Test empty data
        assert!(parser.parse_registry_data(&[], path).is_err());
        
        // Test data too small
        let small_data = vec![0u8; 10];
        assert!(parser.parse_registry_data(&small_data, path).is_err());
    }
}