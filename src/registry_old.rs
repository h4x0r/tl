//! Windows Registry parsing module for NTUSER.DAT and other registry hives
//!
//! Supports parsing of:
//! - NTUSER.DAT user registry hives
//! - Shell Bags and MRU locations
//! - Jump list registry data
//! - Recent documents and search history

use crate::error::{Error, Result};
use crate::types::MftTimestamps;
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
    pub timestamps: MftTimestamps,
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
            root_key: None, // TODO: Parse root key if needed
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
            timestamps: MftTimestamps {
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
            file_name: None, // TODO: Parse filename if needed
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
    Dword = 4,            // REG_DWORD
    DwordBigEndian = 5,   // REG_DWORD_BIG_ENDIAN
    Link = 6,             // REG_LINK
    MultiString = 7,      // REG_MULTI_SZ
    ResourceList = 8,     // REG_RESOURCE_LIST
    FullResourceDescriptor = 9, // REG_FULL_RESOURCE_DESCRIPTOR
    ResourceRequirementsList = 10, // REG_RESOURCE_REQUIREMENTS_LIST
    Qword = 11,           // REG_QWORD
    Unknown(u32),
}

/// Registry hive types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum HiveType {
    NtUser,      // NTUSER.DAT
    System,      // SYSTEM
    Software,    // SOFTWARE
    Sam,         // SAM
    Security,    // SECURITY
    Unknown,
}

/// MRU (Most Recently Used) entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MruEntry {
    /// MRU key path
    pub key_path: String,
    /// Entry index
    pub index: u32,
    /// Entry data
    pub data: Vec<u8>,
    /// Parsed path or name
    pub parsed_value: Option<String>,
    /// Last access time (if available)
    pub last_access: Option<DateTime<Utc>>,
    /// MRU type
    pub mru_type: MruType,
}

/// Types of MRU entries
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum MruType {
    RecentDocs,           // Recent Documents
    BagMru,              // Shell Bags
    OpenSavePidlMru,     // Open/Save Dialog
    LastVisitedPidlMru,  // Last Visited Folders
    WordWheelQuery,      // Search Terms
    JumplistData,        // Jumplist Data
    RecentApps,          // Recent Applications
    TaskBand,            // Taskbar
    StartPage,           // Start Menu
    LockScreen,          // Lock Screen
    Unknown,
}

/// Shell Bag entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellBag {
    /// Bag key path
    pub key_path: String,
    /// Bag ID
    pub bag_id: u32,
    /// Shell item data
    pub shell_item_data: Vec<u8>,
    /// Parsed path
    pub path: Option<String>,
    /// Folder size
    pub folder_size: Option<u64>,
    /// Last access time
    pub last_access: Option<DateTime<Utc>>,
    /// View settings
    pub view_settings: Option<HashMap<String, String>>,
}

impl RegistryHive {
    /// Parse a registry hive file
    pub fn parse_file<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        let path = file_path.as_ref();
        let data = std::fs::read(path)?;
        Self::parse(&data, path.to_string_lossy().to_string())
    }
    
    /// Parse registry hive from bytes
    pub fn parse(data: &[u8], file_path: String) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        
        // Parse hive header
        let header = HiveHeader::parse(&mut cursor)?;
        
        // Determine hive type from file path
        let hive_type = Self::determine_hive_type(&file_path);
        
        let mut hive = RegistryHive {
            header,
            root_key: None,
            file_path,
            hive_type,
        };
        
        // Parse root key if offset is valid
        if hive.header.root_cell_offset > 0 {
            cursor.seek(SeekFrom::Start(0x1000 + hive.header.root_cell_offset as u64))?;
            hive.root_key = Some(RegistryKey::parse(&mut cursor, "".to_string())?);
        }
        
        Ok(hive)
    }
    
    fn determine_hive_type(file_path: &str) -> HiveType {
        let path_lower = file_path.to_lowercase();
        if path_lower.contains("ntuser.dat") {
            HiveType::NtUser
        } else if path_lower.contains("system") {
            HiveType::System
        } else if path_lower.contains("software") {
            HiveType::Software
        } else if path_lower.contains("sam") {
            HiveType::Sam
        } else if path_lower.contains("security") {
            HiveType::Security
        } else {
            HiveType::Unknown
        }
    }
    
    /// Find all MRU entries in the hive
    pub fn find_mru_entries(&self) -> Vec<MruEntry> {
        let mut entries = Vec::new();
        
        if let Some(root) = &self.root_key {
            self.find_mru_recursive(root, &mut entries);
        }
        
        entries
    }
    
    fn find_mru_recursive(&self, key: &RegistryKey, entries: &mut Vec<MruEntry>) {
        // Check if this key is an MRU location
        let mru_type = self.determine_mru_type(&key.path);
        if mru_type != MruType::Unknown {
            // Parse MRU entries in this key
            for value in &key.values {
                if let Some(entry) = self.parse_mru_value(key, value, mru_type) {
                    entries.push(entry);
                }
            }
        }
        
        // Recursively search subkeys
        for subkey in &key.subkeys {
            self.find_mru_recursive(subkey, entries);
        }
    }
    
    fn determine_mru_type(&self, key_path: &str) -> MruType {
        let path_lower = key_path.to_lowercase();
        
        if path_lower.contains("recentdocs") {
            MruType::RecentDocs
        } else if path_lower.contains("bagmru") {
            MruType::BagMru
        } else if path_lower.contains("opensavepidlmru") {
            MruType::OpenSavePidlMru
        } else if path_lower.contains("lastvisitedpidlmru") {
            MruType::LastVisitedPidlMru
        } else if path_lower.contains("wordwheelquery") {
            MruType::WordWheelQuery
        } else if path_lower.contains("jumplistdata") {
            MruType::JumplistData
        } else if path_lower.contains("recentapps") {
            MruType::RecentApps
        } else if path_lower.contains("taskband") {
            MruType::TaskBand
        } else if path_lower.contains("startpage") {
            MruType::StartPage
        } else if path_lower.contains("lock screen") {
            MruType::LockScreen
        } else {
            MruType::Unknown
        }
    }
    
    fn parse_mru_value(&self, key: &RegistryKey, value: &RegistryValue, mru_type: MruType) -> Option<MruEntry> {
        // Skip MRUList values - they contain ordering information
        if value.name.to_lowercase() == "mrulist" {
            return None;
        }
        
        // Try to parse the index from the value name
        let index = if let Ok(idx) = value.name.parse::<u32>() {
            idx
        } else {
            0
        };
        
        let parsed_value = match mru_type {
            MruType::RecentDocs => self.parse_recent_docs_value(&value.data),
            MruType::WordWheelQuery => self.parse_word_wheel_query(&value.data),
            MruType::BagMru => self.parse_shell_bag_value(&value.data),
            _ => self.parse_generic_mru_value(&value.data),
        };
        
        Some(MruEntry {
            key_path: key.path.clone(),
            index,
            data: value.data.clone(),
            parsed_value,
            last_access: key.last_written,
            mru_type,
        })
    }
    
    fn parse_recent_docs_value(&self, data: &[u8]) -> Option<String> {
        // Recent docs values often contain Unicode strings
        if data.len() >= 2 {
            let utf16_data: Vec<u16> = data.chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .take_while(|&c| c != 0)
                .collect();
            
            if !utf16_data.is_empty() {
                return Some(String::from_utf16_lossy(&utf16_data));
            }
        }
        None
    }
    
    fn parse_word_wheel_query(&self, data: &[u8]) -> Option<String> {
        // Word wheel queries are typically Unicode strings
        if data.len() >= 2 {
            let utf16_data: Vec<u16> = data.chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .take_while(|&c| c != 0)
                .collect();
            
            if !utf16_data.is_empty() {
                return Some(String::from_utf16_lossy(&utf16_data));
            }
        }
        None
    }
    
    fn parse_shell_bag_value(&self, data: &[u8]) -> Option<String> {
        // Shell bag values contain complex shell item data
        // This is a simplified parser - real shell items are quite complex
        if data.len() >= 4 {
            return Some(format!("ShellBag ({} bytes)", data.len()));
        }
        None
    }
    
    fn parse_generic_mru_value(&self, data: &[u8]) -> Option<String> {
        // Try to parse as Unicode string first
        if data.len() >= 2 && data.len() % 2 == 0 {
            let utf16_data: Vec<u16> = data.chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .take_while(|&c| c != 0)
                .collect();
            
            if !utf16_data.is_empty() {
                return Some(String::from_utf16_lossy(&utf16_data));
            }
        }
        
        // Try ASCII
        if let Some(null_pos) = data.iter().position(|&b| b == 0) {
            if let Ok(s) = std::str::from_utf8(&data[..null_pos]) {
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
        
        // Return hex representation if no string parsing works
        if !data.is_empty() {
            Some(format!("Binary ({} bytes): {}", data.len(), 
                data.iter().take(16).map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")))
        } else {
            None
        }
    }
    
    /// Find all shell bags in the hive
    pub fn find_shell_bags(&self) -> Vec<ShellBag> {
        let mut bags = Vec::new();
        
        if let Some(root) = &self.root_key {
            self.find_shell_bags_recursive(root, &mut bags);
        }
        
        bags
    }
    
    fn find_shell_bags_recursive(&self, key: &RegistryKey, bags: &mut Vec<ShellBag>) {
        // Check if this key path indicates shell bags
        if key.path.to_lowercase().contains("shell\\bags") {
            // Parse shell bag data from this key
            for value in &key.values {
                if value.name == "0" || value.name == "1" { // Common shell item value names
                    let bag = ShellBag {
                        key_path: key.path.clone(),
                        bag_id: key.name.parse().unwrap_or(0),
                        shell_item_data: value.data.clone(),
                        path: self.parse_shell_bag_value(&value.data),
                        folder_size: None,
                        last_access: key.last_written,
                        view_settings: None,
                    };
                    bags.push(bag);
                }
            }
        }
        
        // Recursively search subkeys
        for subkey in &key.subkeys {
            self.find_shell_bags_recursive(subkey, bags);
        }
    }
}

impl HiveHeader {
    fn parse(cursor: &mut Cursor<&[u8]>) -> Result<Self> {
        let mut signature = [0u8; 4];
        cursor.read_exact(&mut signature)?;
        
        if &signature != b"regf" {
            return Err(Error::ParseError("Invalid registry hive signature".to_string()));
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
        
        // Skip to file name field and parse it
        cursor.seek(SeekFrom::Start(0x30))?;
        let mut file_name_utf16 = [0u16; 32];
        for i in 0..32 {
            file_name_utf16[i] = cursor.read_u16::<LittleEndian>()?;
        }
        
        let file_name = if file_name_utf16[0] != 0 {
            let null_pos = file_name_utf16.iter().position(|&c| c == 0).unwrap_or(32);
            Some(String::from_utf16_lossy(&file_name_utf16[..null_pos]))
        } else {
            None
        };
        
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
            file_name,
        })
    }
}

impl RegistryKey {
    fn parse(_cursor: &mut Cursor<&[u8]>, parent_path: String) -> Result<Self> {
        // This is a simplified registry key parser
        // Real registry parsing is much more complex
        
        Ok(RegistryKey {
            name: "Root".to_string(),
            path: if parent_path.is_empty() { "Root".to_string() } else { parent_path },
            last_written: None,
            subkeys: Vec::new(),
            values: Vec::new(),
            class_name: None,
            security_descriptor: None,
        })
    }
}

impl From<u32> for RegistryValueType {
    fn from(value: u32) -> Self {
        match value {
            0 => RegistryValueType::None,
            1 => RegistryValueType::String,
            2 => RegistryValueType::ExpandString,
            3 => RegistryValueType::Binary,
            4 => RegistryValueType::Dword,
            5 => RegistryValueType::DwordBigEndian,
            6 => RegistryValueType::Link,
            7 => RegistryValueType::MultiString,
            8 => RegistryValueType::ResourceList,
            9 => RegistryValueType::FullResourceDescriptor,
            10 => RegistryValueType::ResourceRequirementsList,
            11 => RegistryValueType::Qword,
            _ => RegistryValueType::Unknown(value),
        }
    }
}

/// Get known MRU registry locations for NTUSER.DAT
pub fn get_ntuser_mru_locations() -> Vec<&'static str> {
    vec![
        "Software\\Microsoft\\Windows\\Shell\\BagMRU",
        "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRULegacy",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TWinUI\\FilePicker\\LastVisitedPidlMRU",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Streams",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StreamMRU",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Search\\JumplistData",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Taskband\\Favorites",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Taskband\\FavoritesResolve",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartPage2\\Favorites",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartPage2\\FavoritesResolve",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartPage2\\ProgramsCache",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartPage2\\ProgramsCacheSMP",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartPage2\\ProgramsCacheTBP",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Lock Screen",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_registry_value_type_conversion() {
        assert!(matches!(RegistryValueType::from(1), RegistryValueType::String));
        assert!(matches!(RegistryValueType::from(3), RegistryValueType::Binary));
        assert!(matches!(RegistryValueType::from(999), RegistryValueType::Unknown(999)));
    }
    
    #[test]
    fn test_hive_type_detection() {
        assert!(matches!(
            RegistryHive::determine_hive_type("C:\\Users\\user\\NTUSER.DAT"),
            HiveType::NtUser
        ));
        assert!(matches!(
            RegistryHive::determine_hive_type("C:\\Windows\\System32\\config\\SYSTEM"),
            HiveType::System
        ));
    }
    
    #[test]
    fn test_mru_locations() {
        let locations = get_ntuser_mru_locations();
        assert!(locations.contains(&"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"));
        assert!(locations.len() > 10);
    }
}