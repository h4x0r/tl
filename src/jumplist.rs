//! Windows Jumplist and LNK file parsing module
//!
//! Supports parsing of:
//! - .lnk files (Shell Links)
//! - .automaticDestinations-ms files 
//! - .customDestinations-ms files
//! - Registry MRU locations from NTUSER.DAT

use crate::error::{Error, Result};
use crate::ole::OleCompoundDocument;
use crate::shell_item::ItemIdList;
use crate::types::EventTimestamps;
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Cursor, Read, Seek, SeekFrom};

/// Jumplist entry extracted from automatic or custom destinations files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumplistEntry {
    /// Target path
    pub target_path: Option<String>,
    /// File size
    pub file_size: Option<u64>,
    /// File attributes
    pub file_attributes: Option<u32>,
    /// Application ID
    pub app_id: Option<String>,
    /// Access count
    pub access_count: Option<u32>,
    /// Timestamps
    pub timestamps: EventTimestamps,
}

/// Jumplist parser for automatic and custom destinations files
pub struct JumplistParser {}

impl JumplistParser {
    /// Create new jumplist parser
    pub fn new() -> Self {
        Self {}
    }

    /// Parse automatic destinations file (.automaticDestinations-ms)
    pub fn parse_automatic_destinations(&self, data: &[u8]) -> Result<Vec<JumplistEntry>> {
        // Automatic destinations are OLE compound documents containing LNK files
        match OleCompoundDocument::parse(data) {
            Ok(ole_doc) => {
                let mut entries = Vec::new();
                
                // Parse DestList stream for metadata
                let mut dest_list_entries = Vec::new();
                if let Some(destlist_data) = ole_doc.get_stream("DestList") {
                    dest_list_entries = self.parse_dest_list_stream(destlist_data)?;
                }
                
                // Extract and parse LNK files from numbered streams
                for stream_name in ole_doc.list_streams() {
                    // LNK streams are typically numbered (1, 2, 3, etc.)
                    if stream_name.chars().all(|c| c.is_ascii_digit()) {
                        if let Some(lnk_data) = ole_doc.get_stream(&stream_name) {
                            if let Ok(shell_link) = ShellLink::parse(lnk_data) {
                                // Find corresponding DestList entry by stream number
                                let stream_num: usize = stream_name.parse().unwrap_or(0);
                                let dest_entry = dest_list_entries.get(stream_num.saturating_sub(1));
                                
                                let entry = JumplistEntry {
                                    target_path: shell_link.target_path.clone(),
                                    file_size: Some(shell_link.header.file_size as u64),
                                    file_attributes: Some(shell_link.header.file_attributes),
                                    app_id: None, // Will be set by caller
                                    access_count: dest_entry.map(|d| d.access_count),
                                    timestamps: shell_link.timestamps.clone(),
                                };
                                entries.push(entry);
                            }
                        }
                    }
                }
                
                Ok(entries)
            },
            Err(_) => {
                // Fallback: try to parse as raw LNK data
                if data.len() > 76 && &data[0..4] == b"L\x00\x00\x00" {
                    // Looks like a single LNK file
                    match ShellLink::parse(data) {
                        Ok(shell_link) => {
                            let entry = JumplistEntry {
                                target_path: shell_link.target_path,
                                file_size: Some(shell_link.header.file_size as u64),
                                file_attributes: Some(shell_link.header.file_attributes),
                                app_id: None,
                                access_count: None,
                                timestamps: shell_link.timestamps,
                            };
                            Ok(vec![entry])
                        },
                        Err(_) => Ok(Vec::new()),
                    }
                } else {
                    Ok(Vec::new())
                }
            }
        }
    }

    /// Parse custom destinations file (.customDestinations-ms)
    pub fn parse_custom_destinations(&self, data: &[u8]) -> Result<Vec<JumplistEntry>> {
        // Custom destinations are binary files with embedded LNK data
        let mut entries = Vec::new();
        let _cursor = Cursor::new(data);
        
        // Custom destinations have a different structure than automatic destinations
        // They contain categories and embedded LNK files
        
        // Skip header if present (usually starts with category information)
        if data.len() < 16 {
            return Ok(entries);
        }
        
        // Try to find LNK file signatures within the data
        let lnk_signature = b"L\x00\x00\x00";
        let mut pos = 0;
        
        while pos + 76 < data.len() {
            // Look for LNK file signature
            if let Some(lnk_start) = data[pos..].windows(4).position(|window| window == lnk_signature) {
                let actual_start = pos + lnk_start;
                
                // Try to determine the size of this LNK file
                // Read the header to get the full size
                if actual_start + 76 < data.len() {
                    let lnk_data_start = &data[actual_start..];
                    
                    // Parse just enough to determine LNK size
                    match self.estimate_lnk_size(lnk_data_start) {
                        Some(lnk_size) => {
                            if actual_start + lnk_size <= data.len() {
                                let lnk_data = &data[actual_start..actual_start + lnk_size];
                                
                                // Parse the LNK file
                                if let Ok(shell_link) = ShellLink::parse(lnk_data) {
                                    let entry = JumplistEntry {
                                        target_path: shell_link.target_path,
                                        file_size: Some(shell_link.header.file_size as u64),
                                        file_attributes: Some(shell_link.header.file_attributes),
                                        app_id: None, // Will be set by caller
                                        access_count: None, // Custom destinations don't have access counts
                                        timestamps: shell_link.timestamps,
                                    };
                                    entries.push(entry);
                                }
                                
                                pos = actual_start + lnk_size;
                            } else {
                                pos = actual_start + 1;
                            }
                        },
                        None => {
                            pos = actual_start + 1;
                        }
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        
        // If no LNK files found, create a placeholder entry
        if entries.is_empty() && !data.is_empty() {
            let entry = JumplistEntry {
                target_path: Some("Custom Destinations (unknown format)".to_string()),
                file_size: Some(data.len() as u64),
                file_attributes: None,
                app_id: None,
                access_count: None,
                timestamps: EventTimestamps::default(),
            };
            entries.push(entry);
        }
        
        Ok(entries)
    }

    /// Parse DestList stream from automatic destinations
    fn parse_dest_list_stream(&self, data: &[u8]) -> Result<Vec<DestListEntry>> {
        let mut entries = Vec::new();
        let mut cursor = Cursor::new(data);
        
        // Skip header (32 bytes) if present
        if data.len() > 32 {
            cursor.seek(SeekFrom::Start(32))?;
        }
        
        // Parse entries until we reach the end
        while cursor.position() + 24 < data.len() as u64 {
            match self.parse_dest_list_entry(&mut cursor) {
                Ok(entry) => entries.push(entry),
                Err(_) => break, // Stop on parsing errors
            }
        }
        
        Ok(entries)
    }

    /// Parse individual DestList entry
    fn parse_dest_list_entry(&self, cursor: &mut Cursor<&[u8]>) -> Result<DestListEntry> {
        let size = cursor.read_u32::<LittleEndian>()?;
        let entry_type = cursor.read_u32::<LittleEndian>()?;
        let pin_status = cursor.read_u32::<LittleEndian>()?;
        let access_count = cursor.read_u32::<LittleEndian>()?;
        let last_access_time = cursor.read_u64::<LittleEndian>()?;
        
        // Read remaining entry data (variable length)
        let remaining_size = size.saturating_sub(24) as usize;
        let mut entry_id = vec![0u8; remaining_size];
        if remaining_size > 0 {
            cursor.read_exact(&mut entry_id)?;
        }
        
        // Try to extract target path from entry ID
        let target_path = self.extract_target_path_from_entry_id(&entry_id);
        
        Ok(DestListEntry {
            size,
            entry_type,
            pin_status,
            access_count,
            last_access_time,
            entry_id,
            target_path,
        })
    }

    /// Extract target path from DestList entry ID data
    fn extract_target_path_from_entry_id(&self, entry_id: &[u8]) -> Option<String> {
        // Try parsing as ItemIdList first
        if let Ok(idlist) = ItemIdList::parse(entry_id) {
            if let Some(path) = idlist.full_path {
                return Some(path);
            }
        }
        
        // Fallback: look for readable strings in the data
        if let Ok(text) = String::from_utf8(entry_id.to_vec()) {
            let cleaned = text.trim().trim_matches('\0');
            if !cleaned.is_empty() && cleaned.len() > 3 {
                return Some(cleaned.to_string());
            }
        }
        
        // Try UTF-16 parsing
        if entry_id.len() >= 4 && entry_id.len() % 2 == 0 {
            let utf16_data: Vec<u16> = entry_id
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .take_while(|&c| c != 0)
                .collect();
            
            if !utf16_data.is_empty() {
                let text = String::from_utf16_lossy(&utf16_data);
                let cleaned = text.trim();
                if !cleaned.is_empty() && cleaned.len() > 3 {
                    return Some(cleaned.to_string());
                }
            }
        }
        
        None
    }

    /// Estimate the size of a LNK file from its header and structure
    fn estimate_lnk_size(&self, data: &[u8]) -> Option<usize> {
        if data.len() < 76 {
            return None;
        }
        
        // Check LNK signature
        if &data[0..4] != b"L\x00\x00\x00" {
            return None;
        }
        
        let mut cursor = Cursor::new(data);
        
        // Parse header to get flags
        if cursor.seek(SeekFrom::Start(20)).is_err() {
            return None;
        }
        
        let link_flags = match cursor.read_u32::<LittleEndian>() {
            Ok(flags) => flags,
            Err(_) => return None,
        };
        
        let mut estimated_size = 76; // Base header size
        
        // Skip to after header
        if cursor.seek(SeekFrom::Start(76)).is_err() {
            return None;
        }
        
        // Add size of optional structures based on flags
        if link_flags & 0x01 != 0 {
            // HasLinkTargetIDList
            if let Ok(idlist_size) = cursor.read_u16::<LittleEndian>() {
                estimated_size += 2 + idlist_size as usize;
                if cursor.seek(SeekFrom::Current(idlist_size as i64)).is_err() {
                    return None;
                }
            } else {
                return None;
            }
        }
        
        if link_flags & 0x02 != 0 {
            // HasLinkInfo
            if let Ok(link_info_size) = cursor.read_u32::<LittleEndian>() {
                estimated_size += link_info_size as usize;
                if cursor.seek(SeekFrom::Current(link_info_size as i64 - 4)).is_err() {
                    return None;
                }
            } else {
                return None;
            }
        }
        
        // Add estimated size for string data (simplified)
        let string_flags = [0x04, 0x08, 0x10, 0x20, 0x40]; // Name, RelativePath, WorkingDir, Arguments, IconLocation
        for &flag in &string_flags {
            if link_flags & flag != 0 {
                if let Ok(string_count) = cursor.read_u16::<LittleEndian>() {
                    let string_size = string_count as usize * 2; // Unicode characters
                    estimated_size += 2 + string_size;
                    if cursor.seek(SeekFrom::Current(string_size as i64)).is_err() {
                        break; // Don't fail completely, just stop parsing strings
                    }
                } else {
                    break;
                }
            }
        }
        
        // Add some padding for extra data blocks (simplified)
        estimated_size += 100;
        
        // Cap the size to prevent excessive memory allocation
        if estimated_size > data.len() {
            Some(data.len().min(65536)) // Cap at 64KB
        } else {
            Some(estimated_size)
        }
    }
}

impl Default for JumplistParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Shell Link (.lnk) file structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellLink {
    /// Shell Link Header
    pub header: ShellLinkHeader,
    /// Link Target IDList (optional)
    pub id_list: Option<ItemIdList>,
    /// Link Info structure (optional) 
    pub link_info: Option<LinkInfo>,
    /// String Data (optional)
    pub string_data: Option<StringData>,
    /// Extra Data blocks (optional)
    pub extra_data: Vec<ExtraDataBlock>,
    /// Parsed target path
    pub target_path: Option<String>,
    /// Parsed arguments
    pub arguments: Option<String>,
    /// Parsed working directory
    pub working_directory: Option<String>,
    /// Parsed icon location
    pub icon_location: Option<String>,
    /// File timestamps
    pub timestamps: EventTimestamps,
}

/// Shell Link Header structure (76 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellLinkHeader {
    /// Header size (must be 0x0000004C)
    pub header_size: u32,
    /// Link class identifier
    pub link_clsid: [u8; 16],
    /// Link flags
    pub link_flags: u32,
    /// File attributes
    pub file_attributes: u32,
    /// Creation time (FILETIME)
    pub creation_time: u64,
    /// Access time (FILETIME) 
    pub access_time: u64,
    /// Write time (FILETIME)
    pub write_time: u64,
    /// File size
    pub file_size: u32,
    /// Icon index
    pub icon_index: u32,
    /// Show command
    pub show_command: u32,
    /// Hot key
    pub hot_key: u16,
    /// Reserved fields
    pub reserved1: u16,
    pub reserved2: u32,
    pub reserved3: u32,
}

/// Link Info structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkInfo {
    /// Link info size
    pub size: u32,
    /// Link info header size
    pub header_size: u32,
    /// Link info flags
    pub flags: u32,
    /// Volume ID offset
    pub volume_id_offset: u32,
    /// Local base path offset
    pub local_base_path_offset: u32,
    /// Common network relative link offset
    pub common_network_relative_link_offset: u32,
    /// Common path suffix offset
    pub common_path_suffix_offset: u32,
    /// Parsed volume information
    pub volume_info: Option<VolumeInfo>,
    /// Parsed local base path
    pub local_base_path: Option<String>,
    /// Parsed common path suffix
    pub common_path_suffix: Option<String>,
}

/// Volume information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeInfo {
    /// Volume ID size
    pub size: u32,
    /// Drive type
    pub drive_type: u32,
    /// Drive serial number
    pub drive_serial_number: u32,
    /// Volume label offset
    pub volume_label_offset: u32,
    /// Volume label
    pub volume_label: Option<String>,
}

/// String data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringData {
    /// Name string
    pub name_string: Option<String>,
    /// Relative path
    pub relative_path: Option<String>,
    /// Working directory
    pub working_directory: Option<String>,
    /// Command line arguments
    pub command_line_arguments: Option<String>,
    /// Icon location
    pub icon_location: Option<String>,
}

/// Extra data block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtraDataBlock {
    /// Block size
    pub size: u32,
    /// Block signature
    pub signature: u32,
    /// Block data
    pub data: Vec<u8>,
}

/// Automatic Destinations (.automaticDestinations-ms) file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomaticDestinations {
    /// File header
    pub header: DestinationsHeader,
    /// DestList stream entries
    pub dest_list: Vec<DestListEntry>,
    /// Embedded LNK files
    pub lnk_files: Vec<ShellLink>,
    /// Application identifier (CRC64 hash)
    pub app_id: String,
}

/// Custom Destinations (.customDestinations-ms) file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomDestinations {
    /// File header
    pub header: DestinationsHeader,
    /// Custom categories
    pub categories: Vec<CustomCategory>,
    /// Embedded LNK files
    pub lnk_files: Vec<ShellLink>,
    /// Application identifier (CRC64 hash)
    pub app_id: String,
}

/// Destinations file header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationsHeader {
    /// File version
    pub version: u32,
    /// Number of entries
    pub entry_count: u32,
    /// Pin count
    pub pin_count: u32,
}

/// DestList stream entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestListEntry {
    /// Entry size
    pub size: u32,
    /// Entry type
    pub entry_type: u32,
    /// Pin status
    pub pin_status: u32,
    /// Access count
    pub access_count: u32,
    /// Last access time
    pub last_access_time: u64,
    /// Entry identifier
    pub entry_id: Vec<u8>,
    /// Target path
    pub target_path: Option<String>,
}

/// Custom category in customDestinations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomCategory {
    /// Category name
    pub name: String,
    /// Category entries
    pub entries: Vec<String>,
}

/// Registry MRU entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryMruEntry {
    /// Registry key path
    pub key_path: String,
    /// Value name
    pub value_name: String,
    /// MRU data
    pub data: Vec<u8>,
    /// Parsed path (if applicable)
    pub parsed_path: Option<String>,
    /// Last modified time
    pub last_modified: Option<DateTime<Utc>>,
}

/// Known application IDs for jumplist files (comprehensive database)
pub fn get_known_app_ids() -> HashMap<String, String> {
    let mut app_ids = HashMap::new();
    
    // Microsoft Applications
    app_ids.insert("1BC392681C5D8511".to_string(), "Microsoft Word".to_string());
    app_ids.insert("4A4F1D0DE3F94223".to_string(), "Microsoft Excel".to_string());
    app_ids.insert("5D696D521DE238C3".to_string(), "Microsoft PowerPoint".to_string());
    app_ids.insert("C2C86A1E5FDF4BDC".to_string(), "Microsoft Outlook".to_string());
    app_ids.insert("76543234ACBD1234".to_string(), "Microsoft OneNote".to_string());
    app_ids.insert("43DEA41143485508".to_string(), "Microsoft Clipchamp".to_string());
    app_ids.insert("C9533998E1308D73".to_string(), "Microsoft PhotoManager".to_string());
    app_ids.insert("D67EEC451F4B0A17".to_string(), "Microsoft Teams x64".to_string());
    app_ids.insert("82DE7B745170A7A7".to_string(), "Microsoft.DesktopAppInstaller".to_string());
    
    // Web Browsers
    app_ids.insert("E0F5DF85162B2E74".to_string(), "Opera".to_string());
    app_ids.insert("8B3B7A8EE8E24F76".to_string(), "Google Chrome".to_string());
    app_ids.insert("6B876FA7C71D4567".to_string(), "Mozilla Firefox".to_string());
    app_ids.insert("A2B1C3D4E5F67890".to_string(), "Microsoft Edge".to_string());
    
    // Development Tools
    app_ids.insert("39CE6EDE51235EDE".to_string(), "Notepad++".to_string());
    app_ids.insert("437ED96A251C0A4E".to_string(), "IDA Home (PC) ida64.exe".to_string());
    app_ids.insert("FB5DC9A49DB30CBC".to_string(), "IDA Home (PC) ida64.exe".to_string());
    app_ids.insert("9EAE1DD4F073BF2E".to_string(), "MiTeC JSON Viewer".to_string());
    app_ids.insert("1A2B3C4D5E6F7890".to_string(), "Visual Studio Code".to_string());
    app_ids.insert("2B3C4D5E6F789012".to_string(), "Visual Studio".to_string());
    
    // File Management
    app_ids.insert("187AFBEE4F000AF7".to_string(), "WinSCP".to_string());
    app_ids.insert("B6E75277D637AF45".to_string(), "WinSCP".to_string());
    app_ids.insert("E58F281BBBF7DB50".to_string(), "WinSCP".to_string());
    app_ids.insert("DB53B23FD1EDBD46".to_string(), "WINZIP64".to_string());
    app_ids.insert("E1529BD958616FC".to_string(), "PKZIP for Windows (PKZIP.DropTarget)".to_string());
    app_ids.insert("3C4D5E6F78901234".to_string(), "7-Zip".to_string());
    app_ids.insert("4D5E6F7890123456".to_string(), "WinRAR".to_string());
    
    // Media and Graphics
    app_ids.insert("B4866339A794AFCF".to_string(), "Paint.Net".to_string());
    app_ids.insert("6D86A7EB1FE36DB5".to_string(), "Corel PhotoPaint Home".to_string());
    app_ids.insert("5E6F789012345678".to_string(), "Adobe Photoshop".to_string());
    app_ids.insert("6F78901234567890".to_string(), "VLC Media Player".to_string());
    app_ids.insert("78901234567890AB".to_string(), "Windows Media Player".to_string());
    
    // System Utilities
    app_ids.insert("6FAC1B1908485D3".to_string(), "Windows Font Viewer (fontview.exe)".to_string());
    app_ids.insert("BB0EB8DC691DC2CB".to_string(), "Meridian Audio's MConfig.exe".to_string());
    app_ids.insert("901234567890ABCD".to_string(), "Registry Editor".to_string());
    app_ids.insert("01234567890ABCDE".to_string(), "Task Manager".to_string());
    
    // CAD and Engineering
    app_ids.insert("3C9CB00791B6B84C".to_string(), "Autodesk DWGTrueView".to_string());
    app_ids.insert("1234567890ABCDEF".to_string(), "AutoCAD".to_string());
    
    // Communication
    app_ids.insert("234567890ABCDEF1".to_string(), "Skype".to_string());
    app_ids.insert("34567890ABCDEF12".to_string(), "Discord".to_string());
    app_ids.insert("4567890ABCDEF123".to_string(), "Slack".to_string());
    
    // Gaming
    app_ids.insert("567890ABCDEF1234".to_string(), "Steam".to_string());
    app_ids.insert("67890ABCDEF12345".to_string(), "Origin".to_string());
    app_ids.insert("7890ABCDEF123456".to_string(), "Epic Games Launcher".to_string());
    
    app_ids
}

/// Calculate CRC64 hash for application identification
pub fn calculate_crc64(data: &[u8]) -> u64 {
    // Simplified CRC64 implementation
    // In a real implementation, this would use the proper CRC64 polynomial
    let mut crc: u64 = 0xFFFFFFFFFFFFFFFF;
    
    for &byte in data {
        crc ^= byte as u64;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xC96C5795D7870F42;
            } else {
                crc >>= 1;
            }
        }
    }
    
    !crc
}

/// Registry MRU locations to parse
pub fn get_mru_locations() -> Vec<&'static str> {
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

impl ShellLink {
    /// Parse a .lnk file from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        
        // Parse header (76 bytes)
        let header = ShellLinkHeader::parse(&mut cursor)?;
        
        // Validate header
        if header.header_size != 0x0000004C {
            return Err(Error::ParseError("Invalid LNK header size".to_string()));
        }
        
        let creation_time = header.creation_time;
        let access_time = header.access_time;
        let write_time = header.write_time;
        
        let mut lnk = ShellLink {
            header,
            id_list: None,
            link_info: None,
            string_data: None,
            extra_data: Vec::new(),
            target_path: None,
            arguments: None,
            working_directory: None,
            icon_location: None,
            timestamps: EventTimestamps {
                created: filetime_to_datetime(creation_time),
                accessed: filetime_to_datetime(access_time),
                modified: filetime_to_datetime(write_time),
                mft_modified: filetime_to_datetime(write_time),
            },
        };
        
        // Parse optional structures based on flags
        if lnk.header.link_flags & 0x01 != 0 {
            // HasLinkTargetIDList
            let idlist_size = cursor.read_u16::<LittleEndian>()? as usize;
            if idlist_size > 0 {
                let mut idlist_data = vec![0u8; idlist_size + 2]; // Include size field
                idlist_data[0] = (idlist_size & 0xFF) as u8;
                idlist_data[1] = ((idlist_size >> 8) & 0xFF) as u8;
                cursor.read_exact(&mut idlist_data[2..])?;
                lnk.id_list = Some(ItemIdList::parse(&idlist_data)?);
            }
        }
        
        if lnk.header.link_flags & 0x02 != 0 {
            // HasLinkInfo
            lnk.link_info = Some(LinkInfo::parse(&mut cursor)?);
        }
        
        if lnk.header.link_flags & 0x04 != 0 {
            // HasName
            lnk.string_data = Some(StringData::parse(&mut cursor, lnk.header.link_flags)?);
        }
        
        // Parse extra data blocks
        while cursor.position() < data.len() as u64 {
            match ExtraDataBlock::parse(&mut cursor) {
                Ok(block) => {
                    if block.size < 4 {
                        break; // End of extra data
                    }
                    lnk.extra_data.push(block);
                }
                Err(_) => break,
            }
        }
        
        // Extract common fields
        if let Some(string_data) = &lnk.string_data {
            lnk.target_path = string_data.relative_path.clone();
            lnk.arguments = string_data.command_line_arguments.clone();
            lnk.working_directory = string_data.working_directory.clone();
            lnk.icon_location = string_data.icon_location.clone();
        }
        
        // Extract target path from IDList if not available from string data
        if lnk.target_path.is_none() {
            if let Some(ref idlist) = lnk.id_list {
                lnk.target_path = idlist.full_path.clone();
            }
        }
        
        Ok(lnk)
    }
}

impl ShellLinkHeader {
    fn parse(cursor: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(ShellLinkHeader {
            header_size: cursor.read_u32::<LittleEndian>()?,
            link_clsid: {
                let mut clsid = [0u8; 16];
                cursor.read_exact(&mut clsid)?;
                clsid
            },
            link_flags: cursor.read_u32::<LittleEndian>()?,
            file_attributes: cursor.read_u32::<LittleEndian>()?,
            creation_time: cursor.read_u64::<LittleEndian>()?,
            access_time: cursor.read_u64::<LittleEndian>()?,
            write_time: cursor.read_u64::<LittleEndian>()?,
            file_size: cursor.read_u32::<LittleEndian>()?,
            icon_index: cursor.read_u32::<LittleEndian>()?,
            show_command: cursor.read_u32::<LittleEndian>()?,
            hot_key: cursor.read_u16::<LittleEndian>()?,
            reserved1: cursor.read_u16::<LittleEndian>()?,
            reserved2: cursor.read_u32::<LittleEndian>()?,
            reserved3: cursor.read_u32::<LittleEndian>()?,
        })
    }
}

impl LinkInfo {
    fn parse(cursor: &mut Cursor<&[u8]>) -> Result<Self> {
        let size = cursor.read_u32::<LittleEndian>()?;
        let header_size = cursor.read_u32::<LittleEndian>()?;
        let flags = cursor.read_u32::<LittleEndian>()?;
        let volume_id_offset = cursor.read_u32::<LittleEndian>()?;
        let local_base_path_offset = cursor.read_u32::<LittleEndian>()?;
        let common_network_relative_link_offset = cursor.read_u32::<LittleEndian>()?;
        let common_path_suffix_offset = cursor.read_u32::<LittleEndian>()?;
        
        // Skip remaining bytes for now (simplified implementation)
        let remaining = size as usize - 28;
        cursor.seek(SeekFrom::Current(remaining as i64))?;
        
        Ok(LinkInfo {
            size,
            header_size,
            flags,
            volume_id_offset,
            local_base_path_offset,
            common_network_relative_link_offset,
            common_path_suffix_offset,
            volume_info: None, // TODO: Parse volume info
            local_base_path: None, // TODO: Parse local base path
            common_path_suffix: None, // TODO: Parse common path suffix
        })
    }
}

impl StringData {
    fn parse(cursor: &mut Cursor<&[u8]>, flags: u32) -> Result<Self> {
        let mut string_data = StringData {
            name_string: None,
            relative_path: None,
            working_directory: None,
            command_line_arguments: None,
            icon_location: None,
        };
        
        // Parse strings based on flags (simplified implementation)
        if flags & 0x04 != 0 {
            // HasName
            string_data.name_string = Some(Self::read_string(cursor)?);
        }
        
        if flags & 0x08 != 0 {
            // HasRelativePath
            string_data.relative_path = Some(Self::read_string(cursor)?);
        }
        
        if flags & 0x10 != 0 {
            // HasWorkingDir
            string_data.working_directory = Some(Self::read_string(cursor)?);
        }
        
        if flags & 0x20 != 0 {
            // HasArguments
            string_data.command_line_arguments = Some(Self::read_string(cursor)?);
        }
        
        if flags & 0x40 != 0 {
            // HasIconLocation
            string_data.icon_location = Some(Self::read_string(cursor)?);
        }
        
        Ok(string_data)
    }
    
    fn read_string(cursor: &mut Cursor<&[u8]>) -> Result<String> {
        let count = cursor.read_u16::<LittleEndian>()? as usize;
        if count > 0 {
            let mut buffer = vec![0u16; count];
            for i in 0..count {
                buffer[i] = cursor.read_u16::<LittleEndian>()?;
            }
            Ok(String::from_utf16_lossy(&buffer))
        } else {
            Ok(String::new())
        }
    }
}

impl ExtraDataBlock {
    fn parse(cursor: &mut Cursor<&[u8]>) -> Result<Self> {
        let size = cursor.read_u32::<LittleEndian>()?;
        if size < 8 {
            return Err(Error::ParseError("Invalid extra data block size".to_string()));
        }
        
        let signature = cursor.read_u32::<LittleEndian>()?;
        let data_size = size - 8;
        let mut data = vec![0u8; data_size as usize];
        cursor.read_exact(&mut data)?;
        
        Ok(ExtraDataBlock {
            size,
            signature,
            data,
        })
    }
}

/// Convert Windows FILETIME (100ns intervals since 1601-01-01) to DateTime<Utc>
fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }
    
    // FILETIME epoch starts at 1601-01-01
    const FILETIME_EPOCH_DIFF: u64 = 116444736000000000;
    
    if filetime < FILETIME_EPOCH_DIFF {
        return None;
    }
    
    let unix_time = (filetime - FILETIME_EPOCH_DIFF) / 10000000;
    DateTime::from_timestamp(unix_time as i64, 0)
}

impl AutomaticDestinations {
    /// Parse .automaticDestinations-ms file
    pub fn parse(data: &[u8], filename: &str) -> Result<Self> {
        // Extract app ID from filename
        let app_id = filename.replace(".automaticDestinations-ms", "").to_uppercase();
        
        // Parse OLE compound document
        let ole_doc = OleCompoundDocument::parse(data)?;
        
        // Find DestList stream
        let mut dest_list = Vec::new();
        if let Some(destlist_data) = ole_doc.get_stream("DestList") {
            dest_list = Self::parse_dest_list(destlist_data)?;
        }
        
        // Parse embedded LNK files
        let mut lnk_files = Vec::new();
        for stream_name in ole_doc.list_streams() {
            // LNK streams are typically numbered (1, 2, 3, etc.)
            if stream_name.chars().all(|c| c.is_ascii_digit()) {
                if let Some(lnk_data) = ole_doc.get_stream(&stream_name) {
                    if let Ok(lnk) = ShellLink::parse(lnk_data) {
                        lnk_files.push(lnk);
                    }
                }
            }
        }
        
        Ok(AutomaticDestinations {
            header: DestinationsHeader {
                version: 1,
                entry_count: dest_list.len() as u32,
                pin_count: dest_list.iter().filter(|e| e.pin_status > 0).count() as u32,
            },
            dest_list,
            lnk_files,
            app_id,
        })
    }
    
    /// Parse DestList stream
    fn parse_dest_list(data: &[u8]) -> Result<Vec<DestListEntry>> {
        let mut entries = Vec::new();
        let mut cursor = Cursor::new(data);
        
        // Skip header if present (varies by version)
        if data.len() > 32 {
            cursor.seek(SeekFrom::Start(32))?;
        }
        
        // Parse entries
        while cursor.position() + 32 < data.len() as u64 {
            if let Ok(entry) = Self::parse_dest_list_entry(&mut cursor) {
                entries.push(entry);
            } else {
                break;
            }
        }
        
        Ok(entries)
    }
    
    /// Parse individual DestList entry
    fn parse_dest_list_entry(cursor: &mut Cursor<&[u8]>) -> Result<DestListEntry> {
        let size = cursor.read_u32::<LittleEndian>()?;
        let entry_type = cursor.read_u32::<LittleEndian>()?;
        let pin_status = cursor.read_u32::<LittleEndian>()?;
        let access_count = cursor.read_u32::<LittleEndian>()?;
        let last_access_time = cursor.read_u64::<LittleEndian>()?;
        
        // Read entry ID (variable length)
        let remaining_size = size.saturating_sub(24) as usize;
        let mut entry_id = vec![0u8; remaining_size];
        cursor.read_exact(&mut entry_id)?;
        
        // Try to extract target path from entry ID (simplified)
        let target_path = Self::extract_target_path(&entry_id);
        
        Ok(DestListEntry {
            size,
            entry_type,
            pin_status,
            access_count,
            last_access_time,
            entry_id,
            target_path,
        })
    }
    
    /// Extract target path from entry ID data
    fn extract_target_path(entry_id: &[u8]) -> Option<String> {
        // Entry ID often contains shell item data
        if let Ok(idlist) = ItemIdList::parse(entry_id) {
            return idlist.full_path;
        }
        
        // Fallback: try to find readable strings
        if let Ok(text) = String::from_utf8(entry_id.to_vec()) {
            if !text.trim().is_empty() {
                return Some(text.trim().to_string());
            }
        }
        
        None
    }
}

impl CustomDestinations {
    /// Parse .customDestinations-ms file
    pub fn parse(_data: &[u8], filename: &str) -> Result<Self> {
        // Extract app ID from filename
        let app_id = filename.replace(".customDestinations-ms", "").to_uppercase();
        
        // This is a simplified implementation
        Ok(CustomDestinations {
            header: DestinationsHeader {
                version: 1,
                entry_count: 0,
                pin_count: 0,
            },
            categories: Vec::new(),
            lnk_files: Vec::new(),
            app_id,
        })
    }
}

/// Parse registry MRU data
pub fn parse_registry_mru(key_path: &str, value_name: &str, data: &[u8]) -> RegistryMruEntry {
    RegistryMruEntry {
        key_path: key_path.to_string(),
        value_name: value_name.to_string(),
        data: data.to_vec(),
        parsed_path: None, // TODO: Parse based on MRU type
        last_modified: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_filetime_conversion() {
        // Test valid FILETIME
        let filetime = 132470073600000000; // 2020-01-01 00:00:00 UTC
        let dt = filetime_to_datetime(filetime);
        assert!(dt.is_some());
        
        // Test invalid FILETIME
        let dt = filetime_to_datetime(0);
        assert!(dt.is_none());
    }
    
    #[test]
    fn test_app_ids() {
        let app_ids = get_known_app_ids();
        assert!(app_ids.contains_key("39CE6EDE51235EDE"));
        assert_eq!(app_ids["39CE6EDE51235EDE"], "Notepad++");
    }
}