//! Shell Item (IDList) parsing module
//!
//! Parses Windows Shell Item data structures found in LNK files and jumplists.
//! Shell items represent paths in the Windows Shell namespace including files, folders,
//! network locations, special folders, and complex hierarchical structures.

use crate::error::{Error, Result};
use crate::property_store::PropertyStore;
use crate::types::EventTimestamps;
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Seek, SeekFrom};

/// IDList (Item ID List) containing shell items
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemIdList {
    /// Total size of IDList
    pub size: u16,
    /// Shell items in the list
    pub items: Vec<ShellItem>,
    /// Reconstructed full path
    pub full_path: Option<String>,
}

/// Individual Shell Item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellItem {
    /// Item size (including this field)
    pub size: u16,
    /// Shell item type
    pub item_type: ShellItemType,
    /// Raw item data
    pub raw_data: Vec<u8>,
    /// Parsed item data
    pub parsed_data: ShellItemData,
    /// Property store (if present)
    pub property_store: Option<PropertyStore>,
}

/// Shell Item Types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShellItemType {
    /// Root folder (Desktop, My Computer, etc.)
    RootFolder,
    /// Volume/Drive
    Volume,
    /// File entry
    File,
    /// Directory entry
    Directory,
    /// Network location
    Network,
    /// Compressed folder
    CompressedFolder,
    /// URI (web link)
    Uri,
    /// Control Panel
    ControlPanel,
    /// Extension block
    Extension,
    /// MTP (Media Transfer Protocol) item
    Mtp,
    /// Unknown/unsupported type
    Unknown(u8),
}

/// Parsed shell item data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellItemData {
    /// Item name/filename
    pub name: Option<String>,
    /// Long filename (if different from name)
    pub long_name: Option<String>,
    /// Creation time
    pub created: Option<DateTime<Utc>>,
    /// Modified time
    pub modified: Option<DateTime<Utc>>,
    /// Accessed time
    pub accessed: Option<DateTime<Utc>>,
    /// File size
    pub file_size: Option<u64>,
    /// File attributes
    pub attributes: Option<u32>,
    /// CLSID for special folders
    pub clsid: Option<[u8; 16]>,
    /// Additional metadata
    pub metadata: Vec<(String, String)>,
}

/// File entry shell item structure
#[derive(Debug, Clone)]
struct FileEntryShellItem {
    /// File attributes
    pub attributes: u32,
    /// File size (32-bit)
    pub file_size_32: u32,
    /// DOS date
    pub dos_date: u16,
    /// DOS time
    pub dos_time: u16,
    /// Short name
    pub short_name: String,
    /// Primary name
    pub primary_name: Option<String>,
    /// Extension blocks
    pub extension_blocks: Vec<ExtensionBlock>,
}

/// Extension block in shell items
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionBlock {
    /// Block size
    pub size: u16,
    /// Block version
    pub version: u16,
    /// Block signature
    pub signature: u32,
    /// Block data
    pub data: Vec<u8>,
    /// Parsed extension data
    pub parsed_data: ExtensionData,
}

/// Extension block data types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtensionData {
    /// BEEF0004 - Extended file information
    ExtendedFileInfo {
        long_name: Option<String>,
        creation_time: Option<DateTime<Utc>>,
        access_time: Option<DateTime<Utc>>,
        write_time: Option<DateTime<Utc>>,
        file_size_64: Option<u64>,
        localized_name: Option<String>,
    },
    /// BEEF0005 - Extended directory information
    ExtendedDirInfo {
        long_name: Option<String>,
        creation_time: Option<DateTime<Utc>>,
        access_time: Option<DateTime<Utc>>,
        write_time: Option<DateTime<Utc>>,
        localized_name: Option<String>,
    },
    /// BEEF0006 - Property store
    PropertyStore(PropertyStore),
    /// Unknown extension
    Unknown(Vec<u8>),
}

impl ItemIdList {
    /// Parse IDList from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(Error::ParseError("IDList too small".to_string()));
        }
        
        let mut cursor = Cursor::new(data);
        let size = cursor.read_u16::<LittleEndian>()?;
        
        if size == 0 {
            return Ok(ItemIdList {
                size,
                items: Vec::new(),
                full_path: None,
            });
        }
        
        let mut items = Vec::new();
        let mut path_components = Vec::new();
        
        // Parse shell items until we hit a 0-length item or end of data
        while cursor.position() < data.len() as u64 {
            let item_size = cursor.read_u16::<LittleEndian>()?;
            
            if item_size == 0 {
                break; // End of IDList
            }
            
            if item_size < 2 {
                return Err(Error::ParseError("Invalid shell item size".to_string()));
            }
            
            // Read item data (excluding the size field we already read)
            let data_size = (item_size - 2) as usize;
            let mut item_data = vec![0u8; data_size];
            cursor.read_exact(&mut item_data)?;
            
            // Parse the shell item
            let item = ShellItem::parse(item_size, &item_data)?;
            
            // Build path component
            if let Some(name) = &item.parsed_data.name {
                if !name.is_empty() && name != "Desktop" {
                    path_components.push(name.clone());
                }
            }
            
            items.push(item);
        }
        
        // Reconstruct full path
        let full_path = if path_components.is_empty() {
            None
        } else {
            Some(path_components.join("\\"))
        };
        
        Ok(ItemIdList {
            size,
            items,
            full_path,
        })
    }
}

impl ShellItem {
    /// Parse shell item from data
    pub fn parse(size: u16, data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::ParseError("Empty shell item data".to_string()));
        }
        
        // Determine item type from first byte
        let type_indicator = data[0];
        let item_type = ShellItemType::from_type_indicator(type_indicator);
        
        // Parse based on type
        let parsed_data = Self::parse_item_data(&item_type, data)?;
        
        Ok(ShellItem {
            size,
            item_type,
            raw_data: data.to_vec(),
            parsed_data,
            property_store: None, // Will be populated from extension blocks
        })
    }
    
    /// Parse item data based on type
    fn parse_item_data(item_type: &ShellItemType, data: &[u8]) -> Result<ShellItemData> {
        match item_type {
            ShellItemType::File | ShellItemType::Directory => {
                Self::parse_file_entry_item(data)
            },
            ShellItemType::Volume => {
                Self::parse_volume_item(data)
            },
            ShellItemType::RootFolder => {
                Self::parse_root_folder_item(data)
            },
            ShellItemType::Network => {
                Self::parse_network_item(data)
            },
            _ => {
                // Default parsing for unknown types
                Ok(ShellItemData {
                    name: None,
                    long_name: None,
                    created: None,
                    modified: None,
                    accessed: None,
                    file_size: None,
                    attributes: None,
                    clsid: None,
                    metadata: vec![("type".to_string(), format!("{:?}", item_type))],
                })
            }
        }
    }
    
    /// Parse file/directory entry shell item
    fn parse_file_entry_item(data: &[u8]) -> Result<ShellItemData> {
        if data.len() < 14 {
            return Err(Error::ParseError("File entry shell item too small".to_string()));
        }
        
        let mut cursor = Cursor::new(data);
        
        // Skip type indicator
        cursor.read_u8()?;
        
        // Read file entry structure
        let file_size_32 = cursor.read_u32::<LittleEndian>()?;
        let dos_date = cursor.read_u16::<LittleEndian>()?;
        let dos_time = cursor.read_u16::<LittleEndian>()?;
        let attributes = cursor.read_u32::<LittleEndian>()?;
        
        // Read short name (null-terminated)
        let mut short_name = String::new();
        while cursor.position() < data.len() as u64 {
            let b = cursor.read_u8()?;
            if b == 0 {
                break;
            }
            short_name.push(b as char);
        }
        
        // Parse DOS date/time
        let mut modified = Self::dos_datetime_to_utc(dos_date, dos_time);
        
        // Look for extension blocks
        let mut extension_blocks = Vec::new();
        let mut long_name = None;
        let mut created = None;
        let mut accessed = None;
        let mut file_size_64 = None;
        
        // Parse extension blocks if present
        while cursor.position() + 4 <= data.len() as u64 {
            let pos = cursor.position();
            
            // Try to read extension block header
            if let Ok(ext_size) = cursor.read_u16::<LittleEndian>() {
                if ext_size == 0 || ext_size < 4 {
                    break;
                }
                
                if let Ok(version) = cursor.read_u16::<LittleEndian>() {
                    if pos + ext_size as u64 <= data.len() as u64 {
                        // We have a valid extension block
                        cursor.seek(SeekFrom::Start(pos))?;
                        if let Ok(block) = ExtensionBlock::parse(&mut cursor) {
                            // Extract data from specific extension types
                            match &block.parsed_data {
                                ExtensionData::ExtendedFileInfo { 
                                    long_name: ln, 
                                    creation_time: ct, 
                                    access_time: at, 
                                    write_time: wt,
                                    file_size_64: fs,
                                    ..
                                } => {
                                    if ln.is_some() { long_name = ln.clone(); }
                                    if ct.is_some() { created = *ct; }
                                    if at.is_some() { accessed = *at; }
                                    if wt.is_some() { modified = *wt; } // Override DOS time with FILETIME
                                    if fs.is_some() { file_size_64 = *fs; }
                                },
                                ExtensionData::ExtendedDirInfo { 
                                    long_name: ln, 
                                    creation_time: ct, 
                                    access_time: at, 
                                    write_time: wt,
                                    ..
                                } => {
                                    if ln.is_some() { long_name = ln.clone(); }
                                    if ct.is_some() { created = *ct; }
                                    if at.is_some() { accessed = *at; }
                                    if wt.is_some() { modified = *wt; }
                                },
                                _ => {}
                            }
                            extension_blocks.push(block);
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        
        // Determine final name
        let name = long_name.as_ref().unwrap_or(&short_name).clone();
        let final_long_name = if long_name.as_ref() != Some(&short_name) { long_name } else { None };
        
        Ok(ShellItemData {
            name: if name.is_empty() { None } else { Some(name) },
            long_name: final_long_name,
            created,
            modified,
            accessed,
            file_size: file_size_64.or(Some(file_size_32 as u64)),
            attributes: Some(attributes),
            clsid: None,
            metadata: vec![
                ("short_name".to_string(), short_name),
                ("extension_blocks".to_string(), extension_blocks.len().to_string()),
            ],
        })
    }
    
    /// Parse volume shell item
    fn parse_volume_item(data: &[u8]) -> Result<ShellItemData> {
        if data.len() < 20 {
            return Ok(ShellItemData::default());
        }
        
        // Volume shell items have various formats
        // This is a simplified parser
        let name = if data.len() > 20 {
            String::from_utf8_lossy(&data[20..]).trim_end_matches('\0').to_string()
        } else {
            "Drive".to_string()
        };
        
        Ok(ShellItemData {
            name: Some(name),
            long_name: None,
            created: None,
            modified: None,
            accessed: None,
            file_size: None,
            attributes: None,
            clsid: None,
            metadata: vec![("type".to_string(), "Volume".to_string())],
        })
    }
    
    /// Parse root folder shell item
    fn parse_root_folder_item(data: &[u8]) -> Result<ShellItemData> {
        if data.len() >= 16 {
            // Root folder items often contain CLSIDs
            let mut clsid = [0u8; 16];
            if data.len() >= 17 {
                clsid.copy_from_slice(&data[1..17]);
            }
            
            let name = match &clsid {
                &[0x20, 0xd0, 0x4f, 0xe0, 0x3a, 0xea, 0x10, 0x69, 0xa2, 0xd8, 0x08, 0x00, 0x2b, 0x30, 0x30, 0x9d] => "My Computer",
                &[0x21, 0xec, 0x20, 0x20, 0xea, 0x3a, 0x10, 0x69, 0xa2, 0xdd, 0x08, 0x00, 0x2b, 0x30, 0x30, 0x9d] => "Control Panel",
                _ => "Desktop",
            };
            
            Ok(ShellItemData {
                name: Some(name.to_string()),
                long_name: None,
                created: None,
                modified: None,
                accessed: None,
                file_size: None,
                attributes: None,
                clsid: Some(clsid),
                metadata: vec![("type".to_string(), "RootFolder".to_string())],
            })
        } else {
            Ok(ShellItemData::default())
        }
    }
    
    /// Parse network shell item
    fn parse_network_item(data: &[u8]) -> Result<ShellItemData> {
        // Network items contain network location information
        // This is a simplified implementation
        
        let name = if data.len() > 4 {
            String::from_utf8_lossy(&data[4..]).trim_end_matches('\0').to_string()
        } else {
            "Network Location".to_string()
        };
        
        Ok(ShellItemData {
            name: Some(name),
            long_name: None,
            created: None,
            modified: None,
            accessed: None,
            file_size: None,
            attributes: None,
            clsid: None,
            metadata: vec![("type".to_string(), "Network".to_string())],
        })
    }
    
    /// Convert DOS date and time to UTC DateTime
    fn dos_datetime_to_utc(dos_date: u16, dos_time: u16) -> Option<DateTime<Utc>> {
        if dos_date == 0 && dos_time == 0 {
            return None;
        }
        
        // Extract DOS date components
        let year = ((dos_date >> 9) & 0x7F) as i32 + 1980;
        let month = ((dos_date >> 5) & 0x0F) as u32;
        let day = (dos_date & 0x1F) as u32;
        
        // Extract DOS time components
        let hour = ((dos_time >> 11) & 0x1F) as u32;
        let minute = ((dos_time >> 5) & 0x3F) as u32;
        let second = ((dos_time & 0x1F) * 2) as u32;
        
        // Validate components
        if month == 0 || month > 12 || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        
        chrono::Utc.with_ymd_and_hms(year, month, day, hour, minute, second).single()
    }
}

impl ShellItemType {
    /// Determine shell item type from type indicator
    fn from_type_indicator(type_indicator: u8) -> Self {
        match type_indicator {
            0x1F => ShellItemType::RootFolder,
            0x2F => ShellItemType::Volume,
            0x30..=0x3F => ShellItemType::File,
            0x20..=0x2F => ShellItemType::Directory, 
            0x40..=0x4F => ShellItemType::Network,
            0x52 => ShellItemType::CompressedFolder,
            0x61 => ShellItemType::Uri,
            0x71 => ShellItemType::ControlPanel,
            0x74 => ShellItemType::Mtp,
            _ => ShellItemType::Unknown(type_indicator),
        }
    }
}

impl ExtensionBlock {
    /// Parse extension block from cursor
    fn parse(cursor: &mut Cursor<&[u8]>) -> Result<Self> {
        let size = cursor.read_u16::<LittleEndian>()?;
        let version = cursor.read_u16::<LittleEndian>()?;
        
        if size < 8 {
            return Err(Error::ParseError("Extension block too small".to_string()));
        }
        
        let signature = cursor.read_u32::<LittleEndian>()?;
        
        let data_size = (size - 8) as usize;
        let mut data = vec![0u8; data_size];
        cursor.read_exact(&mut data)?;
        
        let parsed_data = Self::parse_extension_data(signature, version, &data)?;
        
        Ok(ExtensionBlock {
            size,
            version,
            signature,
            data,
            parsed_data,
        })
    }
    
    /// Parse extension block data based on signature
    fn parse_extension_data(signature: u32, version: u16, data: &[u8]) -> Result<ExtensionData> {
        match signature {
            0xBEEF0004 => Self::parse_beef0004(data), // Extended file info
            0xBEEF0005 => Self::parse_beef0005(data), // Extended directory info  
            0xBEEF0006 => Self::parse_beef0006(data), // Property store
            _ => Ok(ExtensionData::Unknown(data.to_vec())),
        }
    }
    
    /// Parse BEEF0004 extension (Extended file information)
    fn parse_beef0004(data: &[u8]) -> Result<ExtensionData> {
        if data.len() < 26 {
            return Ok(ExtensionData::Unknown(data.to_vec()));
        }
        
        let mut cursor = Cursor::new(data);
        
        // Skip unknown fields
        cursor.read_u32::<LittleEndian>()?; // Unknown
        cursor.read_u16::<LittleEndian>()?; // Unknown
        cursor.read_u16::<LittleEndian>()?; // Flags
        
        let file_size_64 = cursor.read_u64::<LittleEndian>()?;
        let file_size_64 = if file_size_64 == 0 { None } else { Some(file_size_64) };
        
        // Read FILETIME timestamps
        let creation_time = Self::read_filetime(&mut cursor)?;
        let access_time = Self::read_filetime(&mut cursor)?;
        let write_time = Self::read_filetime(&mut cursor)?;
        
        // Try to read long name if present
        let long_name = if cursor.position() < data.len() as u64 {
            Self::read_unicode_string(&mut cursor)?
        } else {
            None
        };
        
        Ok(ExtensionData::ExtendedFileInfo {
            long_name,
            creation_time,
            access_time,
            write_time,
            file_size_64,
            localized_name: None,
        })
    }
    
    /// Parse BEEF0005 extension (Extended directory information)
    fn parse_beef0005(data: &[u8]) -> Result<ExtensionData> {
        if data.len() < 30 {
            return Ok(ExtensionData::Unknown(data.to_vec()));
        }
        
        let mut cursor = Cursor::new(data);
        
        // Skip to timestamps
        cursor.read_u32::<LittleEndian>()?; // Unknown
        cursor.read_u16::<LittleEndian>()?; // Unknown
        cursor.read_u16::<LittleEndian>()?; // Flags
        cursor.read_u64::<LittleEndian>()?; // Skip file size (not used for directories)
        
        let creation_time = Self::read_filetime(&mut cursor)?;
        let access_time = Self::read_filetime(&mut cursor)?;
        let write_time = Self::read_filetime(&mut cursor)?;
        
        let long_name = if cursor.position() < data.len() as u64 {
            Self::read_unicode_string(&mut cursor)?
        } else {
            None
        };
        
        Ok(ExtensionData::ExtendedDirInfo {
            long_name,
            creation_time,
            access_time,
            write_time,
            localized_name: None,
        })
    }
    
    /// Parse BEEF0006 extension (Property store)
    fn parse_beef0006(data: &[u8]) -> Result<ExtensionData> {
        match PropertyStore::parse(data) {
            Ok(store) => Ok(ExtensionData::PropertyStore(store)),
            Err(_) => Ok(ExtensionData::Unknown(data.to_vec())),
        }
    }
    
    /// Read FILETIME from cursor
    fn read_filetime(cursor: &mut Cursor<&[u8]>) -> Result<Option<DateTime<Utc>>> {
        let filetime = cursor.read_u64::<LittleEndian>()?;
        Ok(Self::filetime_to_datetime(filetime))
    }
    
    /// Read Unicode string from cursor
    fn read_unicode_string(cursor: &mut Cursor<&[u8]>) -> Result<Option<String>> {
        let mut utf16_chars = Vec::new();
        
        while cursor.position() + 1 < cursor.get_ref().len() as u64 {
            let char_val = cursor.read_u16::<LittleEndian>()?;
            if char_val == 0 {
                break;
            }
            utf16_chars.push(char_val);
        }
        
        if utf16_chars.is_empty() {
            Ok(None)
        } else {
            Ok(Some(String::from_utf16_lossy(&utf16_chars)))
        }
    }
    
    /// Convert Windows FILETIME to DateTime
    fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
        if filetime == 0 {
            return None;
        }
        
        const FILETIME_EPOCH_DIFF: u64 = 116444736000000000;
        
        if filetime < FILETIME_EPOCH_DIFF {
            return None;
        }
        
        let unix_time = (filetime - FILETIME_EPOCH_DIFF) / 10000000;
        DateTime::from_timestamp(unix_time as i64, 0)
    }
}

impl Default for ShellItemData {
    fn default() -> Self {
        ShellItemData {
            name: None,
            long_name: None,
            created: None,
            modified: None,
            accessed: None,
            file_size: None,
            attributes: None,
            clsid: None,
            metadata: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dos_datetime_conversion() {
        // Test DOS date: January 1, 2000
        let dos_date = ((2000 - 1980) << 9) | (1 << 5) | 1; // Year 2000, Month 1, Day 1
        let dos_time = (12 << 11) | (30 << 5) | (45 / 2);   // 12:30:45
        
        let dt = ShellItem::dos_datetime_to_utc(dos_date as u16, dos_time as u16);
        assert!(dt.is_some());
        
        let dt = dt.unwrap();
        assert_eq!(dt.year(), 2000);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 1);
        assert_eq!(dt.hour(), 12);
        assert_eq!(dt.minute(), 30);
        assert_eq!(dt.second(), 44); // DOS time has 2-second resolution
    }
    
    #[test]
    fn test_shell_item_type_detection() {
        assert!(matches!(ShellItemType::from_type_indicator(0x1F), ShellItemType::RootFolder));
        assert!(matches!(ShellItemType::from_type_indicator(0x2F), ShellItemType::Volume));
        assert!(matches!(ShellItemType::from_type_indicator(0x32), ShellItemType::File));
        assert!(matches!(ShellItemType::from_type_indicator(0x99), ShellItemType::Unknown(0x99)));
    }
}