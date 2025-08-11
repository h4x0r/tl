//! Windows LNK (Shell Link) file parser
//!
//! Parses Windows .lnk files to extract timeline events and file access information.
//! Shell links contain creation, access, and modification timestamps along with target
//! file information, making them valuable forensic artifacts.

use crate::error::{Error, Result};
use crate::shell_item::{ItemIdList, ShellItem};
use crate::types::EventTimestamps;
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Seek, SeekFrom};

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
    /// Hotkey
    pub hotkey: u16,
    /// Reserved fields
    pub reserved1: u16,
    pub reserved2: u32,
    pub reserved3: u32,
}

/// Link Info structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkInfo {
    /// Total size of LinkInfo structure
    pub size: u32,
    /// LinkInfo header size
    pub header_size: u32,
    /// Link info flags
    pub flags: u32,
    /// Volume ID offset
    pub volume_id_offset: u32,
    /// Local path offset
    pub local_path_offset: u32,
    /// Network volume table offset
    pub network_volume_table_offset: u32,
    /// Remaining path offset
    pub remaining_path_offset: u32,
    /// Parsed volume information
    pub volume_info: Option<VolumeInfo>,
    /// Local path
    pub local_path: Option<String>,
    /// Network path
    pub network_path: Option<String>,
}

/// Volume information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeInfo {
    /// Volume ID size
    pub size: u32,
    /// Drive type
    pub drive_type: u32,
    /// Drive serial number
    pub drive_serial: u32,
    /// Volume label offset
    pub volume_label_offset: u32,
    /// Volume label
    pub volume_label: Option<String>,
}

/// String data section
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
    /// Parsed block data
    pub parsed_data: ExtraDataType,
}

/// Extra data block types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtraDataType {
    /// Console properties
    ConsoleProps,
    /// Console codepage
    ConsoleCodepage,
    /// Darwin properties
    DarwinProps,
    /// Environment variable data block
    EnvironmentProps,
    /// Icon environment data block
    IconEnvironmentProps,
    /// Known folder data block
    KnownFolderProps,
    /// Property store data block
    PropertyStoreProps,
    /// Shim data block
    ShimProps,
    /// Special folder data block
    SpecialFolderProps,
    /// Tracker data block
    TrackerProps,
    /// VistaAndAboveIDList data block
    VistaAndAboveIDListProps,
    /// Volume ID data block
    VolumeIDProps,
    /// Unknown block type
    Unknown(Vec<u8>),
}

/// LNK file parser
pub struct LnkParser {
    /// FILETIME epoch difference (1601-01-01 to 1970-01-01)
    filetime_epoch_diff: u64,
}

impl LnkParser {
    /// Create new LNK parser
    pub fn new() -> Self {
        Self {
            filetime_epoch_diff: 116444736000000000, // 100-nanosecond intervals
        }
    }

    /// Parse LNK file data
    pub fn parse_lnk_data(&self, data: &[u8]) -> Result<ShellLink> {
        if data.len() < 76 {
            return Err(Error::InvalidInput(format!("LNK file too small: {} bytes, need at least 76", data.len())));
        }

        // Check if this looks like a LNK file by examining the first few bytes
        if data.len() >= 4 {
            let header_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if header_size != 0x0000004C {
                // This might not be a valid LNK file
                return Err(Error::InvalidInput(format!("File does not appear to be a valid LNK file: header size 0x{:X}", header_size)));
            }
        }

        let mut cursor = Cursor::new(data);
        
        // Parse header
        let header = self.parse_header(&mut cursor)?;
        
        // Parse optional sections based on flags
        let id_list = if header.link_flags & 0x01 != 0 {
            Some(self.parse_id_list(&mut cursor)?)
        } else {
            None
        };

        let link_info = if header.link_flags & 0x02 != 0 {
            Some(self.parse_link_info(&mut cursor)?)
        } else {
            None
        };

        let string_data = if header.link_flags & 0x04 != 0 ||
                             header.link_flags & 0x08 != 0 ||
                             header.link_flags & 0x10 != 0 ||
                             header.link_flags & 0x20 != 0 ||
                             header.link_flags & 0x40 != 0 {
            Some(self.parse_string_data(&mut cursor, &header)?)
        } else {
            None
        };

        let extra_data = self.parse_extra_data(&mut cursor)?;

        // Extract target path from various sources
        let target_path = self.extract_target_path(&id_list, &link_info, &string_data);
        
        // Extract other string data
        let arguments = string_data.as_ref().and_then(|sd| sd.command_line_arguments.clone());
        let working_directory = string_data.as_ref().and_then(|sd| sd.working_directory.clone());
        let icon_location = string_data.as_ref().and_then(|sd| sd.icon_location.clone());

        // Convert FILETIME timestamps to UTC
        let timestamps = EventTimestamps {
            created: self.filetime_to_datetime(header.creation_time),
            modified: self.filetime_to_datetime(header.write_time),
            accessed: self.filetime_to_datetime(header.access_time),
            mft_modified: None, // Not applicable for LNK files
        };

        Ok(ShellLink {
            header,
            id_list,
            link_info,
            string_data,
            extra_data,
            target_path,
            arguments,
            working_directory,
            icon_location,
            timestamps,
        })
    }

    /// Parse shell link header
    fn parse_header(&self, cursor: &mut Cursor<&[u8]>) -> Result<ShellLinkHeader> {
        let header_size = cursor.read_u32::<LittleEndian>()?;
        if header_size != 0x0000004C {
            return Err(Error::InvalidInput(format!("Invalid LNK header size: expected 0x4C (76), got 0x{:X} ({})", header_size, header_size)));
        }

        let mut link_clsid = [0u8; 16];
        cursor.read_exact(&mut link_clsid)?;
        
        // Verify this is a Shell Link CLSID
        let expected_clsid: [u8; 16] = [
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        ];
        if link_clsid != expected_clsid {
            return Err(Error::InvalidInput("Invalid Shell Link CLSID".to_string()));
        }
        
        let link_flags = cursor.read_u32::<LittleEndian>()?;
        let file_attributes = cursor.read_u32::<LittleEndian>()?;
        let creation_time = cursor.read_u64::<LittleEndian>()?;
        let access_time = cursor.read_u64::<LittleEndian>()?;
        let write_time = cursor.read_u64::<LittleEndian>()?;
        let file_size = cursor.read_u32::<LittleEndian>()?;
        let icon_index = cursor.read_u32::<LittleEndian>()?;
        let show_command = cursor.read_u32::<LittleEndian>()?;
        let hotkey = cursor.read_u16::<LittleEndian>()?;
        let reserved1 = cursor.read_u16::<LittleEndian>()?;
        let reserved2 = cursor.read_u32::<LittleEndian>()?;
        let reserved3 = cursor.read_u32::<LittleEndian>()?;

        Ok(ShellLinkHeader {
            header_size,
            link_clsid,
            link_flags,
            file_attributes,
            creation_time,
            access_time,
            write_time,
            file_size,
            icon_index,
            show_command,
            hotkey,
            reserved1,
            reserved2,
            reserved3,
        })
    }

    /// Parse IDList section
    fn parse_id_list(&self, cursor: &mut Cursor<&[u8]>) -> Result<ItemIdList> {
        let size = cursor.read_u16::<LittleEndian>()?;
        
        if size == 0 {
            return Ok(ItemIdList {
                size: 0,
                items: Vec::new(),
                full_path: None,
            });
        }

        // Create IDList data including size field for ItemIdList::parse
        let mut idlist_data = Vec::with_capacity(size as usize + 2);
        idlist_data.extend_from_slice(&size.to_le_bytes()); // Add size field back
        
        // Read the actual IDList data
        let mut remaining_data = vec![0u8; size as usize];
        cursor.read_exact(&mut remaining_data)?;
        idlist_data.extend_from_slice(&remaining_data);

        // Parse using existing ItemIdList parser
        ItemIdList::parse(&idlist_data)
    }

    /// Parse LinkInfo section
    fn parse_link_info(&self, cursor: &mut Cursor<&[u8]>) -> Result<LinkInfo> {
        let size = cursor.read_u32::<LittleEndian>()?;
        if size < 28 {
            return Err(Error::InvalidInput("Invalid LinkInfo size".to_string()));
        }

        let header_size = cursor.read_u32::<LittleEndian>()?;
        let flags = cursor.read_u32::<LittleEndian>()?;
        let volume_id_offset = cursor.read_u32::<LittleEndian>()?;
        let local_path_offset = cursor.read_u32::<LittleEndian>()?;
        let network_volume_table_offset = cursor.read_u32::<LittleEndian>()?;
        let remaining_path_offset = cursor.read_u32::<LittleEndian>()?;

        // Read the rest of LinkInfo data
        let remaining_size = size - 28;
        let mut linkinfo_data = vec![0u8; remaining_size as usize];
        cursor.read_exact(&mut linkinfo_data)?;

        // Parse local path if present
        let local_path = if flags & 0x01 != 0 && local_path_offset > 0 {
            let path_start = (local_path_offset - 28) as usize;
            if path_start < linkinfo_data.len() {
                let path_data = &linkinfo_data[path_start..];
                if let Some(null_pos) = path_data.iter().position(|&b| b == 0) {
                    String::from_utf8_lossy(&path_data[..null_pos]).to_string().into()
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        Ok(LinkInfo {
            size,
            header_size,
            flags,
            volume_id_offset,
            local_path_offset,
            network_volume_table_offset,
            remaining_path_offset,
            volume_info: None, // TODO: Parse volume info if needed
            local_path,
            network_path: None, // TODO: Parse network path if needed
        })
    }

    /// Parse string data section
    fn parse_string_data(&self, cursor: &mut Cursor<&[u8]>, header: &ShellLinkHeader) -> Result<StringData> {
        let is_unicode = header.link_flags & 0x80 != 0;
        
        let mut string_data = StringData {
            name_string: None,
            relative_path: None,
            working_directory: None,
            command_line_arguments: None,
            icon_location: None,
        };

        // Parse name string if present
        if header.link_flags & 0x04 != 0 {
            string_data.name_string = Some(self.read_string(cursor, is_unicode)?);
        }

        // Parse relative path if present
        if header.link_flags & 0x08 != 0 {
            string_data.relative_path = Some(self.read_string(cursor, is_unicode)?);
        }

        // Parse working directory if present
        if header.link_flags & 0x10 != 0 {
            string_data.working_directory = Some(self.read_string(cursor, is_unicode)?);
        }

        // Parse command line arguments if present
        if header.link_flags & 0x20 != 0 {
            string_data.command_line_arguments = Some(self.read_string(cursor, is_unicode)?);
        }

        // Parse icon location if present
        if header.link_flags & 0x40 != 0 {
            string_data.icon_location = Some(self.read_string(cursor, is_unicode)?);
        }

        Ok(string_data)
    }

    /// Parse extra data section
    fn parse_extra_data(&self, cursor: &mut Cursor<&[u8]>) -> Result<Vec<ExtraDataBlock>> {
        let mut extra_blocks = Vec::new();

        while cursor.position() < cursor.get_ref().len() as u64 {
            // Check if we have enough bytes for size field
            if cursor.position() + 4 > cursor.get_ref().len() as u64 {
                break;
            }

            let size = cursor.read_u32::<LittleEndian>()?;
            if size < 4 {
                break; // End of extra data
            }

            // Check if we have enough bytes for signature and data
            if cursor.position() + (size as u64 - 4) > cursor.get_ref().len() as u64 {
                break;
            }

            let signature = cursor.read_u32::<LittleEndian>()?;
            let data_size = size - 8;
            let mut data = vec![0u8; data_size as usize];
            cursor.read_exact(&mut data)?;

            let parsed_data = match signature {
                0xA0000002 => ExtraDataType::ConsoleProps,
                0xA0000004 => ExtraDataType::ConsoleCodepage,
                0xA0000006 => ExtraDataType::DarwinProps,
                0xA0000001 => ExtraDataType::EnvironmentProps,
                0xA0000007 => ExtraDataType::IconEnvironmentProps,
                0xA000000B => ExtraDataType::KnownFolderProps,
                0xA0000009 => ExtraDataType::PropertyStoreProps,
                0xA0000008 => ExtraDataType::ShimProps,
                0xA0000005 => ExtraDataType::SpecialFolderProps,
                0xA0000003 => ExtraDataType::TrackerProps,
                0xA000000C => ExtraDataType::VistaAndAboveIDListProps,
                0xA0000000 => ExtraDataType::VolumeIDProps,
                _ => ExtraDataType::Unknown(data.clone()),
            };

            extra_blocks.push(ExtraDataBlock {
                size,
                signature,
                data,
                parsed_data,
            });
        }

        Ok(extra_blocks)
    }

    /// Read a string from the cursor
    fn read_string(&self, cursor: &mut Cursor<&[u8]>, is_unicode: bool) -> Result<String> {
        let count = cursor.read_u16::<LittleEndian>()? as usize;
        if count == 0 {
            return Ok(String::new());
        }
        
        if is_unicode {
            let mut utf16_data = vec![0u16; count];
            for i in 0..count {
                utf16_data[i] = cursor.read_u16::<LittleEndian>()?;
            }
            
            String::from_utf16(&utf16_data)
                .map_err(|e| Error::InvalidInput(format!("Invalid UTF-16 string: {}", e)))
        } else {
            let mut bytes = vec![0u8; count];
            cursor.read_exact(&mut bytes)?;
            
            // Remove null terminator if present
            if let Some(pos) = bytes.iter().position(|&b| b == 0) {
                bytes.truncate(pos);
            }
            
            String::from_utf8(bytes)
                .map_err(|e| Error::InvalidInput(format!("Invalid UTF-8 string: {}", e)))
        }
    }

    /// Extract target path from various sections
    fn extract_target_path(
        &self,
        id_list: &Option<ItemIdList>,
        link_info: &Option<LinkInfo>,
        string_data: &Option<StringData>,
    ) -> Option<String> {
        // Try link info local path first (often contains full long paths)
        if let Some(link_info) = link_info {
            if let Some(local_path) = &link_info.local_path {
                return Some(local_path.clone());
            }
            if let Some(network_path) = &link_info.network_path {
                return Some(network_path.clone());
            }
        }

        // Fall back to IDList if LinkInfo doesn't have a path
        if let Some(id_list) = id_list {
            if let Some(path) = &id_list.full_path {
                return Some(path.clone());
            }
        }

        // Try string data
        if let Some(string_data) = string_data {
            if let Some(name) = &string_data.name_string {
                return Some(name.clone());
            }
        }

        None
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

impl Default for LnkParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn test_lnk_parser_creation() {
        let parser = LnkParser::new();
        assert_eq!(parser.filetime_epoch_diff, 116444736000000000);
    }

    #[test]
    fn test_filetime_conversion() {
        let parser = LnkParser::new();
        
        // Test zero filetime
        assert!(parser.filetime_to_datetime(0).is_none());
        
        // Test valid filetime (January 1, 2000 00:00:00 UTC)
        // = 125911584000000000 in FILETIME
        let filetime = 125911584000000000u64;
        if let Some(dt) = parser.filetime_to_datetime(filetime) {
            assert_eq!(dt.year(), 2000);
            assert_eq!(dt.month(), 1);
            assert_eq!(dt.day(), 1);
        }
    }

    #[test]
    fn test_invalid_lnk_data() {
        let parser = LnkParser::new();
        
        // Test empty data
        assert!(parser.parse_lnk_data(&[]).is_err());
        
        // Test data too small
        let small_data = vec![0u8; 50];
        assert!(parser.parse_lnk_data(&small_data).is_err());
    }
}