//! OLE Compound Document Format parsing
//!
//! Used for parsing Windows jumplist files (.automaticDestinations-ms, .customDestinations-ms)
//! which are stored as OLE compound documents containing multiple streams.

use crate::error::{Error, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Cursor, Read, Seek, SeekFrom};

/// OLE Compound Document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OleCompoundDocument {
    /// OLE header
    pub header: OleHeader,
    /// Directory entries
    pub directory_entries: Vec<DirectoryEntry>,
    /// File allocation table
    pub fat: Vec<u32>,
    /// Mini FAT for small streams
    pub mini_fat: Vec<u32>,
    /// Streams data
    pub streams: HashMap<String, Vec<u8>>,
    /// Sector size
    pub sector_size: usize,
    /// Mini sector size
    pub mini_sector_size: usize,
}

/// OLE Compound Document Header (512 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OleHeader {
    /// OLE signature (D0CF11E0A1B11AE1)
    pub signature: u64,
    /// Minor version
    pub minor_version: u16,
    /// Major version  
    pub major_version: u16,
    /// Byte order
    pub byte_order: u16,
    /// Sector size power (usually 9 for 512 bytes)
    pub sector_size_power: u16,
    /// Mini sector size power (usually 6 for 64 bytes)
    pub mini_sector_size_power: u16,
    /// Number of directory sectors
    pub num_directory_sectors: u32,
    /// Number of FAT sectors
    pub num_fat_sectors: u32,
    /// Directory first sector
    pub directory_first_sector: u32,
    /// Transaction signature
    pub transaction_signature: u32,
    /// Mini stream cutoff (usually 4096)
    pub mini_stream_cutoff: u32,
    /// Mini FAT first sector
    pub mini_fat_first_sector: u32,
    /// Number of mini FAT sectors
    pub num_mini_fat_sectors: u32,
    /// DIFAT first sector
    pub difat_first_sector: u32,
    /// Number of DIFAT sectors
    pub num_difat_sectors: u32,
    /// First 109 DIFAT entries  
    pub difat: Vec<u32>,
}

/// Directory Entry (128 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    /// Entry name (UTF-16LE, 64 bytes max)
    pub name: String,
    /// Name length
    pub name_length: u16,
    /// Entry type (1=Storage, 2=Stream, 5=Root)
    pub entry_type: u8,
    /// Color flag (0=Red, 1=Black)
    pub color_flag: u8,
    /// Left sibling directory entry ID
    pub left_sibling_id: u32,
    /// Right sibling directory entry ID
    pub right_sibling_id: u32,
    /// Child directory entry ID
    pub child_id: u32,
    /// CLSID
    pub clsid: [u8; 16],
    /// State bits
    pub state_bits: u32,
    /// Creation time
    pub creation_time: u64,
    /// Modified time
    pub modified_time: u64,
    /// Starting sector
    pub starting_sector: u32,
    /// Size in bytes
    pub size: u64,
}

/// OLE Entry Types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OleEntryType {
    Empty = 0,
    Storage = 1,
    Stream = 2,
    LockBytes = 3,
    Property = 4,
    Root = 5,
}

impl From<u8> for OleEntryType {
    fn from(value: u8) -> Self {
        match value {
            0 => OleEntryType::Empty,
            1 => OleEntryType::Storage,
            2 => OleEntryType::Stream,
            3 => OleEntryType::LockBytes,
            4 => OleEntryType::Property,
            5 => OleEntryType::Root,
            _ => OleEntryType::Empty,
        }
    }
}

/// Special sector values
const FREESECT: u32 = 0xFFFFFFFF;
const ENDOFCHAIN: u32 = 0xFFFFFFFE;
const FATSECT: u32 = 0xFFFFFFFD;
const DIFSECT: u32 = 0xFFFFFFFC;

impl OleCompoundDocument {
    /// Parse OLE compound document from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        
        // Parse header
        let header = OleHeader::parse(&mut cursor)?;
        
        // Validate OLE signature
        if header.signature != 0xE11AB1A1E011CFD0 {
            return Err(Error::ParseError("Invalid OLE signature".to_string()));
        }
        
        let sector_size = 1usize << header.sector_size_power;
        let mini_sector_size = 1usize << header.mini_sector_size_power;
        
        // Build complete DIFAT
        let mut difat = header.difat.to_vec();
        
        // Read additional DIFAT sectors if needed
        let mut current_difat_sector = header.difat_first_sector;
        for _ in 0..header.num_difat_sectors {
            if current_difat_sector == FREESECT {
                break;
            }
            
            cursor.seek(SeekFrom::Start((current_difat_sector as u64 + 1) * sector_size as u64))?;
            for _ in 0..127 { // 127 entries per DIFAT sector (last is next sector pointer)
                let entry = cursor.read_u32::<LittleEndian>()?;
                if entry != FREESECT {
                    difat.push(entry);
                }
            }
            current_difat_sector = cursor.read_u32::<LittleEndian>()?;
        }
        
        // Read FAT
        let mut fat = Vec::new();
        for &fat_sector in &difat {
            if fat_sector == FREESECT {
                continue;
            }
            
            cursor.seek(SeekFrom::Start((fat_sector as u64 + 1) * sector_size as u64))?;
            for _ in 0..(sector_size / 4) {
                let entry = cursor.read_u32::<LittleEndian>()?;
                fat.push(entry);
            }
        }
        
        // Read directory entries
        let directory_entries = Self::read_directory_entries(&mut cursor, &header, &fat, sector_size)?;
        
        // Read mini FAT
        let mini_fat = Self::read_mini_fat(&mut cursor, &header, &fat, sector_size)?;
        
        // Read all streams
        let streams = Self::read_all_streams(&mut cursor, &directory_entries, &fat, &mini_fat, sector_size, mini_sector_size)?;
        
        Ok(OleCompoundDocument {
            header,
            directory_entries,
            fat,
            mini_fat,
            streams,
            sector_size,
            mini_sector_size,
        })
    }
    
    /// Read directory entries
    fn read_directory_entries(
        cursor: &mut Cursor<&[u8]>,
        header: &OleHeader,
        fat: &[u32],
        sector_size: usize,
    ) -> Result<Vec<DirectoryEntry>> {
        let mut entries = Vec::new();
        let mut current_sector = header.directory_first_sector;
        
        while current_sector != ENDOFCHAIN && current_sector != FREESECT {
            cursor.seek(SeekFrom::Start((current_sector as u64 + 1) * sector_size as u64))?;
            
            // Each sector contains multiple 128-byte directory entries
            for _ in 0..(sector_size / 128) {
                let entry = DirectoryEntry::parse(cursor)?;
                entries.push(entry);
            }
            
            // Move to next sector in chain
            if (current_sector as usize) < fat.len() {
                current_sector = fat[current_sector as usize];
            } else {
                break;
            }
        }
        
        Ok(entries)
    }
    
    /// Read mini FAT
    fn read_mini_fat(
        cursor: &mut Cursor<&[u8]>,
        header: &OleHeader,
        fat: &[u32],
        sector_size: usize,
    ) -> Result<Vec<u32>> {
        let mut mini_fat = Vec::new();
        let mut current_sector = header.mini_fat_first_sector;
        
        for _ in 0..header.num_mini_fat_sectors {
            if current_sector == ENDOFCHAIN || current_sector == FREESECT {
                break;
            }
            
            cursor.seek(SeekFrom::Start((current_sector as u64 + 1) * sector_size as u64))?;
            for _ in 0..(sector_size / 4) {
                let entry = cursor.read_u32::<LittleEndian>()?;
                mini_fat.push(entry);
            }
            
            if (current_sector as usize) < fat.len() {
                current_sector = fat[current_sector as usize];
            } else {
                break;
            }
        }
        
        Ok(mini_fat)
    }
    
    /// Read all streams from the compound document
    fn read_all_streams(
        cursor: &mut Cursor<&[u8]>,
        directory_entries: &[DirectoryEntry],
        fat: &[u32],
        mini_fat: &[u32],
        sector_size: usize,
        mini_sector_size: usize,
    ) -> Result<HashMap<String, Vec<u8>>> {
        let mut streams = HashMap::new();
        
        // Find root entry and mini stream
        let root_entry = directory_entries.iter()
            .find(|e| e.entry_type == OleEntryType::Root as u8)
            .ok_or_else(|| Error::ParseError("No root entry found".to_string()))?;
        
        let mini_stream_data = if root_entry.size > 0 {
            Self::read_stream_data(cursor, root_entry.starting_sector, root_entry.size, fat, sector_size, false)?
        } else {
            Vec::new()
        };
        
        // Read all stream entries
        for entry in directory_entries {
            if entry.entry_type == OleEntryType::Stream as u8 && !entry.name.is_empty() {
                let stream_data = if entry.size < 4096 && !mini_stream_data.is_empty() {
                    // Small stream - read from mini stream
                    Self::read_mini_stream_data(&mini_stream_data, entry.starting_sector, entry.size as usize, mini_fat, mini_sector_size)?
                } else {
                    // Regular stream
                    Self::read_stream_data(cursor, entry.starting_sector, entry.size, fat, sector_size, false)?
                };
                
                streams.insert(entry.name.clone(), stream_data);
            }
        }
        
        Ok(streams)
    }
    
    /// Read data from a regular stream
    fn read_stream_data(
        cursor: &mut Cursor<&[u8]>,
        starting_sector: u32,
        size: u64,
        fat: &[u32],
        sector_size: usize,
        _is_mini_stream: bool,
    ) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        let mut current_sector = starting_sector;
        let mut bytes_remaining = size as usize;
        
        while current_sector != ENDOFCHAIN && current_sector != FREESECT && bytes_remaining > 0 {
            cursor.seek(SeekFrom::Start((current_sector as u64 + 1) * sector_size as u64))?;
            
            let bytes_to_read = std::cmp::min(sector_size, bytes_remaining);
            let mut sector_data = vec![0u8; bytes_to_read];
            cursor.read_exact(&mut sector_data)?;
            data.extend_from_slice(&sector_data);
            
            bytes_remaining -= bytes_to_read;
            
            // Move to next sector
            if (current_sector as usize) < fat.len() {
                current_sector = fat[current_sector as usize];
            } else {
                break;
            }
        }
        
        Ok(data)
    }
    
    /// Read data from mini stream
    fn read_mini_stream_data(
        mini_stream_data: &[u8],
        starting_sector: u32,
        size: usize,
        mini_fat: &[u32],
        mini_sector_size: usize,
    ) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        let mut current_sector = starting_sector;
        let mut bytes_remaining = size;
        
        while current_sector != ENDOFCHAIN && current_sector != FREESECT && bytes_remaining > 0 {
            let sector_offset = (current_sector as usize) * mini_sector_size;
            if sector_offset + mini_sector_size > mini_stream_data.len() {
                break;
            }
            
            let bytes_to_read = std::cmp::min(mini_sector_size, bytes_remaining);
            data.extend_from_slice(&mini_stream_data[sector_offset..sector_offset + bytes_to_read]);
            
            bytes_remaining -= bytes_to_read;
            
            // Move to next mini sector
            if (current_sector as usize) < mini_fat.len() {
                current_sector = mini_fat[current_sector as usize];
            } else {
                break;
            }
        }
        
        Ok(data)
    }
    
    /// Get a specific stream by name
    pub fn get_stream(&self, name: &str) -> Option<&Vec<u8>> {
        self.streams.get(name)
    }
    
    /// List all stream names
    pub fn list_streams(&self) -> Vec<String> {
        self.streams.keys().cloned().collect()
    }
}

impl OleHeader {
    /// Parse OLE header from cursor
    fn parse(cursor: &mut Cursor<&[u8]>) -> Result<Self> {
        let signature = cursor.read_u64::<LittleEndian>()?;
        
        // Skip 16 bytes (CLSID)
        cursor.seek(SeekFrom::Current(16))?;
        
        let minor_version = cursor.read_u16::<LittleEndian>()?;
        let major_version = cursor.read_u16::<LittleEndian>()?;
        let byte_order = cursor.read_u16::<LittleEndian>()?;
        let sector_size_power = cursor.read_u16::<LittleEndian>()?;
        let mini_sector_size_power = cursor.read_u16::<LittleEndian>()?;
        
        // Skip reserved fields
        cursor.seek(SeekFrom::Current(6))?;
        
        let num_directory_sectors = cursor.read_u32::<LittleEndian>()?;
        let num_fat_sectors = cursor.read_u32::<LittleEndian>()?;
        let directory_first_sector = cursor.read_u32::<LittleEndian>()?;
        let transaction_signature = cursor.read_u32::<LittleEndian>()?;
        let mini_stream_cutoff = cursor.read_u32::<LittleEndian>()?;
        let mini_fat_first_sector = cursor.read_u32::<LittleEndian>()?;
        let num_mini_fat_sectors = cursor.read_u32::<LittleEndian>()?;
        let difat_first_sector = cursor.read_u32::<LittleEndian>()?;
        let num_difat_sectors = cursor.read_u32::<LittleEndian>()?;
        
        // Read first 109 DIFAT entries
        let mut difat = [0u32; 109];
        for i in 0..109 {
            difat[i] = cursor.read_u32::<LittleEndian>()?;
        }
        
        Ok(OleHeader {
            signature,
            minor_version,
            major_version,
            byte_order,
            sector_size_power,
            mini_sector_size_power,
            num_directory_sectors,
            num_fat_sectors,
            directory_first_sector,
            transaction_signature,
            mini_stream_cutoff,
            mini_fat_first_sector,
            num_mini_fat_sectors,
            difat_first_sector,
            num_difat_sectors,
            difat: difat.to_vec(),
        })
    }
}

impl DirectoryEntry {
    /// Parse directory entry from cursor
    fn parse(cursor: &mut Cursor<&[u8]>) -> Result<Self> {
        // Read name (UTF-16LE, up to 64 bytes)
        let mut name_utf16 = [0u16; 32];
        for i in 0..32 {
            name_utf16[i] = cursor.read_u16::<LittleEndian>()?;
        }
        
        let name_length = cursor.read_u16::<LittleEndian>()?;
        
        // Convert UTF-16 to string, stopping at null terminator
        let actual_length = (name_length / 2).saturating_sub(1) as usize; // Convert bytes to u16 count, subtract null terminator
        let name = if actual_length > 0 && actual_length <= 32 {
            String::from_utf16_lossy(&name_utf16[..actual_length])
        } else {
            String::new()
        };
        
        let entry_type = cursor.read_u8()?;
        let color_flag = cursor.read_u8()?;
        let left_sibling_id = cursor.read_u32::<LittleEndian>()?;
        let right_sibling_id = cursor.read_u32::<LittleEndian>()?;
        let child_id = cursor.read_u32::<LittleEndian>()?;
        
        // Read CLSID
        let mut clsid = [0u8; 16];
        cursor.read_exact(&mut clsid)?;
        
        let state_bits = cursor.read_u32::<LittleEndian>()?;
        let creation_time = cursor.read_u64::<LittleEndian>()?;
        let modified_time = cursor.read_u64::<LittleEndian>()?;
        let starting_sector = cursor.read_u32::<LittleEndian>()?;
        let size = cursor.read_u64::<LittleEndian>()?;
        
        Ok(DirectoryEntry {
            name,
            name_length,
            entry_type,
            color_flag,
            left_sibling_id,
            right_sibling_id,
            child_id,
            clsid,
            state_bits,
            creation_time,
            modified_time,
            starting_sector,
            size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ole_entry_type_conversion() {
        assert_eq!(OleEntryType::from(1), OleEntryType::Storage);
        assert_eq!(OleEntryType::from(2), OleEntryType::Stream);
        assert_eq!(OleEntryType::from(5), OleEntryType::Root);
        assert_eq!(OleEntryType::from(99), OleEntryType::Empty);
    }
    
    #[test]
    fn test_special_sector_values() {
        assert_eq!(FREESECT, 0xFFFFFFFF);
        assert_eq!(ENDOFCHAIN, 0xFFFFFFFE);
        assert_eq!(FATSECT, 0xFFFFFFFD);
        assert_eq!(DIFSECT, 0xFFFFFFFC);
    }
}