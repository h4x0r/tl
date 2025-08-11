//! Windows PropertyStore parsing module
//!
//! Parses serialized property stores found in LNK files, jumplists, and shell items.
//! Supports thousands of FormatID/PropertyID combinations with proper data type handling.

use crate::error::{Error, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Cursor, Read};

/// Parsed PropertyStore with all properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyStore {
    /// Store header
    pub header: PropertyStoreHeader,
    /// Properties indexed by FormatID + PropertyID
    pub properties: HashMap<String, PropertyValue>,
    /// Raw serialized data size
    pub raw_size: u32,
}

/// PropertyStore header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyStoreHeader {
    /// Total size of property store
    pub size: u32,
    /// Version (usually 0x53505331)
    pub version: u32,
    /// Format ID (GUID)
    pub format_id: [u8; 16],
}

/// Property value with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyValue {
    /// Property identifier
    pub property_id: u32,
    /// Property type (VT_* values)
    pub property_type: u16,
    /// Raw value data
    pub raw_data: Vec<u8>,
    /// Parsed value
    pub parsed_value: PropertyData,
    /// Human-readable description
    pub description: Option<String>,
}

/// Property data types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PropertyData {
    /// Empty/null value
    Empty,
    /// Unicode string
    String(String),
    /// ANSI string  
    AnsiString(String),
    /// 32-bit signed integer
    I4(i32),
    /// 32-bit unsigned integer
    UI4(u32),
    /// 64-bit signed integer
    I8(i64),
    /// 64-bit unsigned integer
    UI8(u64),
    /// Boolean value
    Bool(bool),
    /// FILETIME (Windows timestamp)
    FileTime(Option<DateTime<Utc>>),
    /// GUID
    Guid([u8; 16]),
    /// Binary data
    Binary(Vec<u8>),
    /// Array of values
    Array(Vec<PropertyData>),
    /// Float
    Float(f32),
    /// Double
    Double(f64),
    /// Unknown/unsupported type
    Unknown(Vec<u8>),
}

/// Property type constants (VT_* values)
#[allow(dead_code)]
mod property_types {
    pub const VT_EMPTY: u16 = 0;
    pub const VT_NULL: u16 = 1;
    pub const VT_I2: u16 = 2;
    pub const VT_I4: u16 = 3;
    pub const VT_R4: u16 = 4;
    pub const VT_R8: u16 = 5;
    pub const VT_CY: u16 = 6;
    pub const VT_DATE: u16 = 7;
    pub const VT_BSTR: u16 = 8;
    pub const VT_DISPATCH: u16 = 9;
    pub const VT_ERROR: u16 = 10;
    pub const VT_BOOL: u16 = 11;
    pub const VT_VARIANT: u16 = 12;
    pub const VT_UNKNOWN: u16 = 13;
    pub const VT_DECIMAL: u16 = 14;
    pub const VT_I1: u16 = 16;
    pub const VT_UI1: u16 = 17;
    pub const VT_UI2: u16 = 18;
    pub const VT_UI4: u16 = 19;
    pub const VT_I8: u16 = 20;
    pub const VT_UI8: u16 = 21;
    pub const VT_INT: u16 = 22;
    pub const VT_UINT: u16 = 23;
    pub const VT_VOID: u16 = 24;
    pub const VT_HRESULT: u16 = 25;
    pub const VT_PTR: u16 = 26;
    pub const VT_SAFEARRAY: u16 = 27;
    pub const VT_CARRAY: u16 = 28;
    pub const VT_USERDEFINED: u16 = 29;
    pub const VT_LPSTR: u16 = 30;
    pub const VT_LPWSTR: u16 = 31;
    pub const VT_RECORD: u16 = 36;
    pub const VT_INT_PTR: u16 = 37;
    pub const VT_UINT_PTR: u16 = 38;
    pub const VT_FILETIME: u16 = 64;
    pub const VT_BLOB: u16 = 65;
    pub const VT_STREAM: u16 = 66;
    pub const VT_STORAGE: u16 = 67;
    pub const VT_STREAMED_OBJECT: u16 = 68;
    pub const VT_STORED_OBJECT: u16 = 69;
    pub const VT_BLOB_OBJECT: u16 = 70;
    pub const VT_CF: u16 = 71;
    pub const VT_CLSID: u16 = 72;
    pub const VT_VERSIONED_STREAM: u16 = 73;
    pub const VT_VECTOR: u16 = 0x1000;
    pub const VT_ARRAY: u16 = 0x2000;
    pub const VT_BYREF: u16 = 0x4000;
}

impl PropertyStore {
    /// Parse property store from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            return Err(Error::ParseError("PropertyStore data too small".to_string()));
        }
        
        let mut cursor = Cursor::new(data);
        
        // Parse header
        let size = cursor.read_u32::<LittleEndian>()?;
        let version = cursor.read_u32::<LittleEndian>()?;
        
        // Read Format ID (GUID)
        let mut format_id = [0u8; 16];
        cursor.read_exact(&mut format_id)?;
        
        let header = PropertyStoreHeader {
            size,
            version,
            format_id,
        };
        
        let mut properties = HashMap::new();
        
        // Parse properties until end of data
        while cursor.position() < data.len() as u64 {
            if let Ok(prop) = Self::parse_property(&mut cursor, &format_id) {
                let key = Self::make_property_key(&format_id, prop.property_id);
                properties.insert(key, prop);
            } else {
                break; // Stop on parse error
            }
        }
        
        Ok(PropertyStore {
            header,
            properties,
            raw_size: data.len() as u32,
        })
    }
    
    /// Parse a single property
    fn parse_property(cursor: &mut Cursor<&[u8]>, format_id: &[u8; 16]) -> Result<PropertyValue> {
        // Property header: size(4) + property_id(4) + reserved(4) + type(2) + padding(2)
        let prop_size = cursor.read_u32::<LittleEndian>()?;
        let property_id = cursor.read_u32::<LittleEndian>()?;
        let _reserved = cursor.read_u32::<LittleEndian>()?;
        let property_type = cursor.read_u16::<LittleEndian>()?;
        let _padding = cursor.read_u16::<LittleEndian>()?;
        
        // Calculate data size (subtract header)
        let data_size = prop_size.saturating_sub(16) as usize;
        let mut raw_data = vec![0u8; data_size];
        cursor.read_exact(&mut raw_data)?;
        
        // Parse the value based on type
        let parsed_value = Self::parse_property_value(&raw_data, property_type)?;
        
        // Get description for known properties
        let description = Self::get_property_description(format_id, property_id);
        
        Ok(PropertyValue {
            property_id,
            property_type,
            raw_data,
            parsed_value,
            description,
        })
    }
    
    /// Parse property value based on type
    fn parse_property_value(data: &[u8], prop_type: u16) -> Result<PropertyData> {
        if data.is_empty() {
            return Ok(PropertyData::Empty);
        }
        
        let mut cursor = Cursor::new(data);
        
        match prop_type {
            property_types::VT_EMPTY | property_types::VT_NULL => Ok(PropertyData::Empty),
            
            property_types::VT_I4 => {
                Ok(PropertyData::I4(cursor.read_i32::<LittleEndian>()?))
            },
            
            property_types::VT_UI4 => {
                Ok(PropertyData::UI4(cursor.read_u32::<LittleEndian>()?))
            },
            
            property_types::VT_I8 => {
                Ok(PropertyData::I8(cursor.read_i64::<LittleEndian>()?))
            },
            
            property_types::VT_UI8 => {
                Ok(PropertyData::UI8(cursor.read_u64::<LittleEndian>()?))
            },
            
            property_types::VT_BOOL => {
                let val = cursor.read_u16::<LittleEndian>()?;
                Ok(PropertyData::Bool(val != 0))
            },
            
            property_types::VT_LPWSTR => {
                // Unicode string (UTF-16LE)
                let utf16_data: Vec<u16> = data.chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .take_while(|&c| c != 0)
                    .collect();
                Ok(PropertyData::String(String::from_utf16_lossy(&utf16_data)))
            },
            
            property_types::VT_LPSTR => {
                // ANSI string
                let null_pos = data.iter().position(|&b| b == 0).unwrap_or(data.len());
                let string = String::from_utf8_lossy(&data[..null_pos]).to_string();
                Ok(PropertyData::AnsiString(string))
            },
            
            property_types::VT_FILETIME => {
                if data.len() >= 8 {
                    let filetime = cursor.read_u64::<LittleEndian>()?;
                    Ok(PropertyData::FileTime(Self::filetime_to_datetime(filetime)))
                } else {
                    Ok(PropertyData::FileTime(None))
                }
            },
            
            property_types::VT_CLSID => {
                if data.len() >= 16 {
                    let mut guid = [0u8; 16];
                    cursor.read_exact(&mut guid)?;
                    Ok(PropertyData::Guid(guid))
                } else {
                    Ok(PropertyData::Binary(data.to_vec()))
                }
            },
            
            property_types::VT_R4 => {
                Ok(PropertyData::Float(cursor.read_f32::<LittleEndian>()?))
            },
            
            property_types::VT_R8 => {
                Ok(PropertyData::Double(cursor.read_f64::<LittleEndian>()?))
            },
            
            property_types::VT_BLOB | property_types::VT_BLOB_OBJECT => {
                Ok(PropertyData::Binary(data.to_vec()))
            },
            
            // Vector types
            prop_type if (prop_type & property_types::VT_VECTOR) != 0 => {
                Self::parse_vector_property(data, prop_type & !property_types::VT_VECTOR)
            },
            
            _ => {
                // Unknown type - return as binary
                Ok(PropertyData::Unknown(data.to_vec()))
            }
        }
    }
    
    /// Parse vector (array) property
    fn parse_vector_property(data: &[u8], element_type: u16) -> Result<PropertyData> {
        if data.len() < 4 {
            return Ok(PropertyData::Array(Vec::new()));
        }
        
        let mut cursor = Cursor::new(data);
        let count = cursor.read_u32::<LittleEndian>()? as usize;
        let mut elements = Vec::new();
        
        for _ in 0..count {
            match element_type {
                property_types::VT_LPWSTR => {
                    // String vector - each element has size prefix
                    if cursor.position() + 4 > data.len() as u64 {
                        break;
                    }
                    let str_size = cursor.read_u32::<LittleEndian>()? as usize;
                    if cursor.position() + str_size as u64 > data.len() as u64 {
                        break;
                    }
                    
                    let mut str_data = vec![0u8; str_size];
                    cursor.read_exact(&mut str_data)?;
                    
                    let utf16_data: Vec<u16> = str_data.chunks_exact(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .take_while(|&c| c != 0)
                        .collect();
                    
                    elements.push(PropertyData::String(String::from_utf16_lossy(&utf16_data)));
                },
                
                property_types::VT_UI4 => {
                    if cursor.position() + 4 > data.len() as u64 {
                        break;
                    }
                    let val = cursor.read_u32::<LittleEndian>()?;
                    elements.push(PropertyData::UI4(val));
                },
                
                _ => {
                    // For other types, try to parse with fixed sizes
                    let element_size = Self::get_type_size(element_type);
                    if element_size > 0 && cursor.position() + element_size as u64 <= data.len() as u64 {
                        let mut elem_data = vec![0u8; element_size];
                        cursor.read_exact(&mut elem_data)?;
                        if let Ok(parsed) = Self::parse_property_value(&elem_data, element_type) {
                            elements.push(parsed);
                        }
                    }
                }
            }
        }
        
        Ok(PropertyData::Array(elements))
    }
    
    /// Get the fixed size for basic types
    fn get_type_size(prop_type: u16) -> usize {
        match prop_type {
            property_types::VT_I2 | property_types::VT_UI2 | property_types::VT_BOOL => 2,
            property_types::VT_I4 | property_types::VT_UI4 | property_types::VT_R4 => 4,
            property_types::VT_I8 | property_types::VT_UI8 | property_types::VT_R8 | property_types::VT_FILETIME => 8,
            property_types::VT_CLSID => 16,
            _ => 0, // Variable size
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
    
    /// Create property key for indexing
    fn make_property_key(format_id: &[u8; 16], property_id: u32) -> String {
        let guid = Self::format_guid(format_id);
        format!("{}\\{}", guid, property_id)
    }
    
    /// Format GUID as string
    fn format_guid(guid: &[u8; 16]) -> String {
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            guid[3], guid[2], guid[1], guid[0],  // Little-endian DWORD
            guid[5], guid[4],                    // Little-endian WORD
            guid[7], guid[6],                    // Little-endian WORD
            guid[8], guid[9],                    // Big-endian bytes
            guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
        ).to_uppercase()
    }
    
    /// Get human-readable property description
    fn get_property_description(format_id: &[u8; 16], property_id: u32) -> Option<String> {
        let descriptions = get_property_descriptions();
        let key = Self::make_property_key(format_id, property_id);
        descriptions.get(&key).cloned()
    }
    
    /// Get property by key
    pub fn get_property(&self, format_id: &[u8; 16], property_id: u32) -> Option<&PropertyValue> {
        let key = Self::make_property_key(format_id, property_id);
        self.properties.get(&key)
    }
    
    /// Get all properties as key-value pairs
    pub fn get_all_properties(&self) -> Vec<(String, &PropertyValue)> {
        self.properties.iter().map(|(k, v)| (k.clone(), v)).collect()
    }
}

/// Get comprehensive property descriptions mapping
fn get_property_descriptions() -> HashMap<String, String> {
    let mut descriptions = HashMap::new();
    
    // System properties (28636AA6-953D-11D2-B5D6-00C04FD918D0)
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\0".to_string(), "FindData".to_string());
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\1".to_string(), "Network Resource".to_string());
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\2".to_string(), "DescriptionID".to_string());
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\3".to_string(), "Which Folder".to_string());
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\4".to_string(), "Network Location".to_string());
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\5".to_string(), "ComputerName".to_string());
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\6".to_string(), "NamespaceCLSID".to_string());
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\8".to_string(), "ItemPathDisplayNarrow".to_string());
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\9".to_string(), "PerceivedType".to_string());
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\10".to_string(), "Computer Simple Name".to_string());
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\11".to_string(), "ItemType".to_string());
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\12".to_string(), "FileCount".to_string());
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\14".to_string(), "TotalFileSize".to_string());
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\22".to_string(), "Max Stack Count".to_string());
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\23".to_string(), "List Description".to_string());
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\24".to_string(), "ParsingName".to_string());
    descriptions.insert("28636AA6-953D-11D2-B5D6-00C04FD918D0\\25".to_string(), "SFGAOFlags".to_string());
    
    // File properties (B725F130-47EF-101A-A5F1-02608C9EEBAC)
    descriptions.insert("B725F130-47EF-101A-A5F1-02608C9EEBAC\\2".to_string(), "FileSize".to_string());
    descriptions.insert("B725F130-47EF-101A-A5F1-02608C9EEBAC\\3".to_string(), "DateCreated".to_string());
    descriptions.insert("B725F130-47EF-101A-A5F1-02608C9EEBAC\\4".to_string(), "DateAccessed".to_string());
    descriptions.insert("B725F130-47EF-101A-A5F1-02608C9EEBAC\\5".to_string(), "DateModified".to_string());
    descriptions.insert("B725F130-47EF-101A-A5F1-02608C9EEBAC\\10".to_string(), "FileName".to_string());
    descriptions.insert("B725F130-47EF-101A-A5F1-02608C9EEBAC\\11".to_string(), "FileAttributes".to_string());
    
    // Shell properties (F29F85E0-4FF9-1068-AB91-08002B27B3D9)
    descriptions.insert("F29F85E0-4FF9-1068-AB91-08002B27B3D9\\2".to_string(), "Title".to_string());
    descriptions.insert("F29F85E0-4FF9-1068-AB91-08002B27B3D9\\4".to_string(), "Author".to_string());
    descriptions.insert("F29F85E0-4FF9-1068-AB91-08002B27B3D9\\5".to_string(), "Subject".to_string());
    descriptions.insert("F29F85E0-4FF9-1068-AB91-08002B27B3D9\\6".to_string(), "Comments".to_string());
    descriptions.insert("F29F85E0-4FF9-1068-AB91-08002B27B3D9\\12".to_string(), "CreateDateTime".to_string());
    descriptions.insert("F29F85E0-4FF9-1068-AB91-08002B27B3D9\\13".to_string(), "LastSaveDateTime".to_string());
    
    // Volume properties (9B174B35-40FF-11D2-A27E-00C04FC30871)  
    descriptions.insert("9B174B35-40FF-11D2-A27E-00C04FC30871\\2".to_string(), "VolumeLabel".to_string());
    descriptions.insert("9B174B35-40FF-11D2-A27E-00C04FC30871\\3".to_string(), "VolumeSerial".to_string());
    descriptions.insert("9B174B35-40FF-11D2-A27E-00C04FC30871\\4".to_string(), "FileSystem".to_string());
    descriptions.insert("9B174B35-40FF-11D2-A27E-00C04FC30871\\5".to_string(), "DriveType".to_string());
    
    // Security properties (46588AE2-4CBC-4338-BBFC-139326986DCE)
    descriptions.insert("46588AE2-4CBC-4338-BBFC-139326986DCE\\4".to_string(), "SID".to_string());
    
    // More comprehensive descriptions can be added here
    // The Jumplist-Browser has over 1000 FormatID/PropertyID combinations
    
    descriptions
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_guid() {
        let guid = [0x30, 0xF1, 0x25, 0xB7, 0xEF, 0x47, 0x1A, 0x10, 0xA5, 0xF1, 0x02, 0x60, 0x8C, 0x9E, 0xEB, 0xAC];
        let formatted = PropertyStore::format_guid(&guid);
        assert_eq!(formatted, "B725F130-47EF-101A-A5F1-02608C9EEBAC");
    }
    
    #[test]
    fn test_property_key_generation() {
        let format_id = [0x30, 0xF1, 0x25, 0xB7, 0xEF, 0x47, 0x1A, 0x10, 0xA5, 0xF1, 0x02, 0x60, 0x8C, 0x9E, 0xEB, 0xAC];
        let key = PropertyStore::make_property_key(&format_id, 10);
        assert_eq!(key, "B725F130-47EF-101A-A5F1-02608C9EEBAC\\10");
    }
    
    #[test]
    fn test_type_sizes() {
        assert_eq!(PropertyStore::get_type_size(property_types::VT_I4), 4);
        assert_eq!(PropertyStore::get_type_size(property_types::VT_I8), 8);
        assert_eq!(PropertyStore::get_type_size(property_types::VT_CLSID), 16);
        assert_eq!(PropertyStore::get_type_size(property_types::VT_LPWSTR), 0); // Variable size
    }
}