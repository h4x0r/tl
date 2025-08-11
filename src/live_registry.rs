//! Live Windows Registry Access Module
//!
//! Provides direct access to live Windows registry for real-time MRU extraction
//! and current user context parsing. Only available on Windows systems.

#[cfg(windows)]
use winapi::um::{
    winreg::{
        RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW,
        HKEY_CURRENT_USER, KEY_READ,
    },
    winnt::{REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ},
};

use crate::error::{Error, Result};
use crate::jumplist::RegistryMruEntry;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
#[cfg(windows)]
use std::ptr;
#[cfg(windows)]
use std::collections::HashMap;

/// Live registry accessor for Windows systems
#[cfg(windows)]
pub struct LiveRegistryAccess {
    /// Currently opened registry keys cache
    open_keys: HashMap<String, winapi::shared::minwindef::HKEY>,
}

#[cfg(not(windows))]
pub struct LiveRegistryAccess;

/// Registry value with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveRegistryValue {
    /// Value name
    pub name: String,
    /// Value type (REG_SZ, REG_BINARY, etc.)
    pub value_type: u32,
    /// Raw data
    pub data: Vec<u8>,
    /// Parsed data as string
    pub parsed_data: Option<String>,
    /// Size in bytes
    pub size: u32,
}

/// Registry key with values and subkeys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveRegistryKey {
    /// Key path
    pub path: String,
    /// Values in this key
    pub values: Vec<LiveRegistryValue>,
    /// Subkey names
    pub subkeys: Vec<String>,
    /// Last write time (if available)
    pub last_write_time: Option<DateTime<Utc>>,
}

#[cfg(windows)]
impl LiveRegistryAccess {
    /// Create a new live registry accessor
    pub fn new() -> Self {
        LiveRegistryAccess {
            open_keys: HashMap::new(),
        }
    }

    /// Get all MRU entries from live registry
    pub fn get_live_mru_entries(&mut self) -> Result<Vec<RegistryMruEntry>> {
        let mut entries = Vec::new();

        // Get known MRU locations
        let mru_locations = [
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
        ];

        // Extract MRU data from each location
        for &key_path in &mru_locations {
            if let Ok(key_data) = self.read_registry_key(key_path) {
                for value in key_data.values {
                    if value.name.to_lowercase() != "mrulist" {
                        // Skip MRUList ordering entries
                        let entry = RegistryMruEntry {
                            key_path: key_path.to_string(),
                            value_name: value.name.clone(),
                            data: value.data.clone(),
                            parsed_path: self.parse_mru_data(&value.data, key_path),
                            last_modified: key_data.last_write_time,
                        };
                        entries.push(entry);
                    }
                }
            }
        }

        Ok(entries)
    }

    /// Read a registry key and all its values
    pub fn read_registry_key(&mut self, key_path: &str) -> Result<LiveRegistryKey> {
        unsafe {
            let mut hkey: winapi::shared::minwindef::HKEY = ptr::null_mut();
            let key_path_wide = Self::to_wide_string(key_path);

            // Open the registry key
            let result = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                key_path_wide.as_ptr(),
                0,
                KEY_READ,
                &mut hkey,
            );

            if result != 0 {
                return Err(Error::Generic(format!(
                    "Failed to open registry key: {} (error: {})",
                    key_path, result
                )));
            }

            // Read all values
            let mut values = Vec::new();
            let mut index = 0u32;

            loop {
                let mut value_name = [0u16; 256];
                let mut value_name_size = 256u32;
                let mut value_type = 0u32;
                let mut data_size = 0u32;

                // First call to get the size
                let result = RegEnumValueW(
                    hkey,
                    index,
                    value_name.as_mut_ptr(),
                    &mut value_name_size,
                    ptr::null_mut(),
                    &mut value_type,
                    ptr::null_mut(),
                    &mut data_size,
                );

                if result != 0 {
                    break; // No more values
                }

                // Second call to get the data
                let mut data = vec![0u8; data_size as usize];
                let mut actual_name_size = 256u32;

                let result = RegEnumValueW(
                    hkey,
                    index,
                    value_name.as_mut_ptr(),
                    &mut actual_name_size,
                    ptr::null_mut(),
                    &mut value_type,
                    data.as_mut_ptr(),
                    &mut data_size,
                );

                if result == 0 {
                    let name = Self::from_wide_string(&value_name[..actual_name_size as usize]);
                    let parsed_data = Self::parse_registry_value(&data, value_type);

                    let value = LiveRegistryValue {
                        name,
                        value_type,
                        data,
                        parsed_data,
                        size: data_size,
                    };
                    values.push(value);
                }

                index += 1;
            }

            // Read subkeys
            let mut subkeys = Vec::new();
            let mut subkey_index = 0u32;

            loop {
                let mut subkey_name = [0u16; 256];
                let mut subkey_name_size = 256u32;

                let result = RegEnumKeyExW(
                    hkey,
                    subkey_index,
                    subkey_name.as_mut_ptr(),
                    &mut subkey_name_size,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                );

                if result != 0 {
                    break; // No more subkeys
                }

                let subkey = Self::from_wide_string(&subkey_name[..subkey_name_size as usize]);
                subkeys.push(subkey);
                subkey_index += 1;
            }

            // Close the key
            RegCloseKey(hkey);

            Ok(LiveRegistryKey {
                path: key_path.to_string(),
                values,
                subkeys,
                last_write_time: None, // Would need additional API call to get this
            })
        }
    }

    /// Parse MRU data based on key type
    fn parse_mru_data(&self, data: &[u8], key_path: &str) -> Option<String> {
        let key_lower = key_path.to_lowercase();

        if key_lower.contains("recentdocs") {
            // Recent documents - usually Unicode strings
            Self::parse_unicode_string(data)
        } else if key_lower.contains("wordwheelquery") {
            // Search terms - Unicode strings
            Self::parse_unicode_string(data)
        } else if key_lower.contains("bagmru") {
            // Shell bags - complex binary data
            Some(format!("ShellBag ({} bytes)", data.len()))
        } else {
            // Try Unicode first, then ANSI
            Self::parse_unicode_string(data).or_else(|| Self::parse_ansi_string(data))
        }
    }

    /// Parse Unicode string from registry data
    fn parse_unicode_string(data: &[u8]) -> Option<String> {
        if data.len() < 2 || data.len() % 2 != 0 {
            return None;
        }

        let utf16_data: Vec<u16> = data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .take_while(|&c| c != 0)
            .collect();

        if utf16_data.is_empty() {
            None
        } else {
            Some(String::from_utf16_lossy(&utf16_data))
        }
    }

    /// Parse ANSI string from registry data
    fn parse_ansi_string(data: &[u8]) -> Option<String> {
        let null_pos = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        let string = String::from_utf8_lossy(&data[..null_pos]).trim().to_string();
        
        if string.is_empty() {
            None
        } else {
            Some(string)
        }
    }

    /// Parse registry value data to string
    fn parse_registry_value(data: &[u8], value_type: u32) -> Option<String> {
        match value_type {
            REG_SZ | REG_EXPAND_SZ => Self::parse_unicode_string(data),
            REG_MULTI_SZ => {
                // Multiple strings separated by null terminators
                let strings: Vec<String> = data
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect::<Vec<u16>>()
                    .split(|&c| c == 0)
                    .filter_map(|s| {
                        if s.is_empty() {
                            None
                        } else {
                            Some(String::from_utf16_lossy(s))
                        }
                    })
                    .collect();
                
                if strings.is_empty() {
                    None
                } else {
                    Some(strings.join("; "))
                }
            },
            REG_DWORD => {
                if data.len() >= 4 {
                    let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    Some(val.to_string())
                } else {
                    None
                }
            },
            REG_QWORD => {
                if data.len() >= 8 {
                    let val = u64::from_le_bytes([
                        data[0], data[1], data[2], data[3],
                        data[4], data[5], data[6], data[7],
                    ]);
                    Some(val.to_string())
                } else {
                    None
                }
            },
            REG_BINARY => {
                // Return hex representation for binary data
                Some(format!(
                    "Binary ({} bytes): {}",
                    data.len(),
                    data.iter()
                        .take(16)
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                ))
            },
            _ => None,
        }
    }

    /// Convert Rust string to Windows wide string
    fn to_wide_string(s: &str) -> Vec<u16> {
        OsString::from(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Convert Windows wide string to Rust string
    fn from_wide_string(wide: &[u16]) -> String {
        OsString::from_wide(wide).to_string_lossy().into_owned()
    }

    /// Get current user SID
    pub fn get_current_user_sid(&self) -> Result<String> {
        // This would require additional Windows API calls to get the current user SID
        // For now, return a placeholder
        Ok("S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX-XXXX".to_string())
    }

    /// Check if a specific registry key exists
    pub fn key_exists(&self, key_path: &str) -> bool {
        unsafe {
            let mut hkey: winapi::shared::minwindef::HKEY = ptr::null_mut();
            let key_path_wide = Self::to_wide_string(key_path);

            let result = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                key_path_wide.as_ptr(),
                0,
                KEY_READ,
                &mut hkey,
            );

            if result == 0 {
                RegCloseKey(hkey);
                true
            } else {
                false
            }
        }
    }
}

#[cfg(not(windows))]
impl LiveRegistryAccess {
    /// Create a new live registry accessor (non-Windows stub)
    pub fn new() -> Self {
        LiveRegistryAccess
    }

    /// Get all MRU entries from live registry (non-Windows stub)
    pub fn get_live_mru_entries(&mut self) -> Result<Vec<RegistryMruEntry>> {
        Err(Error::Generic(
            "Live registry access is only available on Windows".to_string(),
        ))
    }

    /// Read a registry key (non-Windows stub)
    pub fn read_registry_key(&mut self, _key_path: &str) -> Result<LiveRegistryKey> {
        Err(Error::Generic(
            "Live registry access is only available on Windows".to_string(),
        ))
    }

    /// Get current user SID (non-Windows stub)
    pub fn get_current_user_sid(&self) -> Result<String> {
        Err(Error::Generic(
            "Live registry access is only available on Windows".to_string(),
        ))
    }

    /// Check if a specific registry key exists (non-Windows stub)
    pub fn key_exists(&self, _key_path: &str) -> bool {
        false
    }
}

impl Default for LiveRegistryAccess {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unicode_string_parsing() {
        let data = [b'H', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0, 0, 0];
        let result = LiveRegistryAccess::parse_unicode_string(&data);
        assert_eq!(result, Some("Hello".to_string()));
    }

    #[test]
    fn test_ansi_string_parsing() {
        let data = b"Hello\0";
        let result = LiveRegistryAccess::parse_ansi_string(data);
        assert_eq!(result, Some("Hello".to_string()));
    }
}