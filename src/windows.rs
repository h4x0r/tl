//! Windows-specific functionality for live system access.

#[cfg(windows)]
use crate::error::{Error, Result};
#[cfg(windows)]
use byteorder::{LittleEndian, ReadBytesExt};
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::io::{Cursor, Read, Seek, SeekFrom};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use winapi::shared::minwindef::DWORD;
#[cfg(windows)]
use winapi::um::fileapi::{CreateFileW, ReadFile, SetFilePointer};
#[cfg(windows)]
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use winapi::um::winbase::FILE_BEGIN;
#[cfg(windows)]
use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, HANDLE};

#[cfg(windows)]
const BOOT_SECTOR_SIZE: usize = 512;

/// Boot sector information for NTFS volumes
#[cfg(windows)]
#[derive(Debug, Clone)]
pub struct BootSector {
    /// Bytes per sector (usually 512)
    pub bytes_per_sector: u16,
    /// Sectors per cluster
    pub sectors_per_cluster: u8,
    /// Calculated bytes per cluster
    pub bytes_per_cluster: u32,
    /// MFT starting cluster number
    pub mft_cluster: u64,
    /// Calculated MFT byte offset
    pub mft_offset: u64,
    /// Clusters per MFT record segment
    pub clusters_per_file_record_segment: u32,
    /// Calculated MFT record size in bytes
    pub mft_record_size: u32,
}

/// Provides live access to NTFS volumes on Windows systems
#[cfg(windows)]
pub struct LiveSystemAccess {
    /// Windows file handle to the drive
    handle: HANDLE,
    /// Parsed boot sector information
    pub boot_sector: BootSector,
}

#[cfg(windows)]
impl LiveSystemAccess {
    /// Open a drive for live system access
    ///
    /// # Arguments
    /// * `drive_letter` - Drive letter (e.g., 'C', 'D')
    ///
    /// # Errors
    /// Returns error if:
    /// - Drive access is denied (requires Administrator privileges)
    /// - Drive is not NTFS
    /// - Boot sector cannot be read or parsed
    pub fn open_drive(drive_letter: char) -> Result<Self> {
        let drive_path = format!("\\\\.\\{}:", drive_letter);
        let wide_path: Vec<u16> = OsStr::new(&drive_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                3, // OPEN_EXISTING
                0,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(Error::AccessDenied(format!(
                "Failed to open drive {}: Access denied. Run as Administrator.",
                drive_letter
            )));
        }

        let boot_sector = Self::read_boot_sector(handle)?;

        Ok(Self {
            handle,
            boot_sector,
        })
    }

    /// Read and parse the NTFS boot sector
    fn read_boot_sector(handle: HANDLE) -> Result<BootSector> {
        let mut buffer = vec![0u8; BOOT_SECTOR_SIZE];
        let mut bytes_read: DWORD = 0;

        let success = unsafe {
            ReadFile(
                handle,
                buffer.as_mut_ptr() as *mut _,
                BOOT_SECTOR_SIZE as DWORD,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };

        if success == 0 || bytes_read != BOOT_SECTOR_SIZE as DWORD {
            return Err(Error::WindowsApi("Failed to read boot sector".to_string()));
        }

        let mut cursor = Cursor::new(&buffer);
        cursor.seek(SeekFrom::Start(11))?;

        let bytes_per_sector = cursor.read_u16::<LittleEndian>()?;
        let sectors_per_cluster = cursor.read_u8()?;

        cursor.seek(SeekFrom::Start(48))?;
        let mft_cluster = cursor.read_u64::<LittleEndian>()?;

        cursor.seek(SeekFrom::Start(64))?;
        let clusters_per_file_record_segment = cursor.read_u32::<LittleEndian>()?;

        let bytes_per_cluster = bytes_per_sector as u32 * sectors_per_cluster as u32;
        let mft_offset = bytes_per_cluster as u64 * mft_cluster;

        let mft_record_size = if clusters_per_file_record_segment > 127 {
            // Handle special case for certain Windows 7 x64 VMs
            let test_val = 256 - clusters_per_file_record_segment;
            let mut size = 2u32;
            for _ in 1..test_val {
                size *= 2;
            }
            size
        } else {
            bytes_per_cluster * clusters_per_file_record_segment
        };

        Ok(BootSector {
            bytes_per_sector,
            sectors_per_cluster,
            bytes_per_cluster,
            mft_cluster,
            mft_offset,
            clusters_per_file_record_segment,
            mft_record_size,
        })
    }

    /// Read MFT records from the live system
    ///
    /// # Arguments
    /// * `num_records` - Number of MFT records to read
    ///
    /// # Returns
    /// Vector of bytes containing the raw MFT data
    ///
    /// # Errors
    /// Returns error if reading from the drive fails
    pub fn read_mft_records(&self, num_records: usize) -> Result<Vec<u8>> {
        let total_size = num_records * self.boot_sector.mft_record_size as usize;
        let mut buffer = vec![0u8; total_size];

        unsafe {
            SetFilePointer(
                self.handle,
                self.boot_sector.mft_offset as i32,
                std::ptr::null_mut(),
                FILE_BEGIN,
            );
        }

        let mut bytes_read: DWORD = 0;
        let success = unsafe {
            ReadFile(
                self.handle,
                buffer.as_mut_ptr() as *mut _,
                total_size as DWORD,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };

        if success == 0 {
            return Err(Error::WindowsApi("Failed to read MFT records".to_string()));
        }

        buffer.truncate(bytes_read as usize);
        Ok(buffer)
    }

    /// Get information about the accessed drive
    pub fn drive_info(&self) -> String {
        format!(
            "MFT located at offset: 0x{:x}, MFT record size: {} bytes",
            self.boot_sector.mft_offset, self.boot_sector.mft_record_size
        )
    }
}

#[cfg(windows)]
impl Drop for LiveSystemAccess {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}


