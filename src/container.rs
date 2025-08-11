//! Container archive extraction for forensic artifacts
//!
//! Supports extracting MFT data from various container formats:
//! - ZIP archives (common for forensic evidence packages)
//! - E01 Expert Witness format (forensic disk images) 
//! - Raw disk images (.dd, .raw, .img files)

use crate::error::{Error, Result};
use crate::cli::InputType;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use zip::ZipArchive;
use flate2::read::GzDecoder;

/// Container type for different archive formats
#[derive(Debug, Clone, Copy)]
pub enum ContainerType {
    Zip,
    E01,
    Raw,
}

/// Extracted artifact from container
#[derive(Debug)]
pub struct ExtractedArtifact {
    pub name: String,
    pub artifact_type: InputType,
    pub data: Vec<u8>,
}

/// Collection of artifacts extracted from container
#[derive(Debug)]
pub struct ExtractedArtifacts {
    pub artifacts: Vec<ExtractedArtifact>,
}

/// Container extractor for various forensic archive formats
pub struct ContainerExtractor;

impl ContainerExtractor {
    /// Extract all supported artifacts from container
    pub fn extract_artifacts(path: &Path, password: Option<&str>) -> Result<ExtractedArtifacts> {
        let extension = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match extension.as_str() {
            "zip" => Self::extract_all_from_zip(path, password),
            "e01" => Self::extract_all_from_e01(path),
            "dd" | "raw" | "img" => Self::extract_all_from_raw(path),
            _ => Err(Error::InvalidInput(format!(
                "Unsupported container format: {}", extension
            )))
        }
    }

    /// Legacy method - Extract MFT data from container based on file extension
    pub fn extract_mft_data(path: &Path, password: Option<&str>) -> Result<Vec<u8>> {
        let extension = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match extension.as_str() {
            "zip" => Self::extract_from_zip(path, password),
            "e01" => Self::extract_from_e01(path),
            "dd" | "raw" | "img" => Self::extract_from_raw(path),
            _ => Err(Error::InvalidInput(format!(
                "Unsupported container format: {}", extension
            )))
        }
    }

    /// Extract MFT data from ZIP archive
    fn extract_from_zip(path: &Path, password: Option<&str>) -> Result<Vec<u8>> {
        eprintln!("📦 Extracting MFT data from ZIP archive: {}", path.display());
        
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(file)?;

        // Look for common MFT file patterns in ZIP
        let mft_patterns = [
            "$MFT",
            "$mft", 
            "MFT",
            "mft",
            "$MFT.gz",
            "$mft.gz",
            "MFT.gz",
            "mft.gz",
        ];

        for i in 0..archive.len() {
            let mut zip_file = if let Some(pwd) = password {
                match archive.by_index_decrypt(i, pwd.as_bytes())? {
                    Ok(file) => file,
                    Err(_) => return Err(Error::InvalidInput("Invalid ZIP archive password".to_string())),
                }
            } else {
                archive.by_index(i)?
            };

            let filename = zip_file.name().to_string();
            eprintln!("🔍 Found file in ZIP: {}", filename);

            // Check if this matches an MFT pattern by filename
            let matches_filename_pattern = mft_patterns.iter().any(|pattern| {
                filename.ends_with(pattern) || filename.contains(pattern)
            });

            if matches_filename_pattern {
                eprintln!("🔍 Potential MFT file found: {}", filename);
                let mut data = Vec::new();
                
                if filename.ends_with(".gz") {
                    // Handle gzipped MFT files within ZIP
                    let mut gz_decoder = GzDecoder::new(zip_file);
                    gz_decoder.read_to_end(&mut data)?;
                } else {
                    zip_file.read_to_end(&mut data)?;
                }

                eprintln!("📊 Extracted {} bytes from {}", data.len(), filename);

                // Validate MFT signature
                if Self::validate_mft_signature(&data) {
                    eprintln!("✅ Confirmed valid MFT file: {}", filename);
                    return Ok(data);
                } else {
                    eprintln!("⚠️  File {} matches naming pattern but lacks MFT signature", filename);
                }
            }
        }

        // If no filename-based matches worked, try signature validation on all files
        eprintln!("🔍 No filename matches found, checking all files for MFT signatures...");
        
        for i in 0..archive.len() {
            let mut zip_file = if let Some(pwd) = password {
                match archive.by_index_decrypt(i, pwd.as_bytes())? {
                    Ok(file) => file,
                    Err(_) => continue, // Skip files that can't be decrypted
                }
            } else {
                archive.by_index(i)?
            };

            let filename = zip_file.name().to_string();
            let file_size = zip_file.size();
            
            // Only check files that could reasonably be MFT files (>1KB, <10GB)
            if file_size < 1024 || file_size > 10 * 1024 * 1024 * 1024 {
                continue;
            }

            eprintln!("🔍 Checking signature for: {} ({} bytes)", filename, file_size);
            
            // Read first few KB to check signature
            let mut signature_buffer = vec![0u8; std::cmp::min(8192, file_size as usize)];
            let bytes_read = zip_file.read(&mut signature_buffer)?;
            signature_buffer.truncate(bytes_read);
            
            if Self::validate_mft_signature(&signature_buffer) {
                eprintln!("✅ Found MFT file by signature: {}", filename);
                
                // Read the full file
                let mut full_data = signature_buffer;
                zip_file.read_to_end(&mut full_data)?;
                
                eprintln!("📊 Extracted {} bytes from {}", full_data.len(), filename);
                return Ok(full_data);
            }
        }

        Err(Error::InvalidInput(
            "No valid MFT file found in ZIP archive. Searched by filename patterns and MFT signatures.".to_string()
        ))
    }

    /// Extract MFT data from E01 Expert Witness format
    fn extract_from_e01(_path: &Path) -> Result<Vec<u8>> {
        // For now, return an error with a helpful message
        // E01 support requires specialized libraries or custom implementation
        Err(Error::InvalidInput(
            "E01 Expert Witness format support is not yet implemented. \
            Please extract the disk image first and use the raw format, \
            or use ZIP archives for now.".to_string()
        ))
    }

    /// Extract MFT data from raw disk images  
    fn extract_from_raw(path: &Path) -> Result<Vec<u8>> {
        eprintln!("💾 Extracting MFT data from raw disk image: {}", path.display());

        let mut file = File::open(path)?;
        let file_size = file.metadata()?.len();
        
        eprintln!("📊 Raw image size: {} bytes ({:.2} GB)", 
                 file_size, file_size as f64 / (1024.0 * 1024.0 * 1024.0));

        // For NTFS, the MFT is typically located at a specific offset
        // We'll try several common locations and patterns
        Self::locate_mft_in_raw_image(&mut file, file_size)
    }

    /// Locate MFT within a raw disk image
    fn locate_mft_in_raw_image(file: &mut File, file_size: u64) -> Result<Vec<u8>> {
        // NTFS boot sector is at offset 0, contains MFT location
        let mut boot_sector = vec![0u8; 512];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut boot_sector)?;

        // Check for NTFS signature
        if &boot_sector[3..11] != b"NTFS    " {
            return Err(Error::InvalidInput(
                "Raw image does not contain NTFS filesystem signature".to_string()
            ));
        }

        // Parse NTFS boot sector to get MFT location
        let bytes_per_sector = u16::from_le_bytes([boot_sector[11], boot_sector[12]]) as u64;
        let sectors_per_cluster = boot_sector[13] as u64;
        let bytes_per_cluster = bytes_per_sector * sectors_per_cluster;

        // MFT cluster number is at offset 48 in boot sector
        let mft_cluster_number = u64::from_le_bytes([
            boot_sector[48], boot_sector[49], boot_sector[50], boot_sector[51],
            boot_sector[52], boot_sector[53], boot_sector[54], boot_sector[55]
        ]);

        let mft_offset = mft_cluster_number * bytes_per_cluster;
        
        eprintln!("🎯 Found NTFS filesystem:");
        eprintln!("   Bytes per sector: {}", bytes_per_sector);
        eprintln!("   Sectors per cluster: {}", sectors_per_cluster);
        eprintln!("   Bytes per cluster: {}", bytes_per_cluster);
        eprintln!("   MFT cluster number: {}", mft_cluster_number);
        eprintln!("   MFT offset: 0x{:X} ({} bytes)", mft_offset, mft_offset);

        // Validate MFT offset
        if mft_offset >= file_size {
            return Err(Error::InvalidInput(
                format!("MFT offset 0x{:X} exceeds file size", mft_offset)
            ));
        }

        // Read MFT data - start with first 10MB as reasonable default
        let mft_size_to_read = std::cmp::min(10 * 1024 * 1024, file_size - mft_offset);
        
        file.seek(SeekFrom::Start(mft_offset))?;
        let mut mft_data = vec![0u8; mft_size_to_read as usize];
        file.read_exact(&mut mft_data)?;

        // Verify MFT signature in first record
        if &mft_data[0..4] != b"FILE" {
            return Err(Error::InvalidInput(
                format!("Invalid MFT signature at offset 0x{:X}. Expected 'FILE', found: {:?}",
                       mft_offset, &mft_data[0..4])
            ));
        }

        eprintln!("✅ Successfully located MFT at offset 0x{:X}", mft_offset);
        eprintln!("📊 Read {} bytes of MFT data", mft_data.len());

        Ok(mft_data)
    }

    /// Detect artifact type from filename
    fn detect_artifact_type(filename: &str) -> Option<InputType> {
        let lower_name = filename.to_lowercase();
        
        // MFT patterns
        if lower_name.contains("$mft") || lower_name == "mft" || lower_name.ends_with(".mft") {
            return Some(InputType::Mft);
        }
        
        // LNK files (exclude recycle bin metadata files)
        if lower_name.ends_with(".lnk") {
            // Skip recycle bin metadata files that have .lnk extensions but aren't real LNK files
            let basename = std::path::Path::new(filename).file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if basename.starts_with("$I") && filename.contains("$Recycle.Bin") {
                return None; // This is a recycle bin metadata file, not a LNK file
            }
            return Some(InputType::Lnk);
        }
        
        // Jumplist files
        if lower_name.ends_with(".automaticdestinations-ms") {
            return Some(InputType::AutomaticDestinations);
        }
        if lower_name.ends_with(".customdestinations-ms") {
            return Some(InputType::CustomDestinations);
        }
        
        // Registry files
        if lower_name.contains("ntuser") || lower_name.contains("system") || 
           lower_name.contains("software") || lower_name.contains("sam") || 
           lower_name.contains("security") || lower_name.ends_with(".dat") {
            return Some(InputType::Registry);
        }
        
        None
    }

    /// Extract all artifacts from ZIP archive with optimized in-memory processing
    fn extract_all_from_zip(path: &Path, password: Option<&str>) -> Result<ExtractedArtifacts> {
        eprintln!("📦 Extracting all artifacts from ZIP archive: {}", path.display());
        
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(file)?;
        let mut artifacts = Vec::new();
        
        // Pre-allocate for better performance
        let mut mft_found = false;

        // Scan all files in the ZIP with optimized processing
        for i in 0..archive.len() {
            let mut zip_file = if let Some(pwd) = password {
                match archive.by_index_decrypt(i, pwd.as_bytes())? {
                    Ok(file) => file,
                    Err(_) => {
                        eprintln!("⚠️  Skipping encrypted file (wrong password): file {}", i);
                        continue;
                    }
                }
            } else {
                archive.by_index(i)?
            };

            let filename = zip_file.name().to_string();
            let file_size = zip_file.size();
            eprintln!("🔍 Found file in ZIP: {} ({} bytes)", filename, file_size);

            // Detect artifact type with early detection for large MFT files
            if let Some(artifact_type) = Self::detect_artifact_type(&filename) {
                eprintln!("✅ Identified {} artifact: {}", 
                         format!("{:?}", artifact_type).to_lowercase(), filename);
                
                // For MFT files, use streaming read to handle large files efficiently
                let data = if artifact_type == InputType::Mft && file_size > 100 * 1024 * 1024 {
                    eprintln!("🚀 Using optimized in-memory processing for large MFT file ({} MB)", 
                             file_size / (1024 * 1024));
                    mft_found = true;
                    Self::extract_large_file_in_memory(&mut zip_file, &filename, file_size)?
                } else {
                    Self::extract_regular_file(&mut zip_file, &filename)?
                };

                eprintln!("📊 Extracted {} bytes from {} (in-memory)", data.len(), filename);

                artifacts.push(ExtractedArtifact {
                    name: filename,
                    artifact_type,
                    data,
                });
            } else {
                eprintln!("⚠️  Skipping unknown file type: {}", filename);
            }
        }

        if artifacts.is_empty() {
            return Err(Error::InvalidInput(
                "No supported artifacts found in ZIP archive. Expected MFT, LNK, jumplist, or registry files.".to_string()
            ));
        }

        eprintln!("🎉 Successfully extracted {} artifacts from ZIP{}", 
                 artifacts.len(),
                 if mft_found { " (optimized in-memory processing)" } else { "" });
        Ok(ExtractedArtifacts { artifacts })
    }
    
    /// Extract large files using optimized in-memory processing
    fn extract_large_file_in_memory(zip_file: &mut impl Read, filename: &str, file_size: u64) -> Result<Vec<u8>> {
        const BUFFER_SIZE: usize = 1024 * 1024; // 1MB buffer for optimal I/O
        
        let mut data = Vec::with_capacity(file_size as usize);
        let mut buffer = vec![0u8; BUFFER_SIZE];
        let mut total_read = 0u64;
        
        eprintln!("💾 Reading large file in chunks for optimal memory usage...");
        
        while total_read < file_size {
            let bytes_to_read = std::cmp::min(BUFFER_SIZE, (file_size - total_read) as usize);
            let bytes_read = zip_file.read(&mut buffer[..bytes_to_read])?;
            
            if bytes_read == 0 {
                break;
            }
            
            data.extend_from_slice(&buffer[..bytes_read]);
            total_read += bytes_read as u64;
            
            // Show progress for large files
            if total_read % (50 * 1024 * 1024) == 0 || total_read == file_size {
                eprintln!("📈 Progress: {:.1}% ({} MB)", 
                         (total_read as f64 / file_size as f64) * 100.0,
                         total_read / (1024 * 1024));
            }
        }
        
        if filename.ends_with(".gz") {
            eprintln!("🗜️  Decompressing gzipped data...");
            let mut gz_decoder = GzDecoder::new(&data[..]);
            let mut decompressed = Vec::new();
            gz_decoder.read_to_end(&mut decompressed)?;
            Ok(decompressed)
        } else {
            Ok(data)
        }
    }
    
    /// Extract regular sized files
    fn extract_regular_file(zip_file: &mut impl Read, filename: &str) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        
        if filename.ends_with(".gz") {
            let mut gz_decoder = GzDecoder::new(zip_file);
            gz_decoder.read_to_end(&mut data)?;
        } else {
            zip_file.read_to_end(&mut data)?;
        }
        
        Ok(data)
    }

    /// Extract all artifacts from E01 format
    fn extract_all_from_e01(_path: &Path) -> Result<ExtractedArtifacts> {
        Err(Error::InvalidInput(
            "E01 multi-artifact extraction not yet implemented. \
            Please extract individual files first.".to_string()
        ))
    }

    /// Extract all artifacts from raw images
    fn extract_all_from_raw(path: &Path) -> Result<ExtractedArtifacts> {
        // For now, raw images only support MFT extraction
        let mft_data = Self::extract_from_raw(path)?;
        
        let artifacts = vec![ExtractedArtifact {
            name: "$MFT".to_string(),
            artifact_type: InputType::Mft,
            data: mft_data,
        }];

        Ok(ExtractedArtifacts { artifacts })
    }
}

impl ContainerExtractor {
    /// Validate MFT signature by checking for FILE record magic bytes
    fn validate_mft_signature(data: &[u8]) -> bool {
        if data.len() < 1024 {
            return false;
        }

        // Check first record for MFT signature
        if &data[0..4] == b"FILE" {
            return true;
        }

        // Sometimes MFT files have padding or headers, check multiple offsets
        let offsets_to_check = [0, 512, 1024, 2048];
        
        for &offset in &offsets_to_check {
            if offset + 4 <= data.len() && &data[offset..offset + 4] == b"FILE" {
                eprintln!("🎯 Found MFT signature at offset {}", offset);
                return true;
            }
        }

        // Check for pattern of multiple FILE records (MFT record boundaries)
        let mut file_signatures = 0;
        let mut pos = 0;
        
        while pos + 1024 <= data.len() {
            if &data[pos..pos + 4] == b"FILE" {
                file_signatures += 1;
                if file_signatures >= 3 {
                    eprintln!("🎯 Found multiple MFT signatures, confirming MFT file");
                    return true;
                }
            }
            pos += 1024; // Standard MFT record size
        }

        false
    }
}

/// Helper function to determine if a file is a container format
pub fn is_container_format(path: &Path) -> bool {
    let extension = path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
        
    matches!(extension.as_str(), "zip" | "e01" | "dd" | "raw" | "img")
}