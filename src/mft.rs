//! Ultra-high-performance MFT parsing with SIMD, parallel processing, and memory optimizations

use crate::error::{Error, Result};
use crate::types::{Event, EventTimestamps};
use crate::simd_optimize::{
    StringPool, scan_record_boundaries_simd,
    find_attributes_simd, convert_timestamps_simd, apply_fixups_simd
};
use crate::cli::InputType;
use crate::jumplist::JumplistParser;
use crate::lnk_parser::LnkParser;
use crate::registry::RegistryParser;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::Arc;
use byteorder::{LittleEndian, ReadBytesExt};
use bitflags::bitflags;
use rayon::prelude::*;
use parking_lot::RwLock;
use dashmap::DashMap;

/// MFT record size in bytes (standard NTFS)
pub const MFT_RECORD_SIZE: usize = 1024;

/// Processing chunk size for optimal cache performance
const PROCESSING_CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
const MAX_PARALLEL_THREADS: usize = 16;

/// FILETIME to Unix epoch offset (100-nanosecond intervals)
const FILETIME_UNIX_EPOCH: u64 = 116444736000000000;

bitflags! {
    /// MFT Entry flags
    pub struct EntryFlags: u16 {
        const ALLOCATED             = 0x01;
        const INDEX_PRESENT         = 0x02;
        const IS_EXTENSION          = 0x04;
        const SPECIAL_INDEX_PRESENT = 0x08;
    }
}

bitflags! {
    /// File attribute flags  
    pub struct FileAttributeFlags: u32 {
        const FILE_ATTRIBUTE_READONLY             = 0x0000_0001;
        const FILE_ATTRIBUTE_HIDDEN               = 0x0000_0002;
        const FILE_ATTRIBUTE_SYSTEM               = 0x0000_0004;
        const FILE_ATTRIBUTE_DIRECTORY            = 0x0000_0010;
        const FILE_ATTRIBUTE_ARCHIVE              = 0x0000_0020;
        const FILE_ATTRIBUTE_DEVICE               = 0x0000_0040;
        const FILE_ATTRIBUTE_NORMAL               = 0x0000_0080;
        const FILE_ATTRIBUTE_TEMPORARY            = 0x0000_0100;
        const FILE_ATTRIBUTE_SPARSE_FILE          = 0x0000_0200;
        const FILE_ATTRIBUTE_REPARSE_POINT        = 0x0000_0400;
        const FILE_ATTRIBUTE_COMPRESSED           = 0x0000_0800;
        const FILE_ATTRIBUTE_OFFLINE              = 0x0000_1000;
        const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  = 0x0000_2000;
        const FILE_ATTRIBUTE_ENCRYPTED            = 0x0000_4000;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileNamespace {
    POSIX = 0,
    Win32 = 1,
    DOS = 2,
    Win32AndDos = 3,
}

impl FileNamespace {
    #[inline(always)]
    fn from_u8(value: u8) -> Option<FileNamespace> {
        match value {
            0 => Some(FileNamespace::POSIX),
            1 => Some(FileNamespace::Win32),
            2 => Some(FileNamespace::DOS),
            3 => Some(FileNamespace::Win32AndDos),
            _ => None,
        }
    }
    
    #[inline(always)]
    fn priority(self) -> u8 {
        match self {
            FileNamespace::Win32 | FileNamespace::Win32AndDos => 0,
            FileNamespace::DOS => 1,
            FileNamespace::POSIX => 2,
        }
    }
}

/// Optimized entry header with pre-computed values
#[derive(Debug, Clone)]
pub struct EntryHeader {
    pub signature: [u8; 4],
    pub usa_offset: u16,
    pub usa_size: u16,
    pub metadata_transaction_journal: u64,
    pub sequence: u16,
    pub hard_link_count: u16,
    pub first_attribute_record_offset: u16,
    pub flags: EntryFlags,
    pub used_entry_size: u32,
    pub total_entry_size: u32,
    pub base_reference_entry: u64,
    pub base_reference_sequence: u16,
    pub first_attribute_id: u16,
    pub record_number: u64,
}

/// Cached filename attribute for performance
#[derive(Debug, Clone)]
pub struct FileNameAttribute {
    pub parent_entry: u64,
    pub created: Option<chrono::DateTime<chrono::Utc>>,
    pub modified: Option<chrono::DateTime<chrono::Utc>>,
    pub mft_modified: Option<chrono::DateTime<chrono::Utc>>,
    pub accessed: Option<chrono::DateTime<chrono::Utc>>,
    pub logical_size: u64,
    pub physical_size: u64,
    pub flags: FileAttributeFlags,
    pub name_length: u8,
    pub namespace: FileNamespace,
    pub name: Arc<str>,
}

/// Streaming parser result
#[derive(Debug)]
pub struct StreamingResult {
    pub records: Vec<Event>,
    pub progress: f64,
    pub total_processed: usize,
    pub errors: usize,
}

/// Lightweight record info for path reconstruction
#[derive(Clone)]
struct PathInfo {
    filename: Arc<str>,
    parent_id: u64,
}

/// Ultra-high-performance MFT parser with aggressive optimizations
pub struct MftParser {
    /// Shared string pool for deduplication
    string_pool: Arc<StringPool>,
    /// Lightweight path info for all records (for path reconstruction)
    path_info: Arc<DashMap<u64, PathInfo>>,
    /// Full computed path cache
    path_cache: Arc<DashMap<u64, String>>,
    /// Memory-mapped data cache
    mmap_cache: Arc<RwLock<Option<memmap2::Mmap>>>,
    /// Processing configuration
    parallel_threads: usize,
    use_simd: bool,
}

impl MftParser {
    pub fn new() -> Self {
        Self {
            string_pool: Arc::new(StringPool::new()),
            path_info: Arc::new(DashMap::with_capacity(1024 * 1024)), // Pre-size for 1M records
            path_cache: Arc::new(DashMap::with_capacity(65536)),
            mmap_cache: Arc::new(RwLock::new(None)),
            parallel_threads: std::cmp::min(rayon::current_num_threads(), MAX_PARALLEL_THREADS),
            use_simd: Self::detect_simd_support(),
        }
    }
    
    /// Create parser with configuration
    pub fn with_config(config: crate::types::ParsingConfig) -> Self {
        let mut parser = Self::new();
        parser.parallel_threads = if config.parallel_processing {
            std::cmp::min(rayon::current_num_threads(), MAX_PARALLEL_THREADS)
        } else {
            1
        };
        parser
    }
    
    fn detect_simd_support() -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            std::arch::is_x86_feature_detected!("avx2")
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    }

    /// Detect input file type based on extension and content
    fn detect_input_type(path: &Path) -> Result<InputType> {
        let extension = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        
        // Check for jumplist files first (handle compound extensions)
        if filename.ends_with(".automaticDestinations-ms") {
            return Ok(InputType::AutomaticDestinations);
        } else if filename.ends_with(".customDestinations-ms") {
            return Ok(InputType::CustomDestinations);
        }
        
        match extension.as_str() {
            "lnk" => Ok(InputType::Lnk),
            "dat" => {
                let filename = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                if filename.contains("ntuser") || filename.contains("system") || 
                   filename.contains("software") || filename.contains("sam") || 
                   filename.contains("security") {
                    Ok(InputType::Registry)
                } else {
                    Ok(InputType::Mft)
                }
            },
            "ms" => {
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if filename.ends_with(".automaticDestinations-ms") {
                    Ok(InputType::AutomaticDestinations)
                } else if filename.ends_with(".customDestinations-ms") {
                    Ok(InputType::CustomDestinations)
                } else {
                    Err(Error::InvalidInput(format!("Unknown .ms file type: {}", filename)))
                }
            },
            "mft" | "bin" | "gz" => Ok(InputType::Mft),
            _ => {
                let filename = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                if filename.contains("automaticDestinations") {
                    Ok(InputType::AutomaticDestinations)
                } else if filename.contains("customDestinations") {
                    Ok(InputType::CustomDestinations)
                } else if filename.contains("ntuser") {
                    Ok(InputType::Registry)
                } else if filename.contains("$mft") {
                    Ok(InputType::Mft)
                } else {
                    Ok(InputType::Mft)
                }
            }
        }
    }
    
    /// Parse input from file path - dispatches to appropriate parser based on file type
    pub fn parse_input(&mut self, path: &Path, _password: Option<&str>) -> Result<Vec<Event>> {
        // Detect input file type
        let input_type = Self::detect_input_type(path)?;
        
        match input_type {
            InputType::Mft => self.parse_mft_file(path),
            InputType::Lnk => self.parse_lnk_file(path),
            InputType::AutomaticDestinations | InputType::CustomDestinations => {
                self.parse_jumplist_file(path, input_type)
            },
            InputType::Registry => self.parse_registry_file(path),
            _ => {
                // Default to MFT parsing for unknown types
                self.parse_mft_file(path)
            }
        }
    }

    /// Parse MFT file with memory mapping for large files
    fn parse_mft_file(&mut self, path: &Path) -> Result<Vec<Event>> {
        let file = std::fs::File::open(path)?;
        let metadata = file.metadata()?;
        
        // Use memory mapping for files larger than 1MB
        if metadata.len() > 1024 * 1024 {
            return self.parse_mmap(path);
        } else {
            let data = std::fs::read(path)?;
            self.parse_mft_data(&data)
        }
    }
    
    /// Memory-mapped parsing for large files
    fn parse_mmap(&mut self, path: &Path) -> Result<Vec<Event>> {
        let file = std::fs::File::open(path)?;
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        
        eprintln!("🚀 Using memory-mapped parsing for large file ({} bytes)", mmap.len());
        
        // Parse directly from mmap to avoid borrowing issues
        let result = self.parse_mft_data_parallel(&mmap);
        
        // Store mmap for potential reuse after parsing
        *self.mmap_cache.write() = Some(mmap);
        
        result
    }

    /// Parse LNK file and extract timeline events
    fn parse_lnk_file(&mut self, path: &Path) -> Result<Vec<Event>> {
        let data = std::fs::read(path)?;
        let lnk_parser = LnkParser::new();
        let shell_link = match lnk_parser.parse_lnk_data(&data) {
            Ok(link) => link,
            Err(e) => {
                eprintln!("⚠️  Failed to parse LNK file {}: {}", path.display(), e);
                return Ok(Vec::new()); // Skip invalid LNK files instead of failing
            }
        };
        
        // Convert shell link to Event format
        let mut records = Vec::new();
        
        if let Some(record) = Self::shell_link_to_mft_record(&shell_link, path)? {
            records.push(record);
        }
        
        Ok(records)
    }

    /// Parse jumplist file and extract timeline events
    fn parse_jumplist_file(&mut self, path: &Path, jumplist_type: InputType) -> Result<Vec<Event>> {
        let data = std::fs::read(path)?;
        let jumplist_parser = JumplistParser::new();
        
        let jumplist_entries = match jumplist_type {
            InputType::AutomaticDestinations => {
                jumplist_parser.parse_automatic_destinations(&data)?
            },
            InputType::CustomDestinations => {
                jumplist_parser.parse_custom_destinations(&data)?
            },
            _ => return Err(Error::InvalidInput("Invalid jumplist type".to_string())),
        };
        
        // Convert jumplist entries to Event format
        let mut records = Vec::new();
        
        for entry in jumplist_entries {
            if let Some(record) = Self::jumplist_entry_to_mft_record(&entry, path)? {
                records.push(record);
            }
        }
        
        Ok(records)
    }

    /// Parse registry file and extract timeline events
    fn parse_registry_file(&mut self, path: &Path) -> Result<Vec<Event>> {
        let data = std::fs::read(path)?;
        let registry_parser = RegistryParser::new();
        let registry_hive = registry_parser.parse_registry_data(&data, path)?;
        
        // Extract timeline events from registry
        let registry_events = registry_parser.extract_timeline_events(&registry_hive)?;
        
        // Convert registry events to Event format
        let mut records = Vec::new();
        
        for event in registry_events {
            if let Some(record) = Self::registry_event_to_mft_record(&event, path)? {
                records.push(record);
            }
        }
        
        Ok(records)
    }
    
    /// Parse MFT data with maximum optimizations
    pub fn parse_mft_data(&mut self, data: &[u8]) -> Result<Vec<Event>> {
        if data.len() > PROCESSING_CHUNK_SIZE * 4 && self.parallel_threads > 1 {
            self.parse_mft_data_parallel(data)
        } else {
            self.parse_mft_data_sequential(data)
        }
    }
    
    /// High-performance parallel parsing
    fn parse_mft_data_parallel(&mut self, data: &[u8]) -> Result<Vec<Event>> {
        eprintln!("🚀 Using parallel MFT parser ({} threads, SIMD: {})", 
                 self.parallel_threads, self.use_simd);
        
        let start_time = std::time::Instant::now();
        
        // Step 1: SIMD-accelerated boundary detection
        let boundaries = if self.use_simd {
            scan_record_boundaries_simd(data)
        } else {
            self.scan_boundaries_scalar(data)
        };
        
        eprintln!("📍 Found {} potential MFT records in {:?}", 
                 boundaries.len(), start_time.elapsed());
        
        // Handle case where no records are found
        if boundaries.is_empty() {
            eprintln!("⚠️  No MFT records found in data");
            return Ok(Vec::new());
        }
        
        // Step 2: Parallel parsing with work-stealing
        let boundary_chunks: Vec<_> = boundaries
            .chunks((boundaries.len() + self.parallel_threads - 1) / self.parallel_threads)
            .collect();
        
        // Use shared progress tracking
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let threads_completed = Arc::new(AtomicUsize::new(0));
        
        let records: std::result::Result<Vec<Vec<Event>>, Error> = boundary_chunks
            .into_par_iter()
            .map(|chunk_boundaries| {
                let mut chunk_records = Vec::with_capacity(chunk_boundaries.len());
                let mut _valid_count = 0;
                let mut _error_count = 0;
                
                for &offset in chunk_boundaries {
                    if offset + MFT_RECORD_SIZE <= data.len() {
                        let record_data = &data[offset..offset + MFT_RECORD_SIZE];
                        let record_number = (offset / MFT_RECORD_SIZE) as u64;
                        
                        match self.parse_single_entry_fast(record_data, record_number) {
                            Ok(Some(record)) => {
                                chunk_records.push(record);
                                _valid_count += 1;
                            }
                            Ok(None) => {} // Skip invalid records
                            Err(_e) => {
                                _error_count += 1;
                            }
                        }
                    }
                }
                
                // Update progress bar
                let completed = threads_completed.fetch_add(1, Ordering::Relaxed) + 1;
                let progress_bar = "█".repeat(completed) + &"░".repeat(self.parallel_threads - completed);
                eprint!("\r🧵 [{}/{}] [{}] Processing threads", completed, self.parallel_threads, progress_bar);
                if completed == self.parallel_threads {
                    eprintln!(); // New line when done
                }
                
                Ok(chunk_records)
            })
            .collect();
        
        let mut all_records: Vec<Event> = records?
            .into_iter()
            .flatten()
            .collect();
        
        let parse_time = start_time.elapsed();
        eprintln!("⚡ Parsed {} records in {:?} ({:.0} records/sec)", 
                 all_records.len(), parse_time, 
                 all_records.len() as f64 / parse_time.as_secs_f64());
        
        // Step 3: Parallel directory path building
        self.build_directory_paths_parallel(&mut all_records);
        
        eprintln!("📊 Total processing time: {:?}", start_time.elapsed());
        Ok(all_records)
    }
    
    /// Sequential parsing for smaller files  
    fn parse_mft_data_sequential(&mut self, data: &[u8]) -> Result<Vec<Event>> {
        eprintln!("🚀 Using sequential MFT parser (SIMD: {})", self.use_simd);
        
        let mut parsed_records = Vec::with_capacity(data.len() / MFT_RECORD_SIZE);
        let mut valid_count = 0;
        let mut error_count = 0;
        
        // Process in 1024-byte chunks
        for (record_num, chunk) in data.chunks(MFT_RECORD_SIZE).enumerate() {
            if chunk.len() < MFT_RECORD_SIZE {
                break;
            }
            
            match self.parse_single_entry_fast(chunk, record_num as u64) {
                Ok(Some(record)) => {
                    parsed_records.push(record);
                    valid_count += 1;
                }
                Ok(None) => {} // Skip invalid records
                Err(_e) => {
                    error_count += 1;
                    if error_count <= 5 {
                        log::debug!("Entry parsing error at record {}: {}", record_num, _e);
                    }
                }
            }
        }
        
        eprintln!("📊 Parsed {} valid records, {} errors", valid_count, error_count);
        
        // Build directory paths
        self.build_directory_paths_sequential(&mut parsed_records);
        
        Ok(parsed_records)
    }
    
    /// Streaming parser for real-time processing
    pub fn parse_streaming<'a>(&'a mut self, data: &'a [u8]) -> impl Iterator<Item = Result<StreamingResult>> + 'a {
        let total_records = data.len() / MFT_RECORD_SIZE;
        let chunk_size = std::cmp::max(1000, total_records / 100); // 1% chunks
        
        data.chunks(chunk_size * MFT_RECORD_SIZE)
            .enumerate()
            .map(move |(chunk_idx, chunk_data)| {
                let mut chunk_records = Vec::new();
                let mut errors = 0;
                
                for (record_idx, record_data) in chunk_data.chunks(MFT_RECORD_SIZE).enumerate() {
                    if record_data.len() < MFT_RECORD_SIZE {
                        continue;
                    }
                    
                    let record_number = (chunk_idx * chunk_size + record_idx) as u64;
                    match self.parse_single_entry_fast(record_data, record_number) {
                        Ok(Some(record)) => chunk_records.push(record),
                        Ok(None) => {}
                        Err(_) => errors += 1,
                    }
                }
                
                let progress = ((chunk_idx + 1) as f64 / (total_records / chunk_size) as f64).min(1.0);
                let total_processed = (chunk_idx + 1) * chunk_size;
                
                Ok(StreamingResult {
                    records: chunk_records,
                    progress,
                    total_processed,
                    errors,
                })
            })
    }
    
    /// Ultra-fast single entry parsing with aggressive optimizations
    #[inline(always)]
    fn parse_single_entry_fast(&self, buffer: &[u8], entry_number: u64) -> Result<Option<Event>> {
        // Fast signature check first
        if buffer.len() < 4 {
            return Ok(None);
        }
        
        let signature = [buffer[0], buffer[1], buffer[2], buffer[3]];
        
        // Skip zero records immediately
        if signature == [0, 0, 0, 0] {
            return Ok(None);
        }
        
        // Only process FILE records for now (BAAD records are corrupted)
        if signature != *b"FILE" {
            return Ok(None);
        }
        
        // Fast header parsing with minimal error checking for speed
        let header = self.parse_entry_header_fast(buffer, entry_number)?;
        
        // Apply fixups using SIMD if possible
        let mut entry_buffer = buffer.to_vec();
        let _valid_fixup = if self.use_simd {
            apply_fixups_simd(&mut entry_buffer, 
                            header.usa_offset as usize, 
                            header.usa_size as usize,
                            header.record_number)
        } else {
            self.apply_fixups_scalar(&header, &mut entry_buffer)?
        };
        
        // Fast record conversion
        self.convert_entry_to_record_fast(&header, &entry_buffer)
    }
    
    /// Ultra-fast header parsing with minimal bounds checking
    #[inline(always)]
    fn parse_entry_header_fast(&self, data: &[u8], entry_number: u64) -> Result<EntryHeader> {
        if data.len() < 48 {
            return Err(Error::MftParsing("Buffer too small for header".to_string()));
        }
        
        let mut cursor = Cursor::new(data);
        
        let mut signature = [0u8; 4];
        cursor.read_exact(&mut signature)?;
        
        let usa_offset = cursor.read_u16::<LittleEndian>()?;
        let usa_size = cursor.read_u16::<LittleEndian>()?;
        let metadata_transaction_journal = cursor.read_u64::<LittleEndian>()?;
        let sequence = cursor.read_u16::<LittleEndian>()?;
        let hard_link_count = cursor.read_u16::<LittleEndian>()?;
        let first_attribute_offset = cursor.read_u16::<LittleEndian>()?;
        let flags = EntryFlags::from_bits_truncate(cursor.read_u16::<LittleEndian>()?);
        let used_entry_size = cursor.read_u32::<LittleEndian>()?;
        let total_entry_size = cursor.read_u32::<LittleEndian>()?;
        let base_reference_entry = cursor.read_u64::<LittleEndian>()? & 0xFFFFFFFFFFFF;
        let base_reference_sequence = cursor.read_u16::<LittleEndian>()?;
        let first_attribute_id = cursor.read_u16::<LittleEndian>()?;
        
        Ok(EntryHeader {
            signature,
            usa_offset,
            usa_size,
            metadata_transaction_journal,
            sequence,
            hard_link_count,
            first_attribute_record_offset: first_attribute_offset,
            flags,
            used_entry_size,
            total_entry_size,
            base_reference_entry,
            base_reference_sequence,
            first_attribute_id,
            record_number: entry_number,
        })
    }
    
    /// Scalar fixup application (fallback)
    #[inline(always)]
    fn apply_fixups_scalar(&self, header: &EntryHeader, buffer: &mut [u8]) -> Result<bool> {
        if header.usa_size <= 1 {
            return Ok(true);
        }
        
        let number_of_fixups = (header.usa_size - 1) as usize;
        let fixups_start = header.usa_offset as usize;
        let fixups_end = fixups_start + (header.usa_size as usize * 2);
        
        if fixups_end > buffer.len() {
            return Ok(false);
        }
        
        let fixups = buffer[fixups_start..fixups_end].to_vec();
        let _update_sequence = [fixups[0], fixups[1]];
        
        for stride in 0..number_of_fixups {
            let sector_pos = stride * 512 + 510;
            if sector_pos + 1 >= buffer.len() {
                break;
            }
            
            let fixup_idx = 2 + stride * 2;
            if fixup_idx + 1 >= fixups.len() {
                break;
            }
            
            // Skip validation in fast mode, just apply
            buffer[sector_pos] = fixups[fixup_idx];
            buffer[sector_pos + 1] = fixups[fixup_idx + 1];
        }
        
        Ok(true)
    }
    
    /// Fast record conversion with caching and string pooling
    #[inline(always)]
    fn convert_entry_to_record_fast(&self, header: &EntryHeader, data: &[u8]) -> Result<Option<Event>> {
        let mut record = Event::default();
        
        // Basic record info
        record.record_number = header.record_number;
        record.sequence_number = header.sequence;
        record.link_count = Some(header.hard_link_count);
        record.is_directory = header.flags.contains(EntryFlags::INDEX_PRESENT);
        record.is_deleted = !header.flags.contains(EntryFlags::ALLOCATED);
        record.event_source = Some("MFT".to_string());
        
        // Fast attribute parsing with SIMD optimization
        self.parse_attributes_fast(data, header, &mut record)?;
        
        Ok(Some(record))
    }
    
    /// SIMD-accelerated attribute parsing
    #[inline(always)]
    fn parse_attributes_fast(&self, data: &[u8], header: &EntryHeader, record: &mut Event) -> Result<()> {
        // Find all attributes we care about in one pass
        let target_types = [0x10u32, 0x30u32, 0x80u32]; // SI, FN, DATA
        let attributes = if self.use_simd {
            find_attributes_simd(data, &target_types)
        } else {
            self.find_attributes_scalar(data, header, &target_types)
        };
        
        let mut best_filename: Option<FileNameAttribute> = None;
        let mut best_priority = u8::MAX;
        
        for (attr_type, offset) in attributes {
            match attr_type {
                0x10 => { // STANDARD_INFORMATION
                    if let Ok(timestamps) = self.parse_standard_information_fast(&data[offset..]) {
                        record.timestamps = timestamps;
                    }
                }
                0x30 => { // FILE_NAME
                    if let Ok(filename_attr) = self.parse_file_name_fast(&data[offset..]) {
                        let priority = filename_attr.namespace.priority();
                        if priority < best_priority {
                            best_filename = Some(filename_attr);
                            best_priority = priority;
                        }
                    }
                }
                0x80 => { // DATA
                    if record.file_size.is_none() {
                        if let Ok(size) = self.parse_data_size_fast(&data[offset..]) {
                            record.file_size = Some(size);
                        }
                    }
                }
                _ => {}
            }
        }
        
        // Apply best filename
        if let Some(filename_attr) = best_filename {
            record.filename = Some(filename_attr.name.to_string());
            record.parent_directory = Some(filename_attr.parent_entry);
            
            record.fn_timestamps = EventTimestamps {
                created: filename_attr.created,
                modified: filename_attr.modified,
                mft_modified: filename_attr.mft_modified,
                accessed: filename_attr.accessed,
            };
            
            if record.file_size.is_none() {
                record.file_size = Some(filename_attr.logical_size);
                record.allocated_size = Some(filename_attr.physical_size);
            }
        }
        
        Ok(())
    }
    
    /// Scalar attribute finding (fallback)
    fn find_attributes_scalar(&self, data: &[u8], header: &EntryHeader, target_types: &[u32]) -> Vec<(u32, usize)> {
        let mut attributes = Vec::with_capacity(8);
        let mut offset = header.first_attribute_record_offset as usize;
        
        while offset + 8 <= data.len() {
            let attr_type = u32::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
            ]);
            
            if attr_type == 0xFFFFFFFF {
                break;
            }
            
            let attr_length = u32::from_le_bytes([
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
            ]) as usize;
            
            if attr_length < 16 || offset + attr_length > data.len() {
                break;
            }
            
            if target_types.contains(&attr_type) {
                attributes.push((attr_type, offset));
            }
            
            offset += attr_length;
        }
        
        attributes
    }
    
    /// Fast STANDARD_INFORMATION parsing
    #[inline(always)]
    fn parse_standard_information_fast(&self, attr_data: &[u8]) -> Result<EventTimestamps> {
        if attr_data.len() < 24 || attr_data[8] != 0 {
            return Ok(EventTimestamps::default());
        }
        
        let content_offset = u16::from_le_bytes([attr_data[20], attr_data[21]]) as usize;
        if content_offset + 32 > attr_data.len() {
            return Ok(EventTimestamps::default());
        }
        
        let content = &attr_data[content_offset..];
        
        // Read timestamps as u64 array for SIMD conversion
        let timestamps = [
            u64::from_le_bytes([content[0], content[1], content[2], content[3], content[4], content[5], content[6], content[7]]),
            u64::from_le_bytes([content[8], content[9], content[10], content[11], content[12], content[13], content[14], content[15]]),
            u64::from_le_bytes([content[16], content[17], content[18], content[19], content[20], content[21], content[22], content[23]]),
            u64::from_le_bytes([content[24], content[25], content[26], content[27], content[28], content[29], content[30], content[31]]),
        ];
        
        let converted = if self.use_simd {
            convert_timestamps_simd(&timestamps)
        } else {
            timestamps.iter().map(|&ft| self.convert_filetime_fast(ft)).collect()
        };
        
        Ok(EventTimestamps {
            created: converted.get(0).copied().unwrap_or(None),
            modified: converted.get(1).copied().unwrap_or(None),
            mft_modified: converted.get(2).copied().unwrap_or(None),
            accessed: converted.get(3).copied().unwrap_or(None),
        })
    }
    
    /// Fast FILE_NAME parsing with string pooling
    #[inline(always)]
    fn parse_file_name_fast(&self, attr_data: &[u8]) -> Result<FileNameAttribute> {
        if attr_data.len() < 24 || attr_data[8] != 0 {
            return Err(Error::MftParsing("Invalid FILE_NAME attribute".to_string()));
        }
        
        let content_offset = u16::from_le_bytes([attr_data[20], attr_data[21]]) as usize;
        if content_offset + 66 > attr_data.len() {
            return Err(Error::MftParsing("FILE_NAME content too small".to_string()));
        }
        
        let content = &attr_data[content_offset..];
        
        let parent_entry = u64::from_le_bytes([
            content[0], content[1], content[2], content[3],
            content[4], content[5], content[6], content[7],
        ]) & 0xFFFFFFFFFFFF;
        
        // Batch timestamp conversion
        let timestamps = [
            u64::from_le_bytes([content[8], content[9], content[10], content[11], content[12], content[13], content[14], content[15]]),
            u64::from_le_bytes([content[16], content[17], content[18], content[19], content[20], content[21], content[22], content[23]]),
            u64::from_le_bytes([content[24], content[25], content[26], content[27], content[28], content[29], content[30], content[31]]),
            u64::from_le_bytes([content[32], content[33], content[34], content[35], content[36], content[37], content[38], content[39]]),
        ];
        
        let converted = if self.use_simd {
            convert_timestamps_simd(&timestamps)
        } else {
            timestamps.iter().map(|&ft| self.convert_filetime_fast(ft)).collect::<Vec<_>>()
        };
        
        let logical_size = u64::from_le_bytes([content[40], content[41], content[42], content[43], content[44], content[45], content[46], content[47]]);
        let physical_size = u64::from_le_bytes([content[48], content[49], content[50], content[51], content[52], content[53], content[54], content[55]]);
        let flags = FileAttributeFlags::from_bits_truncate(u32::from_le_bytes([content[56], content[57], content[58], content[59]]));
        
        let name_length = content[64] as usize;
        let namespace = FileNamespace::from_u8(content[65]).unwrap_or(FileNamespace::POSIX);
        
        // Fast filename conversion with string pooling
        let name = if name_length > 0 && 66 + name_length * 2 <= content.len() {
            let filename_bytes = &content[66..66 + name_length * 2];
            self.string_pool.intern_utf16(filename_bytes)
        } else {
            self.string_pool.intern(b"")
        };
        
        Ok(FileNameAttribute {
            parent_entry,
            created: converted.get(0).copied().unwrap_or(None),
            modified: converted.get(1).copied().unwrap_or(None),
            mft_modified: converted.get(2).copied().unwrap_or(None),
            accessed: converted.get(3).copied().unwrap_or(None),
            logical_size,
            physical_size,
            flags,
            name_length: name_length as u8,
            namespace,
            name,
        })
    }
    
    /// Fast DATA attribute size parsing
    #[inline(always)]
    fn parse_data_size_fast(&self, attr_data: &[u8]) -> Result<u64> {
        if attr_data.len() < 16 {
            return Ok(0);
        }
        
        if attr_data[8] != 0 {
            // Non-resident
            if attr_data.len() >= 48 {
                Ok(u64::from_le_bytes([
                    attr_data[40], attr_data[41], attr_data[42], attr_data[43],
                    attr_data[44], attr_data[45], attr_data[46], attr_data[47],
                ]))
            } else {
                Ok(0)
            }
        } else {
            // Resident
            if attr_data.len() >= 20 {
                Ok(u32::from_le_bytes([
                    attr_data[16], attr_data[17], attr_data[18], attr_data[19],
                ]) as u64)
            } else {
                Ok(0)
            }
        }
    }
    
    /// Fast FILETIME conversion
    #[inline(always)]
    fn convert_filetime_fast(&self, filetime: u64) -> Option<chrono::DateTime<chrono::Utc>> {
        if filetime == 0 || filetime <= FILETIME_UNIX_EPOCH {
            return None;
        }
        
        let unix_nanos = (filetime - FILETIME_UNIX_EPOCH) * 100;
        let unix_seconds = unix_nanos / 1_000_000_000;
        let nanos = (unix_nanos % 1_000_000_000) as u32;
        
        chrono::DateTime::from_timestamp(unix_seconds as i64, nanos)
    }
    
    /// Scalar boundary scanning (fallback)
    fn scan_boundaries_scalar(&self, data: &[u8]) -> Vec<usize> {
        let mut boundaries = Vec::with_capacity(data.len() / MFT_RECORD_SIZE);
        
        for (record_idx, chunk) in data.chunks(MFT_RECORD_SIZE).enumerate() {
            if chunk.len() >= 4 {
                let sig = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                if sig == 0x454C4946 || sig == 0x44414142 { // FILE or BAAD
                    boundaries.push(record_idx * MFT_RECORD_SIZE);
                }
            }
        }
        
        boundaries
    }
    
    /// Parallel directory path building with proper two-pass processing
    fn build_directory_paths_parallel(&self, records: &mut [Event]) {
        // First pass: Store lightweight path info for all records
        records.par_iter()
            .for_each(|record| {
                if let Some(filename) = &record.filename {
                    let path_info = PathInfo {
                        filename: self.string_pool.intern(filename.as_bytes()),
                        parent_id: record.parent_directory.unwrap_or(0),
                    };
                    self.path_info.insert(record.record_number, path_info);
                }
            });
        
        // Second pass: Build full paths using recursive parent lookup
        records.par_iter_mut()
            .for_each(|record| {
                record.location = Some(self.get_full_path_for_record(record.record_number));
            });
    }
    
    /// Sequential directory path building with proper two-pass processing
    fn build_directory_paths_sequential(&self, records: &mut [Event]) {
        // First pass: Store lightweight path info for all records
        for record in records.iter() {
            if let Some(filename) = &record.filename {
                let path_info = PathInfo {
                    filename: self.string_pool.intern(filename.as_bytes()),
                    parent_id: record.parent_directory.unwrap_or(0),
                };
                self.path_info.insert(record.record_number, path_info);
            }
        }
        
        // Second pass: Build full paths using recursive parent lookup
        for record in records.iter_mut() {
            record.location = Some(self.get_full_path_for_record(record.record_number));
        }
    }
    
    /// Get full path for a record (like proven implementation's get_full_path_for_entry)
    fn get_full_path_for_record(&self, entry_id: u64) -> String {
        // Check cache first
        if let Some(cached_path) = self.path_cache.get(&entry_id) {
            return cached_path.clone();
        }
        
        // Build path recursively
        let path = self.build_path_recursive(entry_id, &mut std::collections::HashSet::new());
        
        // Cache the result
        self.path_cache.insert(entry_id, path.clone());
        path
    }
    
    /// Internal recursive path builder (like proven implementation's inner_get_entry)
    fn build_path_recursive(&self, entry_id: u64, visited: &mut std::collections::HashSet<u64>) -> String {
        // Prevent infinite recursion
        if visited.contains(&entry_id) {
            return format!("[Cycle-{}]", entry_id);
        }
        
        // MFT entry 5 is the root directory
        if entry_id == 5 {
            return String::new();
        }
        
        visited.insert(entry_id);
        
        // Check if we have path info for this record
        if let Some(info) = self.path_info.get(&entry_id) {
            let filename = info.filename.as_ref();
            let parent_id = info.parent_id;
            
            if parent_id == 5 {
                // Direct child of root
                return filename.to_string();
            } else if parent_id == entry_id {
                // Self-referential, orphaned
                return format!("[Orphaned]/{}", filename);
            } else if parent_id > 0 {
                // Recursively build parent path
                let parent_path = self.build_path_recursive(parent_id, visited);
                if parent_path.is_empty() {
                    return filename.to_string();
                } else if parent_path.starts_with("[") {
                    // Parent is orphaned or unknown
                    return format!("{}/{}", parent_path, filename);
                } else {
                    return format!("{}/{}", parent_path, filename);
                }
            } else {
                // No parent, consider it orphaned
                return format!("[Orphaned]/{}", filename);
            }
        } else {
            // Record not found
            format!("[NotFound-{}]", entry_id)
        }
    }

    /// Convert Shell Link to Event format
    fn shell_link_to_mft_record(
        shell_link: &crate::lnk_parser::ShellLink, 
        source_path: &Path
    ) -> Result<Option<Event>> {
        // For LNK files, the filename should be the target executable/file name only
        let target_path = shell_link.target_path.clone().unwrap_or_else(|| "Unknown".to_string());
        let filename = if target_path == "Unknown" {
            "Unknown".to_string()
        } else {
            // Extract just the filename from the Windows path using backslash splitting
            // std::path::Path doesn't work well with Windows paths on non-Windows systems
            target_path.split('\\').last().unwrap_or(&target_path).to_string()
        };
            
        // Location should be the full target path for the "Full Path" column
        let location = target_path;

        let record = Event {
            record_number: 0, // LNK files use 🔗 instead of record numbers
            sequence_number: 0,
            filename: Some(filename), // Remove "LNK: " prefix
            file_size: Some(shell_link.header.file_size as u64),
            allocated_size: Some(shell_link.header.file_size as u64),
            is_directory: false,
            is_deleted: false,
            link_count: Some(1),
            parent_directory: None,
            timestamps: shell_link.timestamps.clone(),
            fn_timestamps: EventTimestamps::default(), // LNK files don't have FILE_NAME attributes (N/A)
            alternate_data_streams: Vec::new(),
            location: Some(location), // Use target path as location
            event_source: Some("LNK".to_string()),
        };

        Ok(Some(record))
    }

    /// Clean jumplist path to show proper Windows path structure
    fn clean_jumplist_path(path: &Path) -> String {
        let path_str = path.to_string_lossy();
        
        // Handle URL-encoded paths like "uploads/auto/C%3A/Users/..."
        let decoded_path = urlencoding::decode(&path_str).unwrap_or(std::borrow::Cow::Borrowed(&path_str));
        
        // Find "Users" in the path and extract from there
        if let Some(users_pos) = decoded_path.find("Users") {
            decoded_path[users_pos..].to_string()
        } else {
            // If no "Users" found, try to extract just the filename
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| decoded_path.to_string())
        }
    }

    /// Convert Jumplist Entry to Event format
    fn jumplist_entry_to_mft_record(
        entry: &crate::jumplist::JumplistEntry, 
        source_path: &Path
    ) -> Result<Option<Event>> {
        let filename = entry.target_path.clone()
            .unwrap_or_else(|| "Unknown Jumplist Entry".to_string());

        let cleaned_path = Self::clean_jumplist_path(source_path);
        let location = if let Some(parent_pos) = cleaned_path.rfind('/') {
            cleaned_path[..parent_pos].to_string()
        } else if let Some(parent_pos) = cleaned_path.rfind('\\') {
            cleaned_path[..parent_pos].to_string()
        } else {
            "Unknown".to_string()
        };

        let jumplist_type = if source_path.to_string_lossy().contains("automaticDestinations") {
            "AutoDest"
        } else {
            "CustomDest"
        };

        let record = Event {
            record_number: 0, // Jumplist entries don't have MFT record numbers
            sequence_number: 0,
            filename: Some(format!("{}: {}", jumplist_type, filename)), // Clean filename without emoji
            file_size: Some(entry.file_size.unwrap_or(0)),
            allocated_size: Some(entry.file_size.unwrap_or(0)),
            is_directory: false,
            is_deleted: false,
            link_count: Some(1),
            parent_directory: None,
            timestamps: entry.timestamps.clone(),
            fn_timestamps: EventTimestamps::default(), // Jumplist files don't have FILE_NAME attributes (N/A)
            alternate_data_streams: Vec::new(),
            location: Some(format!("{} [Source: {}]", cleaned_path.rsplit(['/', '\\']).next().unwrap_or(&cleaned_path), cleaned_path)),
            event_source: Some("Jumplist".to_string()),
        };

        Ok(Some(record))
    }

    /// Convert Registry Event to Event format
    fn registry_event_to_mft_record(
        event: &crate::registry::RegistryTimelineEvent, 
        source_path: &Path
    ) -> Result<Option<Event>> {
        let key_path = &event.key_path;
        let default_value = "(Default)".to_string();
        let value_name = event.value_name.as_ref().unwrap_or(&default_value);
        let filename = format!("REG: {}\\{}", key_path, value_name);

        let location = source_path.parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let hive_name = source_path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let record = Event {
            record_number: 0, // Registry events don't have MFT record numbers
            sequence_number: 0,
            filename: Some(filename),
            file_size: Some(event.data_size.unwrap_or(0) as u64),
            allocated_size: Some(event.data_size.unwrap_or(0) as u64),
            is_directory: false,
            is_deleted: false,
            link_count: Some(1),
            parent_directory: None,
            timestamps: event.timestamps.clone(),
            fn_timestamps: EventTimestamps::default(), // Registry events don't have FILE_NAME attributes (N/A)
            alternate_data_streams: Vec::new(),
            location: Some(format!("{} [Hive: {}, Source: {}]", location, hive_name, source_path.to_string_lossy())),
            event_source: Some("Registry".to_string()),
        };

        Ok(Some(record))
    }
}

// Implement Default for compatibility
impl Default for MftParser {
    fn default() -> Self {
        Self::new()
    }
}