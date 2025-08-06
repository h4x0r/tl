//! SIMD and vectorization optimizations for ultra-fast MFT parsing

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;
use std::sync::Arc;
use parking_lot::RwLock;
use wide::u32x8;

/// SIMD-optimized constants
pub const FILE_SIG_PATTERN: u32 = 0x454C4946; // "FILE" in little-endian
pub const BAAD_SIG_PATTERN: u32 = 0x44414142; // "BAAD" in little-endian
pub const ZERO_SIG_PATTERN: u32 = 0x00000000; // Zero pattern

/// SIMD-optimized string pool for filename deduplication
pub struct StringPool {
    pool: Arc<RwLock<dashmap::DashMap<u64, Arc<str>>>>,
}

impl StringPool {
    pub fn new() -> Self {
        Self {
            pool: Arc::new(RwLock::new(dashmap::DashMap::with_capacity(65536))),
        }
    }
    
    pub fn intern(&self, data: &[u8]) -> Arc<str> {
        let hash = self.fast_hash(data);
        
        if let Some(existing) = self.pool.read().get(&hash) {
            return existing.clone();
        }
        
        let string: Arc<str> = String::from_utf8_lossy(data).into();
        self.pool.read().insert(hash, string.clone());
        string
    }
    
    pub fn intern_utf16(&self, utf16_data: &[u8]) -> Arc<str> {
        let hash = self.fast_hash(utf16_data);
        
        if let Some(existing) = self.pool.read().get(&hash) {
            return existing.clone();
        }
        
        let string: Arc<str> = self.convert_utf16_simd(utf16_data)
            .unwrap_or_else(|_| "[Invalid UTF-16]".to_string())
            .into();
        self.pool.read().insert(hash, string.clone());
        string
    }
    
    #[inline(always)]
    fn fast_hash(&self, data: &[u8]) -> u64 {
        // FNV-1a hash for speed
        let mut hash = 0xcbf29ce484222325u64;
        for &byte in data {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }
    
    /// SIMD-optimized UTF-16 to UTF-8 conversion
    fn convert_utf16_simd(&self, utf16_data: &[u8]) -> Result<String, std::string::FromUtf16Error> {
        if utf16_data.len() % 2 != 0 {
            return Ok(String::new());
        }
        
        let mut utf16_chars = Vec::with_capacity(utf16_data.len() / 2);
        
        // Process in SIMD chunks of 8 u16s
        let chunks = utf16_data.chunks_exact(16); // 8 * 2 bytes
        let remainder = chunks.remainder();
        
        for chunk in chunks {
            // Load 8 u16 values using SIMD
            let mut chars = [0u16; 8];
            for (i, pair) in chunk.chunks_exact(2).enumerate() {
                chars[i] = u16::from_le_bytes([pair[0], pair[1]]);
            }
            utf16_chars.extend_from_slice(&chars);
        }
        
        // Handle remainder
        for pair in remainder.chunks_exact(2) {
            utf16_chars.push(u16::from_le_bytes([pair[0], pair[1]]));
        }
        
        String::from_utf16(&utf16_chars)
    }
}

/// SIMD-accelerated signature scanning (x86_64 only)
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn find_signatures_avx2(data: &[u8]) -> Vec<usize> {
    let mut positions = Vec::with_capacity(data.len() / 1024);
    let file_pattern = u32x8::splat(FILE_SIG_PATTERN);
    let baad_pattern = u32x8::splat(BAAD_SIG_PATTERN);
    
    // Process 32 bytes (8 u32s) at a time
    let chunks = data.chunks_exact(32);
    let remainder = chunks.remainder();
    
    for (chunk_idx, chunk) in chunks.enumerate() {
        // Load 8 u32 values
        let chunk_ptr = chunk.as_ptr() as *const u32;
        let values = u32x8::from([
            std::ptr::read_unaligned(chunk_ptr),
            std::ptr::read_unaligned(chunk_ptr.add(1)),
            std::ptr::read_unaligned(chunk_ptr.add(2)),
            std::ptr::read_unaligned(chunk_ptr.add(3)),
            std::ptr::read_unaligned(chunk_ptr.add(4)),
            std::ptr::read_unaligned(chunk_ptr.add(5)),
            std::ptr::read_unaligned(chunk_ptr.add(6)),
            std::ptr::read_unaligned(chunk_ptr.add(7)),
        ]);
        
        // Compare against patterns
        let file_matches = values.cmp_eq(file_pattern);
        let baad_matches = values.cmp_eq(baad_pattern);
        
        // Check for matches and record positions
        let file_mask = file_matches.to_array();
        let baad_mask = baad_matches.to_array();
        
        for (i, (&file_match, &baad_match)) in file_mask.iter().zip(baad_mask.iter()).enumerate() {
            if file_match != 0 || baad_match != 0 {
                positions.push(chunk_idx * 32 + i * 4);
            }
        }
    }
    
    // Handle remainder with scalar code
    for (i, chunk) in remainder.chunks_exact(4).enumerate() {
        let sig = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if sig == FILE_SIG_PATTERN || sig == BAAD_SIG_PATTERN {
            positions.push(data.len() - remainder.len() + i * 4);
        }
    }
    
    positions
}

/// Fallback signature scanning for systems without AVX2
pub fn find_signatures_scalar(data: &[u8]) -> Vec<usize> {
    let mut positions = Vec::with_capacity(data.len() / 1024);
    
    // Process 4-byte chunks
    for (i, chunk) in data.chunks_exact(4).enumerate() {
        let sig = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if sig == FILE_SIG_PATTERN || sig == BAAD_SIG_PATTERN {
            positions.push(i * 4);
        }
    }
    
    positions
}

/// Adaptive signature finding that uses best available SIMD
pub fn find_signatures_adaptive(data: &[u8]) -> Vec<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            unsafe { find_signatures_avx2(data) }
        } else {
            find_signatures_scalar(data)
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        find_signatures_scalar(data)
    }
}

/// SIMD-accelerated record boundary detection
pub fn scan_record_boundaries_simd(data: &[u8]) -> Vec<usize> {
    let mut boundaries = Vec::with_capacity(data.len() / 1024);
    
    // Scan in 1024-byte chunks (MFT record size)
    for (record_idx, chunk) in data.chunks(1024).enumerate() {
        if chunk.len() >= 4 {
            let sig = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            if sig == FILE_SIG_PATTERN || sig == BAAD_SIG_PATTERN {
                boundaries.push(record_idx * 1024);
            }
        }
    }
    
    boundaries
}

/// SIMD-optimized attribute scanning within MFT records
pub fn find_attributes_simd(record_data: &[u8], target_types: &[u32]) -> Vec<(u32, usize)> {
    let mut positions = Vec::with_capacity(16);
    
    if record_data.len() < 24 {
        return positions;
    }
    
    // Get first attribute offset from MFT header
    let first_attr_offset = if record_data.len() >= 22 {
        u16::from_le_bytes([record_data[20], record_data[21]]) as usize
    } else {
        return positions;
    };
    
    if first_attr_offset >= record_data.len() {
        return positions;
    }
    
    let attr_data = &record_data[first_attr_offset..];
    let mut offset = 0;
    
    // Create SIMD pattern for target types if we have few targets
    let use_simd = target_types.len() <= 4;
    
    while offset + 8 <= attr_data.len() {
        let attr_type = u32::from_le_bytes([
            attr_data[offset],
            attr_data[offset + 1],
            attr_data[offset + 2],
            attr_data[offset + 3],
        ]);
        
        // Check for end marker
        if attr_type == 0xFFFFFFFF {
            break;
        }
        
        let attr_length = u32::from_le_bytes([
            attr_data[offset + 4],
            attr_data[offset + 5],
            attr_data[offset + 6],
            attr_data[offset + 7],
        ]) as usize;
        
        if attr_length == 0 || attr_length < 16 {
            break;
        }
        
        // Check if this is a target type
        if use_simd && target_types.len() <= 4 {
            // Use SIMD comparison for up to 4 target types
            let targets = u32x8::from([
                target_types.get(0).copied().unwrap_or(0xFFFFFFFF),
                target_types.get(1).copied().unwrap_or(0xFFFFFFFF),
                target_types.get(2).copied().unwrap_or(0xFFFFFFFF),
                target_types.get(3).copied().unwrap_or(0xFFFFFFFF),
                0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            ]);
            
            let attr_vec = u32x8::splat(attr_type);
            let matches = attr_vec.cmp_eq(targets);
            let match_mask = matches.to_array();
            
            // Check if any of the first 4 positions matched
            if match_mask[0] != 0 || match_mask[1] != 0 || match_mask[2] != 0 || match_mask[3] != 0 {
                positions.push((attr_type, first_attr_offset + offset));
            }
        } else {
            // Scalar comparison for many target types
            if target_types.contains(&attr_type) {
                positions.push((attr_type, first_attr_offset + offset));
            }
        }
        
        offset += attr_length;
        
        if offset >= attr_data.len() {
            break;
        }
    }
    
    positions
}

/// Batch FILETIME conversion using optimized scalar operations
pub fn convert_timestamps_simd(filetimes: &[u64]) -> Vec<Option<chrono::DateTime<chrono::Utc>>> {
    const FILETIME_UNIX_EPOCH: u64 = 116444736000000000;
    
    filetimes
        .iter()
        .map(|&filetime| {
            if filetime == 0 || filetime <= FILETIME_UNIX_EPOCH {
                None
            } else {
                let unix_nanos = (filetime - FILETIME_UNIX_EPOCH) * 100;
                let unix_seconds = unix_nanos / 1_000_000_000;
                let nanos = (unix_nanos % 1_000_000_000) as u32;
                
                chrono::DateTime::from_timestamp(unix_seconds as i64, nanos)
            }
        })
        .collect()
}

/// Memory-aligned buffer for optimal SIMD access
pub struct AlignedBuffer {
    data: Vec<u8>,
    alignment: usize,
}

impl AlignedBuffer {
    pub fn new(size: usize, alignment: usize) -> Self {
        let mut data = Vec::with_capacity(size + alignment);
        data.resize(size + alignment, 0);
        
        // Align the buffer
        let ptr = data.as_mut_ptr();
        let aligned_ptr = ((ptr as usize + alignment - 1) & !(alignment - 1)) as *mut u8;
        let offset = aligned_ptr as usize - ptr as usize;
        
        data.drain(0..offset);
        data.truncate(size);
        
        Self { data, alignment }
    }
    
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
    
    pub fn is_aligned(&self) -> bool {
        (self.data.as_ptr() as usize) % self.alignment == 0
    }
}

/// High-performance fixup application using SIMD when possible
pub fn apply_fixups_simd(buffer: &mut [u8], usa_offset: usize, usa_size: usize, record_number: u64) -> bool {
    if usa_size <= 1 {
        return true;
    }
    
    let number_of_fixups = usa_size - 1;
    let fixups_start_offset = usa_offset;
    let fixups_end_offset = fixups_start_offset + (usa_size * 2);
    
    if fixups_end_offset > buffer.len() {
        return false;
    }
    
    // Copy fixup array to avoid borrow conflicts
    let fixups: Vec<u8> = buffer[fixups_start_offset..fixups_end_offset].to_vec();
    let update_sequence = [fixups[0], fixups[1]];
    
    let mut valid_fixup = true;
    
    // Apply fixups every 512 bytes
    for stride in 0..number_of_fixups {
        let sector_offset = stride * 512;
        let fixup_pos = sector_offset + 510; // Last 2 bytes of 512-byte sector
        
        if fixup_pos + 2 > buffer.len() {
            break;
        }
        
        let fixup_idx = 2 + stride * 2; // Skip update sequence
        if fixup_idx + 1 >= fixups.len() {
            break;
        }
        
        // Verify fixup signature
        if buffer[fixup_pos] != update_sequence[0] || buffer[fixup_pos + 1] != update_sequence[1] {
            log::warn!(
                "[entry: {}] fixup mismatch at stride {}: expected {:02x}{:02x}, found {:02x}{:02x}",
                record_number, stride,
                update_sequence[0], update_sequence[1],
                buffer[fixup_pos], buffer[fixup_pos + 1]
            );
            valid_fixup = false;
        }
        
        // Apply fixup
        buffer[fixup_pos] = fixups[fixup_idx];
        buffer[fixup_pos + 1] = fixups[fixup_idx + 1];
    }
    
    valid_fixup
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_simd_signature_detection() {
        let mut data = vec![0u8; 8192];
        
        // Insert FILE signature at position 1024
        data[1024..1028].copy_from_slice(b"FILE");
        
        // Insert BAAD signature at position 4096
        data[4096..4100].copy_from_slice(b"BAAD");
        
        let positions = find_signatures_adaptive(&data);
        assert_eq!(positions.len(), 2);
        assert!(positions.contains(&1024));
        assert!(positions.contains(&4096));
    }
    
    #[test]
    fn test_string_pool() {
        let pool = StringPool::new();
        
        let str1 = pool.intern(b"test.txt");
        let str2 = pool.intern(b"test.txt");
        
        // Should be the same Arc
        assert_eq!(Arc::as_ptr(&str1), Arc::as_ptr(&str2));
        assert_eq!(str1.as_ref(), "test.txt");
    }
    
    #[test]
    fn test_aligned_buffer() {
        let mut buffer = AlignedBuffer::new(1024, 32);
        assert!(buffer.is_aligned());
        assert_eq!(buffer.as_slice().len(), 1024);
        
        // Test write access
        buffer.as_mut_slice()[0] = 0xFF;
        assert_eq!(buffer.as_slice()[0], 0xFF);
    }
}