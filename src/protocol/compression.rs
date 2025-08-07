use crate::Result;
use flate2::write::{DeflateEncoder, DeflateDecoder};
use flate2::Compression;
use std::io::Write;

pub struct CompressionUtil;

impl CompressionUtil {
    const COMPRESSION_THRESHOLD: usize = 100;
    
    pub fn should_compress(_data: &[u8]) -> bool {
        // TODO: Compression doesn't work with iOS yet (as noted in Android)
        false
    }
    
    pub fn compress(data: &[u8]) -> Result<Option<Vec<u8>>> {
        // Skip compression for small data
        if data.len() < Self::COMPRESSION_THRESHOLD {
            return Ok(None);
        }
        
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(data)?;
        let compressed = encoder.finish()?;
        
        // Only return if compression was beneficial
        if !compressed.is_empty() && compressed.len() < data.len() {
            Ok(Some(compressed))
        } else {
            Ok(None)
        }
    }
    
    pub fn decompress(compressed_data: &[u8], original_size: usize) -> Result<Vec<u8>> {
        let mut decoder = DeflateDecoder::new(Vec::with_capacity(original_size));
        decoder.write_all(compressed_data)?;
        let decompressed = decoder.finish()?;
        
        Ok(decompressed)
    }
}