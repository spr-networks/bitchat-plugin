use rand::{thread_rng, RngCore};

pub struct MessagePadding;

impl MessagePadding {
    // Standard block sizes for padding - exact same as Android/iOS
    const BLOCK_SIZES: [usize; 4] = [256, 512, 1024, 2048];
    
    pub fn optimal_block_size(data_size: usize) -> usize {
        // Find smallest block that fits the data
        for &block_size in &Self::BLOCK_SIZES {
            if data_size <= block_size {
                return block_size;
            }
        }
        
        // For very large messages, just return the original size (no padding)
        data_size
    }
    
    pub fn pad(data: &[u8], target_size: usize) -> Vec<u8> {
        if data.len() >= target_size {
            return data.to_vec();
        }
        
        let padding_needed = target_size - data.len();
        
        // PKCS#7 only supports padding up to 255 bytes
        // If we need more padding than that, don't pad - return original data
        if padding_needed > 255 {
            return data.to_vec();
        }
        
        let mut result = Vec::with_capacity(target_size);
        
        // Copy original data
        result.extend_from_slice(data);
        
        // Add random padding bytes (all but the last byte)
        if padding_needed > 1 {
            let mut random_bytes = vec![0u8; padding_needed - 1];
            thread_rng().fill_bytes(&mut random_bytes);
            result.extend_from_slice(&random_bytes);
        }
        
        // Last byte tells how much padding was added
        result.push(padding_needed as u8);
        
        result
    }
    
    pub fn unpad(data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return data.to_vec();
        }
        
        // Last byte tells us how much padding to remove
        let padding_length = *data.last().unwrap() as usize;
        
        if padding_length == 0 || padding_length > data.len() {
            // Invalid padding, return original data
            return data.to_vec();
        }
        
        data[..data.len() - padding_length].to_vec()
    }
}