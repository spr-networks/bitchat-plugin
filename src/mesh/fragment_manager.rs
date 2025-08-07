use crate::{Error, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};

const MAX_FRAGMENT_SIZE: usize = 512; // BLE MTU safe size
const FRAGMENT_TIMEOUT_SECS: i64 = 30;

#[derive(Debug, Clone)]
pub struct FragmentHeader {
    pub message_id: String,
    pub fragment_index: u16,
    pub total_fragments: u16,
}

#[derive(Debug)]
struct FragmentGroup {
    fragments: HashMap<u16, Vec<u8>>,
    total_fragments: u16,
    original_type: u8,
    timestamp: DateTime<Utc>,
}

pub struct FragmentManager {
    fragment_groups: Arc<RwLock<HashMap<String, FragmentGroup>>>,
}

impl FragmentManager {
    pub fn new() -> Self {
        Self {
            fragment_groups: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    
    pub async fn add_fragment(
        &self,
        header: FragmentHeader,
        original_type: u8,
        data: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        let mut groups = self.fragment_groups.write().await;
        
        // Clean up old fragments
        self.cleanup_old_fragments(&mut groups).await;
        
        let group = groups.entry(header.message_id.clone()).or_insert_with(|| {
            FragmentGroup {
                fragments: HashMap::new(),
                total_fragments: header.total_fragments,
                original_type,
                timestamp: Utc::now(),
            }
        });
        
        // Validate fragment
        if header.total_fragments != group.total_fragments {
            return Err(Error::Protocol("Fragment count mismatch".to_string()));
        }
        
        if header.fragment_index >= header.total_fragments {
            return Err(Error::Protocol("Invalid fragment index".to_string()));
        }
        
        // Add fragment
        group.fragments.insert(header.fragment_index, data);
        
        // Check if complete
        if group.fragments.len() == group.total_fragments as usize {
            // Reassemble message
            let mut complete_data = Vec::new();
            for i in 0..group.total_fragments {
                if let Some(fragment_data) = group.fragments.get(&i) {
                    complete_data.extend_from_slice(fragment_data);
                } else {
                    return Err(Error::Protocol("Missing fragment".to_string()));
                }
            }
            
            // Remove completed group
            groups.remove(&header.message_id);
            
            Ok(Some(complete_data))
        } else {
            Ok(None)
        }
    }
    
    async fn cleanup_old_fragments(&self, groups: &mut HashMap<String, FragmentGroup>) {
        let cutoff = Utc::now() - Duration::seconds(FRAGMENT_TIMEOUT_SECS);
        groups.retain(|_, group| group.timestamp > cutoff);
    }
    
    pub fn create_fragment_payload(
        fragment_id: &[u8; 8],
        index: u16,
        total: u16,
        original_type: u8,
        data: &[u8],
    ) -> Vec<u8> {
        let mut payload = Vec::with_capacity(13 + data.len());
        
        // Fragment ID (8 bytes)
        payload.extend_from_slice(fragment_id);
        
        // Index (2 bytes, big-endian)
        payload.extend_from_slice(&index.to_be_bytes());
        
        // Total (2 bytes, big-endian)
        payload.extend_from_slice(&total.to_be_bytes());
        
        // Original type (1 byte)
        payload.push(original_type);
        
        // Fragment data
        payload.extend_from_slice(data);
        
        payload
    }
    
    pub fn decode_fragment_payload(data: &[u8]) -> Result<(FragmentHeader, u8, &[u8])> {
        if data.len() < 13 {
            return Err(Error::Protocol("Fragment payload too small".to_string()));
        }
        
        // Fragment ID (8 bytes)
        let fragment_id = &data[0..8];
        let message_id = hex::encode(fragment_id);
        
        // Index (2 bytes)
        let fragment_index = u16::from_be_bytes([data[8], data[9]]);
        
        // Total (2 bytes)
        let total_fragments = u16::from_be_bytes([data[10], data[11]]);
        
        // Original type (1 byte)
        let original_type = data[12];
        
        let header = FragmentHeader {
            message_id,
            fragment_index,
            total_fragments,
        };
        
        Ok((header, original_type, &data[13..]))
    }
}