use crate::{Error, Result};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Handshake request structure matching iOS/Android protocol
#[derive(Debug, Clone)]
pub struct HandshakeRequest {
    pub request_id: String,
    pub requester_id: String,           // Who needs the handshake
    pub requester_nickname: String,     // Nickname of requester
    pub target_id: String,              // Who should initiate handshake
    pub pending_message_count: u8,      // Number of messages queued
    pub timestamp: DateTime<Utc>,
}

impl HandshakeRequest {
    pub fn new(
        requester_id: String,
        requester_nickname: String,
        target_id: String,
        pending_message_count: u8,
    ) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            requester_id,
            requester_nickname,
            target_id,
            pending_message_count,
            timestamp: Utc::now(),
        }
    }
    
    /// Encode to binary format matching iOS implementation
    pub fn to_binary(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Request ID as UUID (16 bytes)
        if let Ok(uuid) = Uuid::parse_str(&self.request_id) {
            data.extend_from_slice(uuid.as_bytes());
        } else {
            // Fallback to zeros if UUID parsing fails
            data.extend_from_slice(&[0u8; 16]);
        }
        
        // Requester ID as 8-byte hex string
        if let Ok(requester_bytes) = hex::decode(&self.requester_id) {
            if requester_bytes.len() >= 8 {
                data.extend_from_slice(&requester_bytes[..8]);
            } else {
                data.extend_from_slice(&requester_bytes);
                // Pad with zeros to 8 bytes
                data.extend(vec![0u8; 8 - requester_bytes.len()]);
            }
        } else {
            data.extend_from_slice(&[0u8; 8]);
        }
        
        // Target ID as 8-byte hex string
        if let Ok(target_bytes) = hex::decode(&self.target_id) {
            if target_bytes.len() >= 8 {
                data.extend_from_slice(&target_bytes[..8]);
            } else {
                data.extend_from_slice(&target_bytes);
                // Pad with zeros to 8 bytes
                data.extend(vec![0u8; 8 - target_bytes.len()]);
            }
        } else {
            data.extend_from_slice(&[0u8; 8]);
        }
        
        // Pending message count (1 byte)
        data.push(self.pending_message_count);
        
        // Timestamp as milliseconds since epoch (8 bytes, big-endian)
        let timestamp_millis = self.timestamp.timestamp_millis() as u64;
        data.extend_from_slice(&timestamp_millis.to_be_bytes());
        
        // Nickname length (2 bytes, little-endian to match iOS)
        let nickname_bytes = self.requester_nickname.as_bytes();
        let nickname_len = nickname_bytes.len() as u16;
        data.extend_from_slice(&nickname_len.to_le_bytes());
        
        // Nickname data
        data.extend_from_slice(nickname_bytes);
        
        data
    }
    
    /// Decode from binary format
    pub fn from_binary(data: &[u8]) -> Result<Self> {
        // Minimum size: UUID (16) + requesterID (8) + targetID (8) + count (1) + timestamp (8) + nickname length (2) = 43
        if data.len() < 43 {
            return Err(Error::Protocol("Handshake request data too short".to_string()));
        }
        
        let mut offset = 0;
        
        // Request ID (16 bytes)
        let request_id_bytes = &data[offset..offset + 16];
        let request_id = Uuid::from_slice(request_id_bytes)
            .map(|u| u.to_string())
            .unwrap_or_else(|_| Uuid::nil().to_string());
        offset += 16;
        
        // Requester ID (8 bytes)
        let requester_id = hex::encode(&data[offset..offset + 8]);
        offset += 8;
        
        // Target ID (8 bytes)
        let target_id = hex::encode(&data[offset..offset + 8]);
        offset += 8;
        
        // Pending message count (1 byte)
        let pending_message_count = data[offset];
        offset += 1;
        
        // Timestamp (8 bytes, big-endian)
        let timestamp_bytes: [u8; 8] = data[offset..offset + 8].try_into()
            .map_err(|_| Error::Protocol("Invalid timestamp bytes".to_string()))?;
        let timestamp_millis = u64::from_be_bytes(timestamp_bytes) as i64;
        let timestamp = DateTime::<Utc>::from_timestamp_millis(timestamp_millis)
            .ok_or_else(|| Error::Protocol("Invalid timestamp".to_string()))?;
        offset += 8;
        
        // Nickname length (2 bytes, little-endian)
        if data.len() < offset + 2 {
            return Err(Error::Protocol("Missing nickname length".to_string()));
        }
        let nickname_len_bytes: [u8; 2] = data[offset..offset + 2].try_into()
            .map_err(|_| Error::Protocol("Invalid nickname length bytes".to_string()))?;
        let nickname_len = u16::from_le_bytes(nickname_len_bytes) as usize;
        offset += 2;
        
        // Nickname data
        if data.len() < offset + nickname_len {
            return Err(Error::Protocol("Nickname data too short".to_string()));
        }
        let requester_nickname = String::from_utf8_lossy(&data[offset..offset + nickname_len]).to_string();
        
        Ok(Self {
            request_id,
            requester_id,
            requester_nickname,
            target_id,
            pending_message_count,
            timestamp,
        })
    }
}