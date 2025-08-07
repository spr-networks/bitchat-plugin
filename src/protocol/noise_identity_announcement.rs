use chrono::{DateTime, Utc};
use crate::Result;

/// Noise Identity Announcement - Compatible with iOS/Android
/// This announces our cryptographic identity to peers
#[derive(Debug, Clone)]
pub struct NoiseIdentityAnnouncement {
    pub peer_id: String,               // Current ephemeral peer ID
    pub public_key: Vec<u8>,          // Noise static public key (X25519 - 32 bytes)
    pub signing_public_key: Vec<u8>,  // Ed25519 signing public key (32 bytes)
    pub nickname: String,             // Current nickname
    pub timestamp: DateTime<Utc>,     // When this binding was created
    pub previous_peer_id: Option<String>, // Previous peer ID (for smooth transition)
    pub signature: Vec<u8>,           // Ed25519 signature proving ownership
}

impl NoiseIdentityAnnouncement {
    pub fn new(
        peer_id: String,
        public_key: Vec<u8>,
        signing_public_key: Vec<u8>,
        nickname: String,
        previous_peer_id: Option<String>,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            peer_id,
            public_key,
            signing_public_key,
            nickname,
            timestamp: Utc::now(),
            previous_peer_id,
            signature,
        }
    }
    
    pub fn new_with_timestamp(
        peer_id: String,
        public_key: Vec<u8>,
        signing_public_key: Vec<u8>,
        nickname: String,
        timestamp: DateTime<Utc>,
        previous_peer_id: Option<String>,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            peer_id,
            public_key,
            signing_public_key,
            nickname,
            timestamp,
            previous_peer_id,
            signature,
        }
    }
    
    /// Convert hex string peer ID to 8-byte array
    fn hex_to_bytes(hex: &str) -> Result<[u8; 8]> {
        let bytes = hex::decode(hex)
            .map_err(|e| crate::Error::Protocol(format!("Invalid hex: {}", e)))?;
        if bytes.len() != 8 {
            return Err(crate::Error::Protocol("Peer ID must be 8 bytes".to_string()));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
    
    /// Encode to binary format matching iOS/Android
    pub fn to_binary(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Flags byte: bit 0 = hasPreviousPeerID
        let flags: u8 = if self.previous_peer_id.is_some() { 0x01 } else { 0x00 };
        data.push(flags);
        
        // PeerID as 8 bytes (no length prefix for fixed field)
        if let Ok(peer_bytes) = Self::hex_to_bytes(&self.peer_id) {
            data.extend_from_slice(&peer_bytes);
        } else {
            // Fallback - should not happen with valid peer ID
            data.extend_from_slice(&[0u8; 8]);
        }
        
        // Public key with length prefix
        data.extend_from_slice(&(self.public_key.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.public_key);
        
        // Signing public key with length prefix
        data.extend_from_slice(&(self.signing_public_key.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.signing_public_key);
        
        // Nickname with length prefix (1 byte for iOS compatibility)
        let nickname_bytes = self.nickname.as_bytes();
        data.push(nickname_bytes.len() as u8);
        data.extend_from_slice(nickname_bytes);
        
        // Timestamp as milliseconds (8 bytes)
        data.extend_from_slice(&(self.timestamp.timestamp_millis() as u64).to_be_bytes());
        
        // Previous peer ID if present (8 bytes, no length prefix)
        if let Some(prev_id) = &self.previous_peer_id {
            if let Ok(prev_bytes) = Self::hex_to_bytes(prev_id) {
                data.extend_from_slice(&prev_bytes);
            }
        }
        
        // Signature with length prefix
        data.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.signature);
        
        data
    }
    
    /// Parse from binary data
    pub fn from_binary(data: &[u8]) -> Result<Self> {
        if data.len() < 10 {
            return Err(crate::Error::Protocol("Data too small for NoiseIdentityAnnouncement".to_string()));
        }
        
        let mut offset = 0;
        
        // Flags byte
        let flags = data[offset];
        offset += 1;
        let has_previous_peer_id = (flags & 0x01) != 0;
        
        // PeerID (8 bytes)
        if offset + 8 > data.len() {
            return Err(crate::Error::Protocol("Invalid peer ID length".to_string()));
        }
        let peer_id_bytes = &data[offset..offset + 8];
        let peer_id = hex::encode(peer_id_bytes);
        offset += 8;
        
        // Public key
        if offset + 2 > data.len() {
            return Err(crate::Error::Protocol("Invalid public key length field".to_string()));
        }
        let pk_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + pk_len > data.len() {
            return Err(crate::Error::Protocol("Invalid public key data".to_string()));
        }
        let public_key = data[offset..offset + pk_len].to_vec();
        offset += pk_len;
        
        // Signing public key
        if offset + 2 > data.len() {
            return Err(crate::Error::Protocol("Invalid signing key length field".to_string()));
        }
        let spk_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + spk_len > data.len() {
            return Err(crate::Error::Protocol("Invalid signing key data".to_string()));
        }
        let signing_public_key = data[offset..offset + spk_len].to_vec();
        offset += spk_len;
        
        // Nickname (1 byte length for iOS compatibility)
        if offset + 1 > data.len() {
            return Err(crate::Error::Protocol("Invalid nickname length field".to_string()));
        }
        let nick_len = data[offset] as usize;
        offset += 1;
        if offset + nick_len > data.len() {
            return Err(crate::Error::Protocol("Invalid nickname data".to_string()));
        }
        let nickname = String::from_utf8_lossy(&data[offset..offset + nick_len]).to_string();
        offset += nick_len;
        
        // Timestamp
        if offset + 8 > data.len() {
            return Err(crate::Error::Protocol("Invalid timestamp".to_string()));
        }
        let timestamp_ms = u64::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
        ]) as i64;
        let timestamp = DateTime::<Utc>::from_timestamp_millis(timestamp_ms)
            .ok_or_else(|| crate::Error::Protocol("Invalid timestamp value".to_string()))?;
        offset += 8;
        
        // Previous peer ID if present
        let previous_peer_id = if has_previous_peer_id {
            if offset + 8 > data.len() {
                return Err(crate::Error::Protocol("Invalid previous peer ID".to_string()));
            }
            let prev_id_bytes = &data[offset..offset + 8];
            offset += 8;
            Some(hex::encode(prev_id_bytes))
        } else {
            None
        };
        
        // Signature
        if offset + 2 > data.len() {
            return Err(crate::Error::Protocol("Invalid signature length field".to_string()));
        }
        let sig_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + sig_len > data.len() {
            return Err(crate::Error::Protocol("Invalid signature data".to_string()));
        }
        let signature = data[offset..offset + sig_len].to_vec();
        
        Ok(Self {
            peer_id,
            public_key,
            signing_public_key,
            nickname,
            timestamp,
            previous_peer_id,
            signature,
        })
    }
}