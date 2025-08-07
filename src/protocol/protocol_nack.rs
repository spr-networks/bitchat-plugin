use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NackErrorCode {
    DecryptionFailed = 0x01,
    InvalidSignature = 0x02,
    SystemValidationFailed = 0x03,
    InvalidPacketFormat = 0x04,
    SessionNotFound = 0x05,
    HandshakeFailed = 0x06,
    UnsupportedVersion = 0x07,
    UnknownError = 0xFF,
}

impl NackErrorCode {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x01 => NackErrorCode::DecryptionFailed,
            0x02 => NackErrorCode::InvalidSignature,
            0x03 => NackErrorCode::SystemValidationFailed,
            0x04 => NackErrorCode::InvalidPacketFormat,
            0x05 => NackErrorCode::SessionNotFound,
            0x06 => NackErrorCode::HandshakeFailed,
            0x07 => NackErrorCode::UnsupportedVersion,
            _ => NackErrorCode::UnknownError,
        }
    }
    
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

pub struct ProtocolNack {
    pub original_packet_id: Vec<u8>,  // Hash of the original packet
    pub sender_id: String,
    pub receiver_id: String,
    pub packet_type: u8,
    pub reason: String,
    pub error_code: NackErrorCode,
}

impl ProtocolNack {
    pub fn new(
        original_packet_id: Vec<u8>,
        sender_id: String,
        receiver_id: String,
        packet_type: u8,
        reason: String,
        error_code: NackErrorCode,
    ) -> Self {
        Self {
            original_packet_id,
            sender_id,
            receiver_id,
            packet_type,
            reason,
            error_code,
        }
    }
    
    pub fn to_binary(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Original packet ID (UUID - pad or truncate to 16 bytes)
        if self.original_packet_id.len() >= 16 {
            data.extend_from_slice(&self.original_packet_id[..16]);
        } else {
            data.extend_from_slice(&self.original_packet_id);
            // Pad with zeros if less than 16 bytes
            data.extend(vec![0u8; 16 - self.original_packet_id.len()]);
        }
        
        // NACK ID (UUID - generate a random one for compatibility)
        let nack_id = uuid::Uuid::new_v4();
        data.extend_from_slice(nack_id.as_bytes());
        
        // Sender ID (8 bytes hex)
        let sender_bytes = hex::decode(&self.sender_id).unwrap_or_else(|_| vec![0u8; 8]);
        if sender_bytes.len() >= 8 {
            data.extend_from_slice(&sender_bytes[..8]);
        } else {
            data.extend_from_slice(&sender_bytes);
            data.extend(vec![0u8; 8 - sender_bytes.len()]);
        }
        
        // Receiver ID (8 bytes hex)
        let receiver_bytes = hex::decode(&self.receiver_id).unwrap_or_else(|_| vec![0u8; 8]);
        if receiver_bytes.len() >= 8 {
            data.extend_from_slice(&receiver_bytes[..8]);
        } else {
            data.extend_from_slice(&receiver_bytes);
            data.extend(vec![0u8; 8 - receiver_bytes.len()]);
        }
        
        // Packet type
        data.push(self.packet_type);
        
        // Error code
        data.push(self.error_code.as_u8());
        
        // Timestamp (8 bytes - use current time)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        data.extend_from_slice(&timestamp.to_be_bytes());
        
        // Reason string (length-prefixed with 1 byte - Mac uses 1-byte for strings by default)
        let reason_bytes = self.reason.as_bytes();
        let reason_len = std::cmp::min(reason_bytes.len(), 255) as u8;
        data.push(reason_len);
        data.extend_from_slice(&reason_bytes[..reason_len as usize]);
        
        data
    }
    
    pub fn from_binary(data: &[u8]) -> Result<Self> {
        // Mac client format: 2 UUIDs (32) + 2 IDs (16) + type (1) + error (1) + timestamp (8) + reason
        if data.len() < 58 {
            return Err(crate::Error::Protocol("NACK data too short".to_string()));
        }
        
        let mut offset = 0;
        
        // Read original packet ID (UUID - 16 bytes)
        if offset + 16 > data.len() {
            return Err(crate::Error::Protocol("Invalid NACK original packet ID".to_string()));
        }
        let original_packet_id = data[offset..offset + 16].to_vec();
        offset += 16;
        
        // Skip nackID (UUID - 16 bytes) - we don't use this field
        if offset + 16 > data.len() {
            return Err(crate::Error::Protocol("Invalid NACK ID".to_string()));
        }
        offset += 16;
        
        // Read sender ID (8 bytes hex)
        if offset + 8 > data.len() {
            return Err(crate::Error::Protocol("Invalid NACK sender ID".to_string()));
        }
        let sender_id = hex::encode(&data[offset..offset + 8]);
        offset += 8;
        
        // Read receiver ID (8 bytes hex)
        if offset + 8 > data.len() {
            return Err(crate::Error::Protocol("Invalid NACK receiver ID".to_string()));
        }
        let receiver_id = hex::encode(&data[offset..offset + 8]);
        offset += 8;
        
        // Read packet type
        let packet_type = data[offset];
        offset += 1;
        
        // Read error code
        let error_code = NackErrorCode::from_u8(data[offset]);
        offset += 1;
        
        // Read timestamp (8 bytes) - skip for now as we don't use it
        if offset + 8 > data.len() {
            return Err(crate::Error::Protocol("Invalid NACK timestamp".to_string()));
        }
        offset += 8;
        
        // Read reason string (length-prefixed with 1 byte - Mac uses 1-byte for strings by default)
        if offset >= data.len() {
            return Err(crate::Error::Protocol("Invalid NACK reason length".to_string()));
        }
        let reason_len = data[offset] as usize;
        offset += 1;
        
        if offset + reason_len > data.len() {
            return Err(crate::Error::Protocol("Invalid NACK reason data".to_string()));
        }
        let reason = String::from_utf8_lossy(&data[offset..offset + reason_len]).to_string();
        
        Ok(Self {
            original_packet_id,
            sender_id,
            receiver_id,
            packet_type,
            reason,
            error_code,
        })
    }
}