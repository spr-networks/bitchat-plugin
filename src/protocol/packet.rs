use crate::protocol::MessageType;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct Packet {
    pub version: u8,
    pub message_type: MessageType,
    pub ttl: u8,
    pub timestamp: DateTime<Utc>,
    pub flags: PacketFlags,
    pub sender_id: [u8; 8],
    pub recipient_id: Option<[u8; 8]>,
    pub payload: Vec<u8>,
    pub signature: Option<[u8; 64]>,
}

#[derive(Debug, Clone, Copy)]
pub struct PacketFlags {
    pub has_recipient: bool,
    pub has_signature: bool,
    pub is_compressed: bool,
}

impl PacketFlags {
    pub fn new() -> Self {
        Self {
            has_recipient: false,
            has_signature: false,
            is_compressed: false,
        }
    }
    
    pub fn from_byte(byte: u8) -> Self {
        Self {
            has_recipient: (byte & 0x01) != 0,
            has_signature: (byte & 0x02) != 0,
            is_compressed: (byte & 0x04) != 0,
        }
    }
    
    pub fn to_byte(&self) -> u8 {
        let mut byte = 0u8;
        if self.has_recipient { byte |= 0x01; }
        if self.has_signature { byte |= 0x02; }
        if self.is_compressed { byte |= 0x04; }
        byte
    }
}

impl Packet {
    pub const HEADER_SIZE: usize = 13;
    pub const MAX_PAYLOAD_SIZE: usize = 65535;
    
    pub fn new(
        message_type: MessageType,
        sender_id: [u8; 8],
        payload: Vec<u8>,
    ) -> Self {
        Self {
            version: 1,
            message_type,
            ttl: 3,
            timestamp: Utc::now(),
            flags: PacketFlags::new(),
            sender_id,
            recipient_id: None,
            payload,
            signature: None,
        }
    }
    
    pub fn with_recipient(mut self, recipient_id: [u8; 8]) -> Self {
        self.recipient_id = Some(recipient_id);
        self.flags.has_recipient = true;
        self
    }
    
    pub fn with_signature(mut self, signature: [u8; 64]) -> Self {
        self.signature = Some(signature);
        self.flags.has_signature = true;
        self
    }
    
    pub fn sender_id_hex(&self) -> String {
        hex::encode(&self.sender_id)
    }
    
    pub fn recipient_id_hex(&self) -> Option<String> {
        self.recipient_id.as_ref().map(hex::encode)
    }
}