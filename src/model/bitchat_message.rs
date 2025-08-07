use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write, Cursor};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crate::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitchatMessage {
    pub id: String,
    pub sender: String,
    pub content: String,
    pub timestamp: DateTime<Utc>,
    pub is_relay: bool,
    pub original_sender: Option<String>,
    pub is_private: bool,
    pub recipient_nickname: Option<String>,
    pub sender_peer_id: Option<String>,
    pub mentions: Option<Vec<String>>,
    pub channel: Option<String>,
    pub encrypted_content: Option<Vec<u8>>,
    pub is_encrypted: bool,
}

impl BitchatMessage {
    pub fn new(
        sender: String,
        content: String,
        timestamp: DateTime<Utc>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            sender,
            content,
            timestamp,
            is_relay: false,
            original_sender: None,
            is_private: false,
            recipient_nickname: None,
            sender_peer_id: None,
            mentions: None,
            channel: None,
            encrypted_content: None,
            is_encrypted: false,
        }
    }
    
    pub fn private_message(
        sender: String,
        content: String,
        timestamp: DateTime<Utc>,
        recipient_nickname: String,
    ) -> Self {
        let mut msg = Self::new(sender, content, timestamp);
        msg.is_private = true;
        msg.recipient_nickname = Some(recipient_nickname);
        msg
    }
    
    pub fn channel_message(
        sender: String,
        content: String,
        timestamp: DateTime<Utc>,
        channel: String,
    ) -> Self {
        let mut msg = Self::new(sender, content, timestamp);
        msg.channel = Some(channel);
        msg
    }

    /// Convert message to binary payload format - matching Android/iOS
    pub fn to_binary_payload(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(4096);
        
        // Flags byte
        let mut flags: u8 = 0;
        if self.is_relay { flags |= 0x01; }
        if self.is_private { flags |= 0x02; }
        if self.original_sender.is_some() { flags |= 0x04; }
        if self.recipient_nickname.is_some() { flags |= 0x08; }
        if self.sender_peer_id.is_some() { flags |= 0x10; }
        if self.mentions.is_some() && !self.mentions.as_ref().unwrap().is_empty() { flags |= 0x20; }
        if self.channel.is_some() { flags |= 0x40; }
        if self.is_encrypted { flags |= 0x80; }
        
        buffer.write_u8(flags)?;
        
        // Timestamp (8 bytes, milliseconds since epoch)
        let timestamp_millis = self.timestamp.timestamp_millis();
        buffer.write_i64::<BigEndian>(timestamp_millis)?;
        
        // ID
        let id_bytes = self.id.as_bytes();
        let id_len = id_bytes.len().min(255) as u8;
        buffer.write_u8(id_len)?;
        buffer.write_all(&id_bytes[..id_len as usize])?;
        
        // Sender
        let sender_bytes = self.sender.as_bytes();
        let sender_len = sender_bytes.len().min(255) as u8;
        buffer.write_u8(sender_len)?;
        buffer.write_all(&sender_bytes[..sender_len as usize])?;
        
        // Content or encrypted content
        if self.is_encrypted {
            if let Some(ref encrypted) = self.encrypted_content {
                let content_len = encrypted.len().min(65535) as u16;
                buffer.write_u16::<BigEndian>(content_len)?;
                buffer.write_all(&encrypted[..content_len as usize])?;
            } else {
                // Empty encrypted content
                buffer.write_u16::<BigEndian>(0)?;
            }
        } else {
            let content_bytes = self.content.as_bytes();
            let content_len = content_bytes.len().min(65535) as u16;
            buffer.write_u16::<BigEndian>(content_len)?;
            buffer.write_all(&content_bytes[..content_len as usize])?;
        }
        
        // Optional fields
        if let Some(ref original_sender) = self.original_sender {
            let bytes = original_sender.as_bytes();
            let len = bytes.len().min(255) as u8;
            buffer.write_u8(len)?;
            buffer.write_all(&bytes[..len as usize])?;
        }
        
        if let Some(ref recipient) = self.recipient_nickname {
            let bytes = recipient.as_bytes();
            let len = bytes.len().min(255) as u8;
            buffer.write_u8(len)?;
            buffer.write_all(&bytes[..len as usize])?;
        }
        
        if let Some(ref peer_id) = self.sender_peer_id {
            let bytes = peer_id.as_bytes();
            let len = bytes.len().min(255) as u8;
            buffer.write_u8(len)?;
            buffer.write_all(&bytes[..len as usize])?;
        }
        
        if let Some(ref mentions) = self.mentions {
            let count = mentions.len().min(255) as u8;
            buffer.write_u8(count)?;
            for mention in mentions.iter().take(count as usize) {
                let bytes = mention.as_bytes();
                let len = bytes.len().min(255) as u8;
                buffer.write_u8(len)?;
                buffer.write_all(&bytes[..len as usize])?;
            }
        }
        
        if let Some(ref channel) = self.channel {
            let bytes = channel.as_bytes();
            let len = bytes.len().min(255) as u8;
            buffer.write_u8(len)?;
            buffer.write_all(&bytes[..len as usize])?;
        }
        
        Ok(buffer)
    }
    
    /// Parse message from binary payload - matching Android/iOS
    pub fn from_binary_payload(data: &[u8]) -> Result<Self> {
        if data.len() < 13 {
            return Err(Error::Protocol("Message too small".to_string()));
        }
        
        let mut cursor = Cursor::new(data);
        
        // Flags
        let flags = cursor.read_u8()?;
        let is_relay = (flags & 0x01) != 0;
        let is_private = (flags & 0x02) != 0;
        let has_original_sender = (flags & 0x04) != 0;
        let has_recipient_nickname = (flags & 0x08) != 0;
        let has_sender_peer_id = (flags & 0x10) != 0;
        let has_mentions = (flags & 0x20) != 0;
        let has_channel = (flags & 0x40) != 0;
        let is_encrypted = (flags & 0x80) != 0;
        
        // Timestamp
        let timestamp_millis = cursor.read_i64::<BigEndian>()?;
        let timestamp = DateTime::from_timestamp_millis(timestamp_millis)
            .ok_or_else(|| Error::Protocol("Invalid timestamp".to_string()))?;
        
        // ID
        let id_len = cursor.read_u8()? as usize;
        let mut id_bytes = vec![0u8; id_len];
        cursor.read_exact(&mut id_bytes)?;
        let id = String::from_utf8(id_bytes)
            .map_err(|_| Error::Protocol("Invalid ID encoding".to_string()))?;
        
        // Sender
        let sender_len = cursor.read_u8()? as usize;
        let mut sender_bytes = vec![0u8; sender_len];
        cursor.read_exact(&mut sender_bytes)?;
        let sender = String::from_utf8(sender_bytes)
            .map_err(|_| Error::Protocol("Invalid sender encoding".to_string()))?;
        
        // Content
        let content_len = cursor.read_u16::<BigEndian>()? as usize;
        let mut content_bytes = vec![0u8; content_len];
        cursor.read_exact(&mut content_bytes)?;
        
        let (content, encrypted_content) = if is_encrypted {
            ("".to_string(), Some(content_bytes))
        } else {
            let content = String::from_utf8(content_bytes)
                .map_err(|_| Error::Protocol("Invalid content encoding".to_string()))?;
            (content, None)
        };
        
        // Optional fields
        let original_sender = if has_original_sender {
            let len = cursor.read_u8()? as usize;
            let mut bytes = vec![0u8; len];
            cursor.read_exact(&mut bytes)?;
            Some(String::from_utf8(bytes)
                .map_err(|_| Error::Protocol("Invalid original sender encoding".to_string()))?)
        } else {
            None
        };
        
        let recipient_nickname = if has_recipient_nickname {
            let len = cursor.read_u8()? as usize;
            let mut bytes = vec![0u8; len];
            cursor.read_exact(&mut bytes)?;
            Some(String::from_utf8(bytes)
                .map_err(|_| Error::Protocol("Invalid recipient encoding".to_string()))?)
        } else {
            None
        };
        
        let sender_peer_id = if has_sender_peer_id {
            let len = cursor.read_u8()? as usize;
            let mut bytes = vec![0u8; len];
            cursor.read_exact(&mut bytes)?;
            Some(String::from_utf8(bytes)
                .map_err(|_| Error::Protocol("Invalid peer ID encoding".to_string()))?)
        } else {
            None
        };
        
        let mentions = if has_mentions {
            let count = cursor.read_u8()? as usize;
            let mut mentions_vec = Vec::with_capacity(count);
            for _ in 0..count {
                let len = cursor.read_u8()? as usize;
                let mut bytes = vec![0u8; len];
                cursor.read_exact(&mut bytes)?;
                let mention = String::from_utf8(bytes)
                    .map_err(|_| Error::Protocol("Invalid mention encoding".to_string()))?;
                mentions_vec.push(mention);
            }
            Some(mentions_vec)
        } else {
            None
        };
        
        let channel = if has_channel {
            let len = cursor.read_u8()? as usize;
            let mut bytes = vec![0u8; len];
            cursor.read_exact(&mut bytes)?;
            Some(String::from_utf8(bytes)
                .map_err(|_| Error::Protocol("Invalid channel encoding".to_string()))?)
        } else {
            None
        };
        
        Ok(BitchatMessage {
            id,
            sender,
            content,
            timestamp,
            is_relay,
            original_sender,
            is_private,
            recipient_nickname,
            sender_peer_id,
            mentions,
            channel,
            encrypted_content,
            is_encrypted,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_message_binary_roundtrip() {
        let msg = BitchatMessage::new(
            "Alice".to_string(),
            "Hello, World!".to_string(),
            Utc::now(),
        );
        
        let binary = msg.to_binary_payload().unwrap();
        let decoded = BitchatMessage::from_binary_payload(&binary).unwrap();
        
        assert_eq!(msg.id, decoded.id);
        assert_eq!(msg.sender, decoded.sender);
        assert_eq!(msg.content, decoded.content);
        assert_eq!(msg.timestamp.timestamp_millis(), decoded.timestamp.timestamp_millis());
    }
    
    #[test]
    fn test_private_message_binary() {
        let mut msg = BitchatMessage::new(
            "Bob".to_string(),
            "Secret message".to_string(),
            Utc::now(),
        );
        msg.is_private = true;
        msg.recipient_nickname = Some("Alice".to_string());
        
        let binary = msg.to_binary_payload().unwrap();
        let decoded = BitchatMessage::from_binary_payload(&binary).unwrap();
        
        assert!(decoded.is_private);
        assert_eq!(decoded.recipient_nickname, Some("Alice".to_string()));
    }
    
    #[test]
    fn test_channel_message_with_mentions() {
        let mut msg = BitchatMessage::new(
            "Charlie".to_string(),
            "Hey @Alice and @Bob!".to_string(),
            Utc::now(),
        );
        msg.channel = Some("#general".to_string());
        msg.mentions = Some(vec!["Alice".to_string(), "Bob".to_string()]);
        
        let binary = msg.to_binary_payload().unwrap();
        let decoded = BitchatMessage::from_binary_payload(&binary).unwrap();
        
        assert_eq!(decoded.channel, Some("#general".to_string()));
        assert_eq!(decoded.mentions, Some(vec!["Alice".to_string(), "Bob".to_string()]));
    }
    
    #[test]
    fn test_encrypted_message() {
        let mut msg = BitchatMessage::new(
            "Dave".to_string(),
            "".to_string(), // Empty content for encrypted
            Utc::now(),
        );
        msg.is_encrypted = true;
        msg.encrypted_content = Some(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        
        let binary = msg.to_binary_payload().unwrap();
        let decoded = BitchatMessage::from_binary_payload(&binary).unwrap();
        
        assert!(decoded.is_encrypted);
        assert_eq!(decoded.encrypted_content, Some(vec![1, 2, 3, 4, 5, 6, 7, 8]));
    }
}