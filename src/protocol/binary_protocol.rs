use crate::{Error, Result};
use crate::protocol::{MessageType, Packet};
use crate::protocol::packet::PacketFlags;
use crate::protocol::compression::CompressionUtil;
use crate::protocol::padding::MessagePadding;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::{DateTime, Utc};
use std::io::{Cursor, Read, Write};

pub struct BinaryProtocol;

impl BinaryProtocol {
    pub fn encode(packet: &Packet) -> Result<Vec<u8>> {
        // Try to compress payload if beneficial
        let mut payload = packet.payload.clone();
        let mut original_payload_size: Option<u16> = None;
        let mut is_compressed = false;
        
        if CompressionUtil::should_compress(&packet.payload) {
            if let Some(compressed_payload) = CompressionUtil::compress(&packet.payload)? {
                original_payload_size = Some(packet.payload.len() as u16);
                payload = compressed_payload;
                is_compressed = true;
            }
        }
        
        // Update flags
        let mut flags = packet.flags;
        flags.is_compressed = is_compressed;
        
        let mut buffer = Vec::new();
        
        // Header (13 bytes)
        buffer.write_u8(packet.version)?;
        buffer.write_u8(packet.message_type.as_u8())?;
        buffer.write_u8(packet.ttl)?;
        buffer.write_u64::<BigEndian>(packet.timestamp.timestamp_millis() as u64)?;
        buffer.write_u8(flags.to_byte())?;
        
        // Payload length (2 bytes, big-endian) - includes original size if compressed
        let payload_data_size = payload.len() + if is_compressed { 2 } else { 0 };
        if payload_data_size > Packet::MAX_PAYLOAD_SIZE {
            return Err(Error::MessageTooLarge {
                size: payload_data_size,
                max: Packet::MAX_PAYLOAD_SIZE,
            });
        }
        buffer.write_u16::<BigEndian>(payload_data_size as u16)?;
        
        // Sender ID (8 bytes)
        buffer.write_all(&packet.sender_id)?;
        
        // Recipient ID (8 bytes if present)
        if let Some(recipient_id) = &packet.recipient_id {
            buffer.write_all(recipient_id)?;
        }
        
        // Payload (with original size prepended if compressed)
        if is_compressed {
            if let Some(original_size) = original_payload_size {
                buffer.write_u16::<BigEndian>(original_size)?;
            }
        }
        buffer.write_all(&payload)?;
        
        // Signature (64 bytes if present)
        if let Some(signature) = &packet.signature {
            buffer.write_all(signature)?;
        }
        
        // Apply padding to standard block sizes for traffic analysis resistance
        let optimal_size = MessagePadding::optimal_block_size(buffer.len());
        let padded_data = MessagePadding::pad(&buffer, optimal_size);
        
        Ok(padded_data)
    }
    
    pub fn decode(data: &[u8]) -> Result<Packet> {
        // Remove padding first
        let unpadded_data = MessagePadding::unpad(data);
        
        if unpadded_data.len() < Packet::HEADER_SIZE + 8 {
            return Err(Error::Protocol("Packet too small for header".to_string()));
        }
        
        let mut cursor = Cursor::new(&unpadded_data);
        
        // Read header
        let version = cursor.read_u8()?;
        if version != 1 {
            return Err(Error::Protocol(format!("Unsupported version: {}", version)));
        }
        
        let message_type = MessageType::from_u8(cursor.read_u8()?)?;
        let ttl = cursor.read_u8()?;
        let timestamp_millis = cursor.read_u64::<BigEndian>()?;
        let flags = PacketFlags::from_byte(cursor.read_u8()?);
        let payload_len = cursor.read_u16::<BigEndian>()? as usize;
        
        // Calculate expected packet size
        let mut expected_size = Packet::HEADER_SIZE + 8 + payload_len; // header + sender_id + payload
        if flags.has_recipient {
            expected_size += 8;
        }
        if flags.has_signature {
            expected_size += 64;
        }
        
        if unpadded_data.len() < expected_size {
            return Err(Error::Protocol(format!(
                "Packet size mismatch: expected at least {}, got {}",
                expected_size,
                unpadded_data.len()
            )));
        }
        
        // Read sender ID
        let mut sender_id = [0u8; 8];
        cursor.read_exact(&mut sender_id)?;
        
        // Read recipient ID if present
        let recipient_id = if flags.has_recipient {
            let mut id = [0u8; 8];
            cursor.read_exact(&mut id)?;
            Some(id)
        } else {
            None
        };
        
        // Read payload
        let payload = if flags.is_compressed {
            if payload_len < 2 {
                return Err(Error::Protocol("Compressed payload too small".to_string()));
            }
            
            let original_size = cursor.read_u16::<BigEndian>()? as usize;
            
            // Compressed payload
            let mut compressed_payload = vec![0u8; payload_len - 2];
            cursor.read_exact(&mut compressed_payload)?;
            
            // Decompress
            CompressionUtil::decompress(&compressed_payload, original_size)?
        } else {
            let mut payload_bytes = vec![0u8; payload_len];
            cursor.read_exact(&mut payload_bytes)?;
            payload_bytes
        };
        
        // Read signature if present
        let signature = if flags.has_signature {
            let mut sig = [0u8; 64];
            cursor.read_exact(&mut sig)?;
            Some(sig)
        } else {
            None
        };
        
        // Convert timestamp
        let timestamp = DateTime::<Utc>::from_timestamp_millis(timestamp_millis as i64)
            .unwrap_or_else(Utc::now);
        
        Ok(Packet {
            version,
            message_type,
            ttl,
            timestamp,
            flags,
            sender_id,
            recipient_id,
            payload,
            signature,
        })
    }
    
    pub fn get_packet_size(data: &[u8]) -> Result<usize> {
        if data.len() < Packet::HEADER_SIZE {
            return Err(Error::Protocol("Insufficient data for header".to_string()));
        }
        
        let flags = PacketFlags::from_byte(data[11]);
        let payload_len = u16::from_be_bytes([data[11], data[12]]) as usize;
        
        let mut size = Packet::HEADER_SIZE + 8 + payload_len; // header + sender_id + payload
        if flags.has_recipient {
            size += 8;
        }
        if flags.has_signature {
            size += 64;
        }
        
        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encode_decode() {
        let packet = Packet::new(
            MessageType::Message,
            [1, 2, 3, 4, 5, 6, 7, 8],
            b"Hello, world!".to_vec(),
        );
        
        let encoded = BinaryProtocol::encode(&packet).unwrap();
        let decoded = BinaryProtocol::decode(&encoded).unwrap();
        
        assert_eq!(decoded.version, packet.version);
        assert_eq!(decoded.message_type, packet.message_type);
        assert_eq!(decoded.sender_id, packet.sender_id);
        assert_eq!(decoded.payload, packet.payload);
    }
}