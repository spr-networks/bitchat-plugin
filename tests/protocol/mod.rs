use bitchat_rust::protocol::{BinaryProtocol, Packet};
use bitchat_rust::model::BitchatMessage;

mod test_helpers;
use test_helpers::*;

#[test]
fn test_basic_packet_encoding_decoding() {
    let original_packet = create_test_packet();
    
    // Encode
    let encoded_data = BinaryProtocol::encode(&original_packet).expect("Failed to encode packet");
    
    // Decode
    let decoded_packet = BinaryProtocol::decode(&encoded_data).expect("Failed to decode packet");
    
    // Verify
    assert_eq!(decoded_packet.message_type, original_packet.message_type);
    assert_eq!(decoded_packet.ttl, original_packet.ttl);
    assert_eq!(decoded_packet.timestamp.timestamp_millis(), original_packet.timestamp.timestamp_millis());
    assert_eq!(decoded_packet.payload, original_packet.payload);
    assert_eq!(decoded_packet.sender_id, original_packet.sender_id);
}

#[test]
fn test_packet_with_recipient() {
    let recipient_id = [0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34];
    let packet = create_test_packet_with_recipient(recipient_id);
    
    // Encode and decode
    let encoded_data = BinaryProtocol::encode(&packet).expect("Failed to encode packet");
    let decoded_packet = BinaryProtocol::decode(&encoded_data).expect("Failed to decode packet");
    
    // Verify recipient
    assert!(decoded_packet.recipient_id.is_some());
    assert_eq!(decoded_packet.recipient_id.unwrap(), recipient_id);
}

#[test]
fn test_packet_with_signature() {
    let mut signature = [0u8; 64];
    signature.fill(0xAB);
    let packet = create_test_packet_with_signature(signature);
    
    // Encode and decode
    let encoded_data = BinaryProtocol::encode(&packet).expect("Failed to encode packet");
    let decoded_packet = BinaryProtocol::decode(&encoded_data).expect("Failed to decode packet");
    
    // Verify signature
    assert!(decoded_packet.signature.is_some());
    assert_eq!(decoded_packet.signature.unwrap(), signature);
}

#[test]
fn test_payload_compression() {
    // Create a large, compressible payload
    let repeated_string = "This is a test message. ".repeat(50);
    let large_payload = repeated_string.as_bytes().to_vec();
    
    let packet = create_test_packet_with_payload(large_payload.clone());
    
    // Encode (should compress)
    let encoded_data = BinaryProtocol::encode(&packet).expect("Failed to encode packet");
    
    // Since compression is disabled (Android behavior), size should be larger due to padding
    let uncompressed_size = Packet::HEADER_SIZE + 8 + large_payload.len();
    // With padding, encoded size should be padded to a standard block size
    assert!(encoded_data.len() >= uncompressed_size);
    
    // Decode and verify
    let decoded_packet = BinaryProtocol::decode(&encoded_data).expect("Failed to decode compressed packet");
    assert_eq!(decoded_packet.payload, large_payload);
}

#[test]
fn test_small_payload_no_compression() {
    // Small payloads should not be compressed
    let small_payload = b"Hi".to_vec();
    let packet = create_test_packet_with_payload(small_payload.clone());
    
    let encoded_data = BinaryProtocol::encode(&packet).expect("Failed to encode packet");
    let decoded_packet = BinaryProtocol::decode(&encoded_data).expect("Failed to decode packet");
    
    assert_eq!(decoded_packet.payload, small_payload);
}

#[test]
fn test_message_padding() {
    let medium = "Medium length message content ".repeat(5);  // ~150 bytes
    let long = "Long message content that should exceed the 512 byte limit ".repeat(8);  // ~480 bytes
    let very_long = "Very long message content that should exceed the 1024 byte limit for sure ".repeat(15);  // ~1125 bytes
    
    let payloads = vec![
        "Short",
        &medium,
        &long,
        &very_long,
    ];
    
    let mut encoded_sizes = std::collections::HashSet::new();
    
    for payload in payloads {
        let packet = create_test_packet_with_payload(payload.as_bytes().to_vec());
        
        let encoded_data = BinaryProtocol::encode(&packet).expect("Failed to encode packet");
        
        // Check if this payload should be padded or not  
        let unpadded_size = Packet::HEADER_SIZE + 2 + 8 + payload.as_bytes().len(); // header + payload_len + sender_id + payload
        let optimal_size = bitchat_rust::protocol::padding::MessagePadding::optimal_block_size(unpadded_size);
        let padding_needed = optimal_size.saturating_sub(unpadded_size);
        
        println!("Payload '{}...' (len={}): unpadded_size={}, optimal_size={}, padding_needed={}, encoded_len={}", 
            &payload[..payload.len().min(20)], payload.len(), unpadded_size, optimal_size, padding_needed, encoded_data.len());
        
        if padding_needed <= 255 && optimal_size != unpadded_size {
            // Should be padded to standard block size
            let block_sizes = vec![256, 512, 1024, 2048];
            assert!(block_sizes.contains(&encoded_data.len()), 
                "Encoded size {} is not a standard block size for payload size {}", 
                encoded_data.len(), payload.len());
        } else {
            // Very large messages that need >255 bytes padding should NOT be padded
            // They keep their original size
            assert_eq!(encoded_data.len(), unpadded_size,
                "Very large message should not be padded: expected {}, got {}", 
                unpadded_size, encoded_data.len());
        }
        
        encoded_sizes.insert(encoded_data.len());
        
        // Verify decoding works
        let decoded_packet = BinaryProtocol::decode(&encoded_data).expect("Failed to decode padded packet");
        assert_eq!(decoded_packet.payload, payload.as_bytes());
    }
    
    // Different payload sizes should result in at least 2 different encoded sizes
    assert!(encoded_sizes.len() >= 2, 
        "Expected at least 2 different encoded sizes, got {:?}", encoded_sizes);
}

#[test]
fn test_message_encoding_decoding() {
    let message = create_test_message();
    
    let payload = message.to_binary_payload().expect("Failed to encode message to binary");
    let decoded_message = BitchatMessage::from_binary_payload(&payload)
        .expect("Failed to decode message from binary");
    
    assert_eq!(decoded_message.content, message.content);
    assert_eq!(decoded_message.sender, message.sender);
    assert_eq!(decoded_message.sender_peer_id, message.sender_peer_id);
    assert_eq!(decoded_message.is_private, message.is_private);
    
    // Timestamp should be close (within 1 second due to conversion)
    let time_diff = (decoded_message.timestamp.timestamp_millis() - message.timestamp.timestamp_millis()).abs();
    assert!(time_diff < 1000);
}

#[test]
fn test_private_message_encoding() {
    let message = create_test_message_private("Bob");
    
    let payload = message.to_binary_payload().expect("Failed to encode private message");
    let decoded_message = BitchatMessage::from_binary_payload(&payload)
        .expect("Failed to decode private message");
    
    assert!(decoded_message.is_private);
    assert_eq!(decoded_message.recipient_nickname, Some("Bob".to_string()));
}

#[test]
fn test_message_with_mentions() {
    let mentions = vec!["Bob".to_string(), "Charlie".to_string()];
    let message = create_test_message_with_mentions(mentions.clone());
    
    let payload = message.to_binary_payload().expect("Failed to encode message with mentions");
    let decoded_message = BitchatMessage::from_binary_payload(&payload)
        .expect("Failed to decode message with mentions");
    
    assert_eq!(decoded_message.mentions, Some(mentions));
}

#[test]
fn test_relay_message_encoding() {
    let mut message = create_test_message();
    message.is_relay = true;
    message.original_sender = Some("Charlie".to_string());
    
    let payload = message.to_binary_payload().expect("Failed to encode relay message");
    let decoded_message = BitchatMessage::from_binary_payload(&payload)
        .expect("Failed to decode relay message");
    
    assert!(decoded_message.is_relay);
    assert_eq!(decoded_message.original_sender, Some("Charlie".to_string()));
}

#[test]
fn test_invalid_data_decoding() {
    // Too small data
    let too_small = vec![0u8; 5];
    assert!(BinaryProtocol::decode(&too_small).is_err());
    
    // Random data
    let random = generate_random_data(100);
    assert!(BinaryProtocol::decode(&random).is_err());
    
    // Corrupted header
    let packet = create_test_packet();
    let mut encoded = BinaryProtocol::encode(&packet).expect("Failed to encode test packet");
    
    // Corrupt the version byte
    encoded[0] = 0xFF;
    assert!(BinaryProtocol::decode(&encoded).is_err());
}

#[test]
fn test_large_message_handling() {
    // Test maximum size handling
    let large_content = "X".repeat(65535); // Max u16
    let message = create_test_message_with_content(&large_content);
    
    let payload = message.to_binary_payload().expect("Failed to encode large message");
    let decoded_message = BitchatMessage::from_binary_payload(&payload)
        .expect("Failed to decode large message");
    
    assert_eq!(decoded_message.content, large_content);
}

#[test]
fn test_empty_fields_handling() {
    // Test message with empty content
    let empty_message = create_test_message_with_content("");
    
    let payload = empty_message.to_binary_payload().expect("Failed to encode empty message");
    let decoded_message = BitchatMessage::from_binary_payload(&payload)
        .expect("Failed to decode empty message");
    
    assert_eq!(decoded_message.content, "");
}

#[test]
fn test_protocol_version_handling() {
    let packet = create_test_packet();
    
    let encoded = BinaryProtocol::encode(&packet).expect("Failed to encode packet");
    let decoded = BinaryProtocol::decode(&encoded).expect("Failed to decode packet");
    
    assert_eq!(decoded.version, 1);
}

#[test]
fn test_unsupported_protocol_version() {
    let packet = create_test_packet();
    let mut encoded = BinaryProtocol::encode(&packet).expect("Failed to encode packet");
    
    // Manually change version byte to unsupported value
    encoded[0] = 99;
    
    // Should fail to decode
    assert!(BinaryProtocol::decode(&encoded).is_err());
}

#[test]
fn test_malformed_packet_with_invalid_payload_length() {
    let mut malformed_data = Vec::new();
    
    // Valid header (13 bytes)
    malformed_data.push(1); // version
    malformed_data.push(1); // type
    malformed_data.push(10); // ttl
    
    // Timestamp (8 bytes)
    for _ in 0..8 {
        malformed_data.push(0);
    }
    
    malformed_data.push(0); // flags
    
    // Invalid payload length: 193 (0x00c1) but we'll only provide 8 bytes total data
    malformed_data.push(0x00);
    malformed_data.push(0xc1);
    
    // SenderID (8 bytes)
    for _ in 0..8 {
        malformed_data.push(0x01);
    }
    
    // Only provide 8 more bytes instead of the claimed 193
    for _ in 0..8 {
        malformed_data.push(0x02);
    }
    
    assert_eq!(malformed_data.len(), 30);
    
    // This should not crash - should return error gracefully
    assert!(BinaryProtocol::decode(&malformed_data).is_err());
}

#[test]
fn test_truncated_packet_handling() {
    let packet = create_test_packet();
    let valid_encoded = BinaryProtocol::encode(&packet).expect("Failed to encode test packet");
    
    // Test truncation at various points
    let truncation_points = vec![0, 5, 10, 15, 20, 25];
    
    for point in truncation_points {
        let truncated = &valid_encoded[..point.min(valid_encoded.len())];
        assert!(BinaryProtocol::decode(truncated).is_err(),
            "Truncated packet at {} bytes should return error", point);
    }
}

#[test]
fn test_malformed_compressed_packet() {
    let mut malformed_data = Vec::new();
    
    // Valid header
    malformed_data.push(1); // version
    malformed_data.push(1); // type
    malformed_data.push(10); // ttl
    
    // Timestamp (8 bytes)
    for _ in 0..8 {
        malformed_data.push(0);
    }
    
    malformed_data.push(0x04); // flags: is_compressed = true
    
    // Small payload length that's insufficient for compression
    malformed_data.push(0x00);
    malformed_data.push(0x01); // 1 byte - insufficient for 2-byte original size
    
    // SenderID (8 bytes)
    for _ in 0..8 {
        malformed_data.push(0x01);
    }
    
    // Only 1 byte of "compressed" data
    malformed_data.push(0x99);
    
    // Should handle this gracefully
    assert!(BinaryProtocol::decode(&malformed_data).is_err());
}

#[test]
fn test_channel_message_encoding() {
    let message = create_test_message_with_channel("#general");
    
    let payload = message.to_binary_payload().expect("Failed to encode channel message");
    let decoded_message = BitchatMessage::from_binary_payload(&payload)
        .expect("Failed to decode channel message");
    
    assert_eq!(decoded_message.channel, Some("#general".to_string()));
}

#[test]
fn test_encrypted_message_encoding() {
    let mut message = create_test_message();
    message.is_encrypted = true;
    message.encrypted_content = Some(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    message.content = String::new(); // Empty content for encrypted
    
    let payload = message.to_binary_payload().expect("Failed to encode encrypted message");
    let decoded_message = BitchatMessage::from_binary_payload(&payload)
        .expect("Failed to decode encrypted message");
    
    assert!(decoded_message.is_encrypted);
    assert_eq!(decoded_message.encrypted_content, Some(vec![1, 2, 3, 4, 5, 6, 7, 8]));
}
