use bitchat_rust::protocol::{MessageType, Packet};
use bitchat_rust::model::BitchatMessage;
use chrono::Utc;
use rand::RngCore;

pub fn create_test_packet() -> Packet {
    Packet::new(
        MessageType::Message,
        [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0],
        b"test payload".to_vec(),
    )
}

pub fn create_test_packet_with_recipient(recipient_id: [u8; 8]) -> Packet {
    create_test_packet().with_recipient(recipient_id)
}

pub fn create_test_packet_with_signature(signature: [u8; 64]) -> Packet {
    create_test_packet().with_signature(signature)
}

pub fn create_test_packet_with_payload(payload: Vec<u8>) -> Packet {
    Packet::new(
        MessageType::Message,
        [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0],
        payload,
    )
}

pub fn create_test_message() -> BitchatMessage {
    BitchatMessage::new(
        "Alice".to_string(),
        "Hello, World!".to_string(),
        Utc::now(),
    )
}

pub fn create_test_message_with_content(content: &str) -> BitchatMessage {
    BitchatMessage::new(
        "Alice".to_string(),
        content.to_string(),
        Utc::now(),
    )
}

pub fn create_test_message_private(recipient: &str) -> BitchatMessage {
    BitchatMessage::private_message(
        "Alice".to_string(),
        "Secret message".to_string(),
        Utc::now(),
        recipient.to_string(),
    )
}

pub fn create_test_message_with_mentions(mentions: Vec<String>) -> BitchatMessage {
    let mut message = create_test_message();
    message.mentions = Some(mentions);
    message
}

pub fn create_test_message_with_channel(channel: &str) -> BitchatMessage {
    BitchatMessage::channel_message(
        "Alice".to_string(),
        "Channel message".to_string(),
        Utc::now(),
        channel.to_string(),
    )
}

pub fn generate_random_data(length: usize) -> Vec<u8> {
    let mut data = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut data);
    data
}
