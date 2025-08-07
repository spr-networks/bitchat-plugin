use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Announce = 0x01,
    Leave = 0x03,
    Message = 0x04,
    FragmentStart = 0x05,
    FragmentContinue = 0x06,
    FragmentEnd = 0x07,
    ChannelAnnounce = 0x08,
    ChannelRetention = 0x09,
    DeliveryAck = 0x0A,
    DeliveryStatusRequest = 0x0B,
    ReadReceipt = 0x0C,
    NoiseHandshakeInit = 0x10,
    NoiseHandshakeResp = 0x11,
    NoiseEncrypted = 0x12,
    NoiseIdentityAnnounce = 0x13,
    ChannelKeyVerifyRequest = 0x14,
    ChannelKeyVerifyResponse = 0x15,
    ChannelPasswordUpdate = 0x16,
    ChannelMetadata = 0x17,
    NoiseHandshakeFinal = 0x18,
    VersionHello = 0x20,
    VersionAck = 0x21,
    ProtocolAck = 0x22,
    ProtocolNack = 0x23,
    SystemValidation = 0x24,
    HandshakeRequest = 0x25,
    Favorited = 0x30,
    Unfavorited = 0x31,
}

impl MessageType {
    pub fn from_u8(value: u8) -> crate::Result<Self> {
        match value {
            0x01 => Ok(MessageType::Announce),
            0x03 => Ok(MessageType::Leave),
            0x04 => Ok(MessageType::Message),
            0x05 => Ok(MessageType::FragmentStart),
            0x06 => Ok(MessageType::FragmentContinue),
            0x07 => Ok(MessageType::FragmentEnd),
            0x08 => Ok(MessageType::ChannelAnnounce),
            0x09 => Ok(MessageType::ChannelRetention),
            0x0A => Ok(MessageType::DeliveryAck),
            0x0B => Ok(MessageType::DeliveryStatusRequest),
            0x0C => Ok(MessageType::ReadReceipt),
            0x10 => Ok(MessageType::NoiseHandshakeInit),
            0x11 => Ok(MessageType::NoiseHandshakeResp),
            0x12 => Ok(MessageType::NoiseEncrypted),
            0x13 => Ok(MessageType::NoiseIdentityAnnounce),
            0x14 => Ok(MessageType::ChannelKeyVerifyRequest),
            0x15 => Ok(MessageType::ChannelKeyVerifyResponse),
            0x16 => Ok(MessageType::ChannelPasswordUpdate),
            0x17 => Ok(MessageType::ChannelMetadata),
            0x18 => Ok(MessageType::NoiseHandshakeFinal),
            0x20 => Ok(MessageType::VersionHello),
            0x21 => Ok(MessageType::VersionAck),
            0x22 => Ok(MessageType::ProtocolAck),
            0x23 => Ok(MessageType::ProtocolNack),
            0x24 => Ok(MessageType::SystemValidation),
            0x25 => Ok(MessageType::HandshakeRequest),
            0x30 => Ok(MessageType::Favorited),
            0x31 => Ok(MessageType::Unfavorited),
            _ => Err(Error::UnknownMessageType(value)),
        }
    }
    
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}