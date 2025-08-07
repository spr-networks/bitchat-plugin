use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Bluetooth error: {0}")]
    Bluetooth(String),
    
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    
    #[error("Noise protocol error: {0}")]
    Noise(String),
    
    #[error("Invalid peer ID: {0}")]
    InvalidPeerId(String),
    
    #[error("Message too large: {size} bytes (max: {max})")]
    MessageTooLarge { size: usize, max: usize },
    
    #[error("Connection error: {0}")]
    Connection(String),
    
    #[error("Timeout")]
    Timeout,
    
    #[error("Unknown message type: {0}")]
    UnknownMessageType(u8),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Other error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;