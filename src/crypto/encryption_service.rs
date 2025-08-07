use crate::{Error, Result};
use crate::crypto::NoiseEncryptionService;
use crate::protocol::Packet;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::sync::Arc;

/// Wrapper service that provides backward compatibility while using NoiseEncryptionService
pub struct EncryptionService {
    noise_service: Arc<NoiseEncryptionService>,
}

impl EncryptionService {
    pub fn new() -> Result<Self> {
        Ok(Self {
            noise_service: Arc::new(NoiseEncryptionService::new()?),
        })
    }
    
    pub fn get_noise_service(&self) -> Arc<NoiseEncryptionService> {
        self.noise_service.clone()
    }
    
    pub fn get_identity_public_key(&self) -> Vec<u8> {
        self.noise_service.get_identity_public_key()
    }
    
    pub fn get_static_public_key(&self) -> Vec<u8> {
        self.noise_service.get_static_public_key()
    }
    
    pub async fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.noise_service.sign_data(data).await
    }
    
    pub async fn sign_packet(&self, packet: Packet) -> Result<Packet> {
        self.noise_service.sign_packet(packet).await
    }
    
    /// Encrypt data using password-derived key (for channel encryption)
    pub fn encrypt_with_password(data: &[u8], password: &str) -> Result<Vec<u8>> {
        // Derive key from password
        let salt = b"bitchat-channel-salt"; // Fixed salt for deterministic key derivation
        let mut key_bytes = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut key_bytes);
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| Error::Encryption(format!("Failed to generate nonce: {}", e)))?;
        
        // Encrypt
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| Error::Encryption(format!("AES encryption failed: {}", e)))?;
        
        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Decrypt data using password-derived key (for channel decryption)
    pub fn decrypt_with_password(data: &[u8], password: &str) -> Result<Vec<u8>> {
        if data.len() < 12 {
            return Err(Error::Encryption("Data too short for decryption".to_string()));
        }
        
        // Extract nonce and ciphertext
        let nonce_bytes = &data[..12];
        let ciphertext = &data[12..];
        
        // Derive key from password
        let salt = b"bitchat-channel-salt";
        let mut key_bytes = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut key_bytes);
        
        // Decrypt
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| Error::Encryption(format!("AES decryption failed: {}", e)))?;
        
        Ok(plaintext)
    }
}