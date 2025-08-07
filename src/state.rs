use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppState {
    pub nickname: String,
    pub peer_id_override: Option<String>, // hex-encoded peer ID override (optional, for manual setting)
    pub private_key: Option<String>, // hex-encoded private key for persistent identity
    pub wifi_secret_salt: Option<String>, // hex-encoded 32-byte secret salt for WiFi password generation
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            nickname: "anonymous".to_string(),
            peer_id_override: None,
            private_key: None,
            wifi_secret_salt: None,
        }
    }
}

impl AppState {
    /// Get the path to the state file (~/.bitchat/state.json)
    fn get_state_file_path() -> Result<PathBuf> {
        let home_dir = dirs::home_dir()
            .ok_or_else(|| Error::Other("Could not determine home directory".to_string()))?;
        
        let bitchat_dir = home_dir.join(".bitchat");
        
        // Create the directory if it doesn't exist
        if !bitchat_dir.exists() {
            fs::create_dir_all(&bitchat_dir)
                .map_err(|e| Error::Other(format!("Failed to create .bitchat directory: {}", e)))?;
        }
        
        Ok(bitchat_dir.join("state.json"))
    }
    
    /// Load state from ~/.bitchat/state.json
    pub fn load() -> Result<Self> {
        let state_path = Self::get_state_file_path()?;
        
        if !state_path.exists() {
            // Return default state if file doesn't exist
            return Ok(Self::default());
        }
        
        let contents = fs::read_to_string(&state_path)
            .map_err(|e| Error::Other(format!("Failed to read state file: {}", e)))?;
        
        let state: AppState = serde_json::from_str(&contents)
            .map_err(|e| Error::Other(format!("Failed to parse state file: {}", e)))?;
        
        Ok(state)
    }
    
    /// Save state to ~/.bitchat/state.json
    pub fn save(&self) -> Result<()> {
        let state_path = Self::get_state_file_path()?;
        
        let contents = serde_json::to_string_pretty(self)
            .map_err(|e| Error::Other(format!("Failed to serialize state: {}", e)))?;
        
        fs::write(&state_path, contents)
            .map_err(|e| Error::Other(format!("Failed to write state file: {}", e)))?;
        
        log::info!("Saved state to: {}", state_path.display());
        Ok(())
    }
    
    /// Update nickname and save
    pub fn update_nickname(&mut self, nickname: String) -> Result<()> {
        self.nickname = nickname;
        self.save()
    }
    
    /// Generate a new private key and save to state (no longer generates peer ID)
    pub fn generate_new_identity(&mut self) -> Result<()> {
        // Generate a private key for persistent identity (32 bytes for Ed25519)
        let mut private_key_bytes = [0u8; 32];
        getrandom::getrandom(&mut private_key_bytes)
            .map_err(|e| Error::Other(format!("Failed to generate private key: {}", e)))?;
        
        self.private_key = Some(hex::encode(&private_key_bytes));
        
        self.save()
    }
    
    /// Get peer ID override as bytes (returns None if not set)
    pub fn get_peer_id_override_bytes(&self) -> Result<Option<[u8; 8]>> {
        match self.peer_id_override.as_ref() {
            Some(peer_id_hex) => {
                let bytes = hex::decode(peer_id_hex)
                    .map_err(|e| Error::Other(format!("Invalid peer ID hex: {}", e)))?;
                
                if bytes.len() != 8 {
                    return Err(Error::Other("Peer ID must be 8 bytes".to_string()));
                }
                
                let mut result = [0u8; 8];
                result.copy_from_slice(&bytes);
                Ok(Some(result))
            }
            None => Ok(None)
        }
    }
    
    /// Get private key as bytes
    pub fn get_private_key_bytes(&self) -> Result<[u8; 32]> {
        let private_key_hex = self.private_key.as_ref()
            .ok_or_else(|| Error::Other("No private key set".to_string()))?;
        
        let bytes = hex::decode(private_key_hex)
            .map_err(|e| Error::Other(format!("Invalid private key hex: {}", e)))?;
        
        if bytes.len() != 32 {
            return Err(Error::Other("Private key must be 32 bytes".to_string()));
        }
        
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes);
        Ok(result)
    }
    
    /// Generate WiFi secret salt if not exists and save
    pub fn ensure_wifi_secret_salt(&mut self) -> Result<()> {
        if self.wifi_secret_salt.is_none() {
            // Generate a new 32-byte secret salt
            let mut salt_bytes = [0u8; 32];
            getrandom::getrandom(&mut salt_bytes)
                .map_err(|e| Error::Other(format!("Failed to generate WiFi secret salt: {}", e)))?;
            
            self.wifi_secret_salt = Some(hex::encode(&salt_bytes));
            self.save()?;
            
            log::info!("Generated new WiFi secret salt");
        }
        Ok(())
    }
    
    /// Get WiFi secret salt as bytes
    pub fn get_wifi_secret_salt_bytes(&self) -> Result<[u8; 32]> {
        let salt_hex = self.wifi_secret_salt.as_ref()
            .ok_or_else(|| Error::Other("No WiFi secret salt set".to_string()))?;
        
        let bytes = hex::decode(salt_hex)
            .map_err(|e| Error::Other(format!("Invalid WiFi salt hex: {}", e)))?;
        
        if bytes.len() != 32 {
            return Err(Error::Other("WiFi salt must be 32 bytes".to_string()));
        }
        
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes);
        Ok(result)
    }
}