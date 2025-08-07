use crate::{Error, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::fs;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TrustLevel {
    Unknown,
    Trusted,
    Verified,  // Future: for in-person verification
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEntry {
    pub fingerprint: String,
    pub nickname: Option<String>,
    pub peer_id: Option<String>,  // Current peer ID (may change)
    pub trust_level: TrustLevel,
    pub first_seen: DateTime<Utc>,
    pub last_verified: Option<DateTime<Utc>>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustStore {
    // Fingerprint -> TrustEntry
    pub trusted_peers: HashMap<String, TrustEntry>,
    // Nickname -> Fingerprint mapping for easy lookup
    pub nickname_index: HashMap<String, String>,
}

pub struct TrustManager {
    store: Arc<RwLock<TrustStore>>,
    config_path: PathBuf,
}

impl TrustManager {
    pub fn new() -> Result<Self> {

        let home_dir = dirs::home_dir()
            .ok_or_else(|| Error::Other("Could not determine home directory".to_string()))?;

        let config_dir = home_dir.join(".bitchat");

        // Create the directory if it doesn't exist
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)
                .map_err(|e| Error::Other(format!("Failed to create .bitchat directory: {}", e)))?;
        }
        
        let config_path = config_dir.join("trust.json");
        
        let store = if config_path.exists() {
            // Load existing trust store
            let data = std::fs::read_to_string(&config_path)?;
            serde_json::from_str(&data)
                .unwrap_or_else(|_| TrustStore {
                    trusted_peers: HashMap::new(),
                    nickname_index: HashMap::new(),
                })
        } else {
            TrustStore {
                trusted_peers: HashMap::new(),
                nickname_index: HashMap::new(),
            }
        };
        
        Ok(Self {
            store: Arc::new(RwLock::new(store)),
            config_path,
        })
    }
    
    async fn save_internal(&self, store: &TrustStore) -> Result<()> {
        let data = serde_json::to_string_pretty(store)?;
        std::fs::write(&self.config_path, data)?;
        Ok(())
    }
    
    pub async fn save(&self) -> Result<()> {
        let store = self.store.read().await;
        self.save_internal(&*store).await
    }
    
    pub async fn trust_peer(&self, fingerprint: String, nickname: Option<String>, peer_id: Option<String>) -> Result<()> {
        let mut store = self.store.write().await;
        
        // Remove old nickname mapping if exists
        if let Some(old_nickname) = store.trusted_peers.get(&fingerprint).and_then(|e| e.nickname.clone()) {
            store.nickname_index.remove(&old_nickname);
        }
        
        // Add new nickname mapping
        if let Some(ref nick) = nickname {
            store.nickname_index.insert(nick.clone(), fingerprint.clone());
        }
        
        // Create or update trust entry
        let entry = store.trusted_peers.entry(fingerprint.clone()).or_insert_with(|| {
            TrustEntry {
                fingerprint: fingerprint.clone(),
                nickname: nickname.clone(),
                peer_id: peer_id.clone(),
                trust_level: TrustLevel::Trusted,
                first_seen: Utc::now(),
                last_verified: None,
                notes: None,
            }
        });
        
        // Update fields
        entry.trust_level = TrustLevel::Trusted;
        entry.last_verified = Some(Utc::now());
        if nickname.is_some() {
            entry.nickname = nickname;
        }
        if peer_id.is_some() {
            entry.peer_id = peer_id;
        }
        
        // Save while holding the write lock
        self.save_internal(&*store).await?;
        Ok(())
    }
    
    pub async fn untrust_peer(&self, identifier: &str) -> Result<bool> {
        let mut store = self.store.write().await;
        
        // Check if identifier is a fingerprint or nickname
        let fingerprint = if store.trusted_peers.contains_key(identifier) {
            identifier.to_string()
        } else if let Some(fp) = store.nickname_index.get(identifier) {
            fp.clone()
        } else {
            return Ok(false);
        };
        
        // Remove trust entry
        if let Some(entry) = store.trusted_peers.remove(&fingerprint) {
            // Remove nickname mapping
            if let Some(ref nick) = entry.nickname {
                store.nickname_index.remove(nick);
            }
            
            // Save while holding the write lock
            self.save_internal(&*store).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    pub async fn is_trusted(&self, fingerprint: &str) -> bool {
        let store = self.store.read().await;
        store.trusted_peers.contains_key(fingerprint)
    }
    
    pub async fn is_trusted_by_nickname(&self, nickname: &str) -> bool {
        let store = self.store.read().await;
        // Check if this nickname is in the index and points to a trusted peer
        if let Some(fingerprint) = store.nickname_index.get(nickname) {
            store.trusted_peers.contains_key(fingerprint)
        } else {
            false
        }
    }
    
    pub async fn get_trust_level(&self, fingerprint: &str) -> TrustLevel {
        let store = self.store.read().await;
        store.trusted_peers
            .get(fingerprint)
            .map(|e| e.trust_level)
            .unwrap_or(TrustLevel::Unknown)
    }
    
    pub async fn get_trusted_fingerprint_by_nickname(&self, nickname: &str) -> Option<String> {
        let store = self.store.read().await;
        store.nickname_index.get(nickname).cloned()
    }
    
    pub async fn get_all_trusted(&self) -> Vec<TrustEntry> {
        let store = self.store.read().await;
        store.trusted_peers.values().cloned().collect()
    }
    
    pub async fn update_peer_id(&self, fingerprint: &str, peer_id: String) -> Result<()> {
        let mut store = self.store.write().await;
        if let Some(entry) = store.trusted_peers.get_mut(fingerprint) {
            entry.peer_id = Some(peer_id);
            // Save while holding the write lock
            self.save_internal(&*store).await?;
        }
        Ok(())
    }
}
