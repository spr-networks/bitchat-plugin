use crate::model::Peer;
use crate::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use sha2::{Sha256, Digest};

pub struct PeerManager {
    peers: Arc<RwLock<HashMap<String, Peer>>>,
    nicknames: Arc<RwLock<HashMap<String, String>>>, // nickname -> peer_id
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            nicknames: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub async fn add_peer(&self, peer_id: String) -> Result<()> {
        let mut peers = self.peers.write().await;
        let peer = peers.entry(peer_id.clone()).or_insert_with(|| Peer::new(peer_id));
        peer.update_last_seen();
        Ok(())
    }
    
    pub async fn remove_peer(&self, peer_id: &str) -> Result<()> {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.remove(peer_id) {
            // Remove nickname mapping if exists
            if let Some(nickname) = &peer.nickname {
                self.nicknames.write().await.remove(nickname);
            }
        }
        Ok(())
    }
    
    pub async fn update_peer_connected(&self, peer_id: &str, connected: bool) -> Result<()> {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(peer_id) {
            peer.is_connected = connected;
            if connected {
                peer.update_last_seen();
            }
        }
        Ok(())
    }
    
    pub async fn update_peer_nickname(&self, peer_id: &str, nickname: String) -> Result<()> {
        let mut peers = self.peers.write().await;
        let mut nicknames = self.nicknames.write().await;
        
        if let Some(peer) = peers.get_mut(peer_id) {
            // Remove old nickname mapping
            if let Some(old_nickname) = &peer.nickname {
                nicknames.remove(old_nickname);
            }
            
            // Set new nickname
            peer.nickname = Some(nickname.clone());
            nicknames.insert(nickname, peer_id.to_string());
        }
        
        Ok(())
    }
    
    pub async fn update_peer_static_key(&self, peer_id: &str, public_key: Vec<u8>) -> Result<()> {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(peer_id) {
            // Calculate fingerprint from public key
            let mut hasher = Sha256::new();
            hasher.update(&public_key);
            let fingerprint = hex::encode(hasher.finalize());
            
            peer.static_public_key = Some(public_key);
            peer.fingerprint = Some(fingerprint);
        }
        Ok(())
    }
    
    pub async fn get_peer(&self, peer_id: &str) -> Option<Peer> {
        self.peers.read().await.get(peer_id).cloned()
    }
    
    pub async fn get_peer_by_nickname(&self, nickname: &str) -> Option<Peer> {
        // Handle both "nickname" and "nickname (ID:ID:ID)" formats
        let clean_nickname = if let Some(paren_pos) = nickname.find(" (") {
            &nickname[..paren_pos]
        } else {
            nickname
        };
        
        let nicknames = self.nicknames.read().await;
        if let Some(peer_id) = nicknames.get(clean_nickname) {
            self.get_peer(peer_id).await
        } else {
            None
        }
    }
    
    pub async fn get_all_peers(&self) -> Vec<Peer> {
        self.peers.read().await.values().cloned().collect()
    }
    
    pub async fn get_connected_peers(&self) -> Vec<Peer> {
        self.peers.read().await
            .values()
            .filter(|p| p.is_connected)
            .cloned()
            .collect()
    }
    
    pub async fn get_connected_peer_nicknames(&self) -> Vec<String> {
        self.peers.read().await
            .values()
            .filter(|p| p.is_connected)
            .map(|p| {
                let nickname = p.nickname.clone().unwrap_or_else(|| format!("peer_{}", &p.id[..8]));
                // Format peer ID as ID:ID:ID (first 6 chars split by colons)
                let id_display = if p.id.len() >= 6 {
                    format!("{}:{}:{}", &p.id[0..2], &p.id[2..4], &p.id[4..6])
                } else {
                    p.id[..p.id.len().min(6)].to_string()
                };
                format!("{} ({})", nickname, id_display)
            })
            .collect()
    }
    
    pub async fn get_favorite_peers(&self) -> Vec<Peer> {
        self.peers.read().await
            .values()
            .filter(|p| p.is_favorite)
            .cloned()
            .collect()
    }
    
    pub async fn set_peer_favorite(&self, peer_id: &str, is_favorite: bool) -> Result<()> {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(peer_id) {
            peer.is_favorite = is_favorite;
        }
        Ok(())
    }
    
    pub async fn peer_exists(&self, peer_id: &str) -> bool {
        self.peers.read().await.contains_key(peer_id)
    }
    
    pub async fn get_peer_count(&self) -> usize {
        self.peers.read().await.len()
    }
    
    pub async fn nickname_exists(&self, nickname: &str) -> bool {
        self.nicknames.read().await.contains_key(nickname)
    }
    
    pub async fn update_peer_last_seen(&self, peer_id: &str) -> Result<()> {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(peer_id) {
            peer.update_last_seen();
        }
        Ok(())
    }
    
    pub async fn cleanup_stale_peers(&self, timeout_seconds: i64) -> Vec<String> {
        use chrono::Duration;
        let mut peers = self.peers.write().await;
        let mut nicknames = self.nicknames.write().await;
        let now = chrono::Utc::now();
        let mut removed_peers = Vec::new();
        
        let stale_peer_ids: Vec<String> = peers
            .iter()
            .filter(|(_, peer)| {
                peer.is_connected && 
                now.signed_duration_since(peer.last_seen) > Duration::seconds(timeout_seconds)
            })
            .map(|(id, _)| id.clone())
            .collect();
            
        for peer_id in stale_peer_ids {
            if let Some(peer) = peers.get_mut(&peer_id) {
                peer.is_connected = false;
                // Remove nickname mapping
                if let Some(nickname) = &peer.nickname {
                    nicknames.remove(nickname);
                }
                removed_peers.push(peer_id.clone());
                log::info!("Marked peer {} as disconnected due to inactivity", peer_id);
            }
        }
        
        removed_peers
    }
}