use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct Peer {
    pub id: String,
    pub nickname: Option<String>,
    pub fingerprint: Option<String>,
    pub last_seen: DateTime<Utc>,
    pub is_connected: bool,
    pub is_favorite: bool,
    pub static_public_key: Option<Vec<u8>>,
}

impl Peer {
    pub fn new(id: String) -> Self {
        Self {
            id,
            nickname: None,
            fingerprint: None,
            last_seen: Utc::now(),
            is_connected: false,
            is_favorite: false,
            static_public_key: None,
        }
    }
    
    pub fn display_name(&self) -> &str {
        self.nickname.as_deref().unwrap_or(&self.id)
    }
    
    pub fn update_last_seen(&mut self) {
        self.last_seen = Utc::now();
    }
}