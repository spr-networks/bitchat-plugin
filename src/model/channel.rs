#[derive(Debug, Clone)]
pub struct Channel {
    pub name: String,
    pub password: Option<String>,
    pub is_encrypted: bool,
    pub unread_count: usize,
}

impl Channel {
    pub fn new(name: String) -> Self {
        Self {
            name,
            password: None,
            is_encrypted: false,
            unread_count: 0,
        }
    }
    
    pub fn encrypted(name: String, password: String) -> Self {
        Self {
            name,
            password: Some(password),
            is_encrypted: true,
            unread_count: 0,
        }
    }
}