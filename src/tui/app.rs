use tui_input::Input;
use std::collections::HashMap;
use chrono;

#[derive(Debug, Clone)]
pub struct Message {
    pub id: String,  // Message ID for tracking acks/receipts
    pub sender: String,
    pub timestamp: String,
    pub content: String,
    pub is_self: bool,
    pub is_trusted: bool,  // For showing trust indicator
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidebarSection {
    Channels,
    People,
    Blocked,
    Settings,
}

pub struct SidebarMenuState {
    pub expanded: [bool; 5], // Public, Channels, People, Blocked, Settings
    pub public_selected: Option<bool>,
    pub channel_selected: Option<usize>,
    pub people_selected: Option<usize>,
    pub blocked_selected: Option<usize>,
}

impl SidebarMenuState {
    pub fn new() -> Self {
        Self {
            expanded: [true, true, true, true, true],
            public_selected: Some(true),
            channel_selected: None,
            people_selected: None,
            blocked_selected: None,
        }
    }

    pub fn toggle_expand(&mut self, section_index: usize) {
        if section_index < self.expanded.len() {
            self.expanded[section_index] = !self.expanded[section_index];
        }
    }
}

pub enum TuiPhase {
    Connecting,
    Connected,
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusArea {
    Sidebar,
    MainPanel,
    InputBox,
}

pub struct App {
    // UI state
    pub input: Input,
    pub phase: TuiPhase,
    pub should_quit: bool,
    pub focus_area: FocusArea,
    pub sidebar_flat_selected: usize,
    pub msg_scroll: usize,
    pub message_viewport_height: usize,
    
    // Data state for rendering
    pub nickname: String,
    pub network_name: String,
    pub connected: bool,
    pub channels: Vec<String>,
    pub people: Vec<String>,
    pub blocked: Vec<String>,
    
    // Debug mode flag
    pub debug_mode: bool,
    
    // Message storage
    pub channel_messages: HashMap<String, Vec<Message>>,
    pub dm_messages: HashMap<String, Vec<Message>>,
    
    // Navigation and Popups
    pub sidebar_state: SidebarMenuState,
    pub popup_messages: Vec<String>,
    
    // To track current conversation
    pub current_conv: Option<(Option<String>, Option<String>)>, // (DM target, Channel name)
    
    // Backend communication flags
    pub pending_channel_switch: Option<String>,
    pub pending_dm_switch: Option<(String, String)>,
    pub pending_nickname_update: Option<String>,
    pub pending_connection_retry: bool,
    pub pending_clear_conversation: bool,
    pub pending_reconnect: bool,
    
    // Unread message tracking
    pub unread_counts: HashMap<String, usize>,
    pub last_read_messages: HashMap<String, usize>,
    
    // Popup state
    pub popup_active: bool,
    pub popup_input: Input,
    pub popup_title: String,
}

impl App {
    pub fn new_with_nickname(nickname: String) -> Self {
        let channels = Vec::new();
        let mut channel_messages = HashMap::new();
        channel_messages.insert("#public".to_string(), Vec::new());
        
        let mut app = Self {
            input: Input::default(),
            phase: TuiPhase::Connected,
            should_quit: false,
            focus_area: FocusArea::InputBox,
            sidebar_flat_selected: 0,
            msg_scroll: 0,
            message_viewport_height: 10,
            nickname,
            network_name: "BitChat Mesh".to_string(),
            connected: false,
            channels,
            people: Vec::new(),
            blocked: Vec::new(),
            debug_mode: false,  // Start with debug mode off
            channel_messages,
            dm_messages: HashMap::new(),
            sidebar_state: SidebarMenuState::new(),
            popup_messages: Vec::new(),
            current_conv: Some((None, Some("#public".to_string()))),
            pending_channel_switch: None,
            pending_dm_switch: None,
            pending_nickname_update: None,
            pending_connection_retry: false,
            pending_clear_conversation: false,
            pending_reconnect: false,
            unread_counts: HashMap::new(),
            last_read_messages: HashMap::new(),
            popup_active: false,
            popup_input: Input::default(),
            popup_title: String::new(),
        };
        
        app.update_current_conversation();
        app
    }
    
    pub fn get_current_messages(&self) -> (&[Message], Option<String>, Option<String>) {
        if let Some(user_idx) = self.sidebar_state.people_selected {
            if let Some(user) = self.people.get(user_idx) {
                let messages = self.dm_messages.get(user).map(|v| v.as_slice()).unwrap_or(&[]);
                return (messages, Some(user.clone()), None);
            }
        }
        
        let ch = self.get_selected_channel_name();
        let messages = self.channel_messages.get(&ch).map(|v| v.as_slice()).unwrap_or(&[]);
        (messages, None, Some(ch))
    }

    pub fn get_selected_channel_name(&self) -> String {
        if self.sidebar_state.public_selected.unwrap_or(false) {
            return "#public".to_string();
        }
        
        if let Some(idx) = self.sidebar_state.channel_selected {
            if let Some(ch_name) = self.channels.get(idx) {
                return ch_name.clone();
            }
        }
        "#public".to_string()
    }

    pub fn update_current_conversation(&mut self) {
        if let Some(user_idx) = self.sidebar_state.people_selected {
            if let Some(user) = self.people.get(user_idx) {
                self.current_conv = Some((Some(user.clone()), None));
                return;
            }
        }
        
        if self.sidebar_state.public_selected.unwrap_or(false) {
            self.current_conv = Some((None, Some("#public".to_string())));
            return;
        }
        
        if let Some(channel_idx) = self.sidebar_state.channel_selected {
            if let Some(channel) = self.channels.get(channel_idx) {
                self.current_conv = Some((None, Some(channel.clone())));
                return;
            }
        }
        
        self.current_conv = Some((None, Some("#public".to_string())));
    }

    pub fn add_sent_message(&mut self, text: String) {
        let timestamp = chrono::Local::now().format("%H:%M").to_string();
        let msg = Message { 
            id: uuid::Uuid::new_v4().to_string(),
            sender: self.nickname.clone(), 
            timestamp, 
            content: text, 
            is_self: true,
            is_trusted: false  // Self messages don't need trust indicator
        };

        let (dm_target, channel_name) = self.current_conv.clone().unwrap_or((None, None));
        if let Some(target) = dm_target {
            self.dm_messages.entry(target).or_default().push(msg);
        } else if let Some(channel) = channel_name {
            self.channel_messages.entry(channel).or_default().push(msg);
        }
        self.scroll_to_bottom_current_conversation();
    }

    pub fn add_sent_dm(&mut self, recipient: String, text: String, is_encrypted: bool, is_trusted: bool) {
        let timestamp = chrono::Local::now().format("%H:%M").to_string();
        
        // Don't add to DM history yet - wait for successful send
        // Just show attempt in current conversation
        let display_msg = Message {
            id: uuid::Uuid::new_v4().to_string(),
            sender: format!("→ {}", recipient),
            timestamp,
            content: text,
            is_self: true, // Mark as self so it shows in green/different color
            is_trusted: is_encrypted && is_trusted,  // Only show checkmark for encrypted messages to trusted peers
        };
        
        // Add to current channel/DM based on current_conv
        if let Some((dm_target, channel_name)) = &self.current_conv {
            if let Some(target) = dm_target {
                self.dm_messages.entry(target.clone()).or_default().push(display_msg);
            } else if let Some(channel) = channel_name {
                self.channel_messages.entry(channel.clone()).or_default().push(display_msg);
            }
        }
        
        self.scroll_to_bottom_current_conversation();
    }

    pub fn add_system_message(&mut self, text: String) {
        let timestamp = chrono::Local::now().format("%H:%M").to_string();
        let msg = Message {
            id: uuid::Uuid::new_v4().to_string(),
            sender: "system".to_string(),
            timestamp,
            content: text,
            is_self: false,
            is_trusted: false,
        };
        
        // Add to current channel/DM based on current_conv
        if let Some((dm_target, channel_name)) = &self.current_conv {
            if let Some(target) = dm_target {
                self.dm_messages.entry(target.clone()).or_default().push(msg);
            } else if let Some(channel) = channel_name {
                self.channel_messages.entry(channel.clone()).or_default().push(msg);
            }
        }
        
        self.scroll_to_bottom_current_conversation();
    }

    pub fn scroll_to_bottom_current_conversation(&mut self) {
        self.msg_scroll = 0;
    }
    
    pub fn transition_to_connected(&mut self) {
        self.phase = TuiPhase::Connected;
        self.connected = true;
        let mut final_messages = self.popup_messages.drain(..)
            .map(|content| Message { 
                id: uuid::Uuid::new_v4().to_string(),
                sender: "system".to_string(), 
                timestamp: chrono::Local::now().format("%H:%M").to_string(), 
                content, 
                is_self: false,
                is_trusted: false 
            })
            .collect();
        self.channel_messages.entry("#public".to_string()).or_default().append(&mut final_messages);
    }
    
    pub fn transition_to_connecting(&mut self) {
        self.phase = TuiPhase::Connecting;
        self.connected = false;
        self.popup_messages.clear();
    }

    pub fn transition_to_error(&mut self, error: String) {
        self.phase = TuiPhase::Error(error);
    }

    pub fn add_popup_message(&mut self, message: String) {
        let trimmed = message.trim().to_string();
        if !trimmed.is_empty() { 
            match self.phase {
                TuiPhase::Connecting => {
                    // During connecting, add to popup messages
                    self.popup_messages.push(trimmed); 
                }
                TuiPhase::Connected | TuiPhase::Error(_) => {
                    // When connected, add as system message to current conversation
                    let system_msg = Message {
                        id: uuid::Uuid::new_v4().to_string(),
                        sender: "system".to_string(),
                        timestamp: chrono::Local::now().format("%H:%M").to_string(),
                        content: trimmed,
                        is_self: false,
                        is_trusted: false,
                    };
                    
                    // Add to current channel/DM
                    if let Some((dm_target, channel_name)) = &self.current_conv {
                        if let Some(target) = dm_target {
                            self.dm_messages.entry(target.clone()).or_default().push(system_msg);
                        } else if let Some(channel) = channel_name {
                            self.channel_messages.entry(channel.clone()).or_default().push(system_msg);
                        }
                    }
                    
                    self.scroll_to_bottom_current_conversation();
                }
            }
        }
    }

    pub fn mark_current_conversation_as_read(&mut self) {
        let (messages, dm_target, channel_name) = self.get_current_messages();
        let conversation_key = if let Some(target) = dm_target { 
            format!("dm:{}", target) 
        } else if let Some(channel) = channel_name { 
            channel 
        } else { 
            return; 
        };
        let message_count = messages.len();
        self.last_read_messages.insert(conversation_key.clone(), message_count);
        self.unread_counts.remove(&conversation_key);
    }

    pub fn add_unread_message(&mut self, conversation_key: String) {
        let (_, dm_target, channel_name) = self.get_current_messages();
        let current_key = if let Some(target) = dm_target { 
            format!("dm:{}", target) 
        } else if let Some(channel) = channel_name { 
            channel 
        } else { 
            return; 
        };
        if current_key == conversation_key { 
            return; 
        }
        *self.unread_counts.entry(conversation_key).or_insert(0) += 1;
    }

    pub fn get_unread_count(&self, conversation_key: &str) -> usize {
        self.unread_counts.get(conversation_key).copied().unwrap_or(0)
    }

    pub fn get_section_unread_count(&self, section: usize) -> usize {
        match section {
            0 => { 
                if self.get_unread_count("#public") > 0 { 1 } else { 0 } 
            }
            1 => { 
                self.channels.iter().map(|ch| self.get_unread_count(ch)).sum() 
            }
            2 => { 
                self.people.iter()
                    .map(|person| self.get_unread_count(&format!("dm:{}", person)))
                    .sum() 
            }
            _ => 0,
        }
    }

    pub fn update_sidebar_flat_selection(&mut self) {
        let mut flat_idx = 0;
        for section in 0..5 {
            flat_idx += 1;
            if self.sidebar_state.expanded[section] {
                let count = match section {
                    0 => 1,
                    1 => self.channels.len(),
                    2 => self.people.len(),
                    3 => self.blocked.len(),
                    4 => 2,
                    _ => 0,
                };
                let is_current_section = match section {
                    0 => self.sidebar_state.public_selected.unwrap_or(false),
                    1 => self.sidebar_state.channel_selected.is_some(),
                    2 => self.sidebar_state.people_selected.is_some(),
                    _ => false,
                };
                if is_current_section {
                    let item_idx = match section {
                        0 => 0,
                        1 => self.sidebar_state.channel_selected.unwrap_or(0),
                        2 => self.sidebar_state.people_selected.unwrap_or(0),
                        _ => 0,
                    };
                    self.sidebar_flat_selected = flat_idx + item_idx;
                    return;
                }
                flat_idx += count;
            }
        }
    }
    
    pub fn get_input_box_height(&self, available_width: usize) -> usize {
        let input_text = self.input.value();
        if input_text.is_empty() {
            return 3;
        }
        
        let chars: Vec<char> = input_text.chars().collect();
        let mut lines_needed = 1;
        let mut current_line_length = 0;
        
        for &ch in &chars {
            if ch == '\n' {
                lines_needed += 1;
                current_line_length = 0;
            } else {
                current_line_length += 1;
                if current_line_length >= available_width.saturating_sub(2) {
                    lines_needed += 1;
                    current_line_length = 0;
                }
            }
        }
        
        std::cmp::max(3, std::cmp::min(lines_needed + 2, 10))
    }
    
    pub fn add_received_message(&mut self, sender: String, content: String, channel: Option<String>, is_private: bool, recipient_nickname: Option<String>, is_trusted: bool) {
        self.add_received_message_with_id(uuid::Uuid::new_v4().to_string(), sender, content, channel, is_private, recipient_nickname, is_trusted);
    }
    
    pub fn add_received_message_with_id(&mut self, message_id: String, sender: String, content: String, channel: Option<String>, is_private: bool, recipient_nickname: Option<String>, is_trusted: bool) {
        let timestamp = chrono::Local::now().format("%H:%M").to_string();
        let sender_clone = sender.clone();
        let content_clone = content.clone();
        let msg = Message {
            id: message_id.clone(),
            sender,
            timestamp,
            content,
            is_self: false,
            is_trusted,
        };
        
        if is_private {
            if let Some(recipient) = recipient_nickname {
                if recipient == self.nickname {
                    // Message is for us, store under sender
                    let dm_key = msg.sender.clone();
                    self.dm_messages.entry(dm_key.clone()).or_default().push(msg);
                    
                    // Add unread notification if not currently viewing this DM
                    let (_, current_dm, _) = self.get_current_messages();
                    if current_dm.as_ref() != Some(&sender_clone) {
                        self.add_unread_message(format!("dm:{}", sender_clone));
                        
                        // Also show in current conversation
                        let display_msg = Message {
                            id: message_id,
                            sender: format!("← {}", sender_clone),
                            timestamp: chrono::Local::now().format("%H:%M").to_string(),
                            content: content_clone,
                            is_self: false,
                            is_trusted,
                        };
                        
                        // Add to current channel
                        if let Some((_, channel_name)) = &self.current_conv {
                            if let Some(channel) = channel_name {
                                self.channel_messages.entry(channel.clone()).or_default().push(display_msg);
                            }
                        }
                    }
                }
            }
        } else {
            // Channel message
            let channel_name = channel.unwrap_or_else(|| "#public".to_string());
            self.channel_messages.entry(channel_name.clone()).or_default().push(msg);
            
            // Add unread notification if not currently viewing this channel
            let (_, _, current_channel) = self.get_current_messages();
            if current_channel.as_ref() != Some(&channel_name) {
                self.add_unread_message(channel_name);
            }
        }
        
        self.scroll_to_bottom_current_conversation();
    }
}