use anyhow::Result;
use hex;
use bitchat_rust::mesh::{BluetoothMeshService, BluetoothMeshDelegate};
use bitchat_rust::model::{BitchatMessage, TrustManager};
use bitchat_rust::protocol::{Packet, MessageType};
use bitchat_rust::tui::{App, Event, FocusArea, LogEvent, init_tui_logger};
use bitchat_rust::state::AppState;
use std::sync::Arc;
use async_trait::async_trait;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use log::{error, info, debug, warn};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tui_input::backend::crossterm::EventHandler;

// Helper function to resolve peer ID from prefix
async fn resolve_peer_id(mesh_service: &BluetoothMeshService, prefix: &str) -> Result<String, String> {
    let peer_manager = mesh_service.get_peer_manager();
    let all_peers = peer_manager.get_all_peers().await;
    let matching_peers: Vec<_> = all_peers.iter()
        .filter(|p| p.id.starts_with(prefix))
        .collect();
    
    if matching_peers.is_empty() {
        Err(format!("No peer found matching prefix: {}", prefix))
    } else if matching_peers.len() > 1 {
        let mut msg = format!("Multiple peers match prefix '{}':\n", prefix);
        for peer in matching_peers {
            let nickname = peer.nickname.as_deref().unwrap_or("unknown");
            msg.push_str(&format!("  {} - {}\n", peer.id, nickname));
        }
        msg.push_str("Please be more specific");
        Err(msg)
    } else {
        Ok(matching_peers[0].id.clone())
    }
}

struct TuiMeshDelegate {
    app_sender: mpsc::UnboundedSender<AppEvent>,
    my_peer_id: Arc<RwLock<Option<String>>>,
    my_nickname: Arc<RwLock<String>>,
    mesh_service: Arc<RwLock<Option<Arc<BluetoothMeshService>>>>,
}

enum AppEvent {
    Message(BitchatMessage),
    PeerConnected(String),
    PeerDisconnected(String),
    PeerListUpdated(Vec<String>),
    NoiseHandshakeComplete(String),
    NoiseHandshakeFailed(String, String),
    Error(String),
    Log(String, log::Level),
    CommandOutput(String),  // Always visible command output
    ConnectToPeer(String),
    DeliveryAck(String, String),
    ReadReceipt(String, String),
    TypingIndicator(String, bool),
    VersionNegotiated(String, u8),
    SendVersionAck(String, u8),
    InitiateHandshake(String),
    SendNoiseIdentityAnnouncement,
    SendTargetedNoiseIdentityAnnouncement(String), // target_peer_id
    CheckHandshakeNeeded(String, String), // (my_peer_id, other_peer_id)
    SendAnnounce,
    NoiseHandshakeInit(String, Packet), // peer_id, packet
    NoiseHandshakeResponse(String, Packet), // peer_id, packet
    SendHandshakeRequest(String), // target_peer_id
    NoiseEncrypted(String, Packet), // peer_id, packet
    SystemValidation(String, Packet), // peer_id, packet
}

#[async_trait]
impl BluetoothMeshDelegate for TuiMeshDelegate {
    async fn did_receive_message(&self, message: BitchatMessage) {
        let _ = self.app_sender.send(AppEvent::Message(message));
    }
    
    async fn did_connect_to_peer(&self, peer_id: String) {
        let _ = self.app_sender.send(AppEvent::PeerConnected(peer_id));
    }
    
    async fn did_disconnect_from_peer(&self, peer_id: String) {
        let _ = self.app_sender.send(AppEvent::PeerDisconnected(peer_id));
    }
    
    async fn did_update_peer_list(&self, peers: Vec<String>) {
        let _ = self.app_sender.send(AppEvent::PeerListUpdated(peers));
    }
    
    async fn did_receive_noise_handshake_init(&self, peer_id: String, packet: Packet) {
        info!("Received Noise handshake init from: {}", peer_id);
        let _ = self.app_sender.send(AppEvent::NoiseHandshakeInit(peer_id, packet));
    }
    
    async fn did_receive_noise_handshake_response(&self, peer_id: String, packet: Packet) {
        info!("Received Noise handshake response from: {}", peer_id);
        let _ = self.app_sender.send(AppEvent::NoiseHandshakeResponse(peer_id, packet));
    }
    
    async fn did_receive_noise_identity_announce(&self, peer_id: String, packet: Packet) {
        info!("Received Noise identity announce from: {} (payload: {} bytes)", peer_id, packet.payload.len());
    }
    
    async fn did_complete_noise_handshake(&self, peer_id: String) {
        let _ = self.app_sender.send(AppEvent::NoiseHandshakeComplete(peer_id));
    }
    
    async fn did_fail_noise_handshake(&self, peer_id: String, error: String) {
        let _ = self.app_sender.send(AppEvent::NoiseHandshakeFailed(peer_id, error));
    }
    
    async fn did_receive_noise_encrypted(&self, peer_id: String, packet: Packet) {
        info!("Received Noise encrypted message from: {}", peer_id);
        let _ = self.app_sender.send(AppEvent::NoiseEncrypted(peer_id, packet));
    }
    
    async fn did_receive_system_validation(&self, peer_id: String, packet: Packet) {
        info!("Received system validation from: {}", peer_id);
        // System validation is handled similarly to encrypted messages
        // Try to decrypt and send NACK if it fails
        let _ = self.app_sender.send(AppEvent::SystemValidation(peer_id, packet));
    }
    
    // Connection management
    async fn should_connect_to_peer(&self, peer_address: String) {
        let _ = self.app_sender.send(AppEvent::ConnectToPeer(peer_address));
    }
    
    // Message acknowledgments
    async fn did_receive_delivery_ack(&self, message_id: String, from_peer: String) {
        let _ = self.app_sender.send(AppEvent::DeliveryAck(message_id, from_peer));
    }
    
    async fn did_receive_read_receipt(&self, message_id: String, from_peer: String) {
        let _ = self.app_sender.send(AppEvent::ReadReceipt(message_id, from_peer));
    }
    
    // UI indicators
    async fn did_receive_typing_indicator(&self, peer_id: String, is_typing: bool) {
        let _ = self.app_sender.send(AppEvent::TypingIndicator(peer_id, is_typing));
    }
    
    // Channel key verification
    async fn did_receive_key_verify_request(&self, peer_id: String, key_hash: Vec<u8>) {
        info!("Key verification request from {}: {}", peer_id, hex::encode(&key_hash));
    }
    
    async fn did_receive_key_verify_response(&self, peer_id: String, verified: bool) {
        info!("Key verification response from {}: {}", peer_id, verified);
    }
    
    // Channel management
    async fn did_receive_password_update(&self, channel: String, password_hash: Vec<u8>, from_peer: String) {
        info!("Password update for channel {} from {}: {}", channel, from_peer, hex::encode(&password_hash));
    }
    
    async fn did_receive_channel_metadata(&self, channel: String, metadata: Vec<u8>, from_peer: String) {
        info!("Channel metadata for {} from {} ({} bytes)", channel, from_peer, metadata.len());
    }
    
    // Version negotiation
    async fn should_send_version_ack(&self, peer_id: String, peer_version: u8) {
        info!("Should send version ack to {} for version {}", peer_id, peer_version);
        let _ = self.app_sender.send(AppEvent::SendVersionAck(peer_id, peer_version));
    }
    
    async fn did_complete_version_negotiation(&self, peer_id: String, agreed_version: u8) {
        let _ = self.app_sender.send(AppEvent::VersionNegotiated(peer_id, agreed_version));
    }
    
    // Handshake management
    async fn should_initiate_noise_handshake(&self, peer_id: String) {
        info!("Should initiate noise handshake with {}", peer_id);
        let _ = self.app_sender.send(AppEvent::InitiateHandshake(peer_id));
    }
    
    async fn should_send_handshake_request(&self, target_peer_id: String) {
        info!("Should send handshake request to {}", target_peer_id);
        let _ = self.app_sender.send(AppEvent::SendHandshakeRequest(target_peer_id));
    }
    
    async fn should_send_noise_identity_announcement(&self) {
        info!("Should send noise identity announcement");
        let _ = self.app_sender.send(AppEvent::SendNoiseIdentityAnnouncement);
    }
    
    async fn should_send_targeted_noise_identity_announcement(&self, target_peer_id: String) {
        info!("Should send targeted noise identity announcement to {}", target_peer_id);
        let _ = self.app_sender.send(AppEvent::SendTargetedNoiseIdentityAnnouncement(target_peer_id));
    }
    
    async fn get_my_peer_id(&self) -> String {
        self.my_peer_id.read().await.clone().unwrap_or_else(|| {
            error!("Peer ID not set in delegate!");
            "unknown".to_string()
        })
    }
    
    async fn get_my_nickname(&self) -> String {
        self.my_nickname.read().await.clone()
    }
    
    async fn should_send_announce(&self) {
        info!("Delegate requesting to send announce");
        let _ = self.app_sender.send(AppEvent::SendAnnounce);
    }
}

impl TuiMeshDelegate {
    pub fn new(app_sender: mpsc::UnboundedSender<AppEvent>) -> Self {
        Self {
            app_sender,
            my_peer_id: Arc::new(RwLock::new(None)),
            my_nickname: Arc::new(RwLock::new("anonymous".to_string())),
            mesh_service: Arc::new(RwLock::new(None)),
        }
    }
    
    pub async fn set_peer_id(&self, peer_id: String) {
        *self.my_peer_id.write().await = Some(peer_id);
    }
    
    pub async fn set_nickname(&self, nickname: String) {
        *self.my_nickname.write().await = nickname;
    }
    
    pub async fn set_mesh_service(&self, service: Arc<BluetoothMeshService>) {
        *self.mesh_service.write().await = Some(service);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    
    // Setup terminal FIRST before any initialization
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    
    // Set panic handler to cleanup terminal
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        let _ = disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        original_hook(panic);
    }));
    
    // Load or create persistent state
    let mut app_state = AppState::load().unwrap_or_else(|e| {
        eprintln!("Warning: Failed to load state, using defaults: {}", e);
        AppState::default()
    });
    
    // Generate private key if we don't have one (for Noise identity)
    if app_state.private_key.is_none() {
        if let Err(e) = app_state.generate_new_identity() {
            eprintln!("Warning: Failed to generate private key: {}", e);
        }
    }
    
    // Create app state with loaded nickname
    let mut app = App::new_with_nickname(app_state.nickname.clone());
    app.transition_to_connecting();
    
    // Create event channels
    let (app_sender, mut app_receiver) = mpsc::unbounded_channel();
    
    // Create cancellation token for graceful shutdown
    let cancel_token = CancellationToken::new();
    
    // Initialize TUI logger (also writes to files)
    let tui_logger = init_tui_logger();
    
    info!("=== BitChat TUI Starting ===");
    info!("Log files: logs/info.log and logs/error.log");
    debug!("Debug logging enabled");
    
    // Create log event channel
    let (log_sender, mut log_receiver) = mpsc::unbounded_channel();
    
    // Set up log event forwarding
    let app_sender_for_logs = app_sender.clone();
    let cancel_token_logs = cancel_token.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_token_logs.cancelled() => {
                    break;
                }
                log_event = log_receiver.recv() => {
                    match log_event {
                        Some(LogEvent::Log(msg, level)) => {
                            let _ = app_sender_for_logs.send(AppEvent::Log(msg, level));
                        }
                        None => break,
                    }
                }
            }
        }
    });
    
    tui_logger.set_sender(log_sender);
    let mut event_handler = bitchat_rust::tui::event::EventHandler::new();
    
    // Create delegate with initial nickname
    let delegate = Arc::new(TuiMeshDelegate::new(app_sender.clone()));
    let delegate_clone = delegate.clone();
    
    // Set initial nickname in delegate
    delegate_clone.set_nickname(app_state.nickname.clone()).await;
    
    // Use peer ID override if set, otherwise generate a random one
    let peer_id_bytes = match app_state.get_peer_id_override_bytes() {
        Ok(Some(override_bytes)) => {
            info!("Using peer ID override from config");
            override_bytes
        }
        Ok(None) => {
            // Generate random peer ID for this session
            let mut random_id = [0u8; 8];
            getrandom::getrandom(&mut random_id).expect("Failed to generate random peer ID");
            info!("Generated random peer ID for this session: {}", hex::encode(&random_id));
            random_id
        }
        Err(e) => {
            eprintln!("Warning: Failed to parse peer ID override: {}", e);
            // Generate random peer ID as fallback
            let mut random_id = [0u8; 8];
            getrandom::getrandom(&mut random_id).expect("Failed to generate random peer ID");
            random_id
        }
    };
    
    // Initialize trust manager
    let trust_manager = match TrustManager::new() {
        Ok(tm) => Arc::new(tm),
        Err(e) => {
            error!("Failed to initialize trust manager: {}", e);
            Arc::new(TrustManager::new().expect("Failed to create default trust manager"))
        }
    };
    
    let mesh_service = match BluetoothMeshService::new(delegate).await {
        Ok(service) => {
            let service = service.with_peer_id(peer_id_bytes);
            app.add_popup_message("Bluetooth mesh service initialized".to_string());
            app.add_popup_message(format!("Peer ID: {}", service.get_peer_id_hex()));
            
            // Set the peer ID in the delegate
            delegate_clone.set_peer_id(service.get_peer_id_hex()).await;
            
            let service_arc = Arc::new(service);
            // Set the mesh service in the delegate
            delegate_clone.set_mesh_service(service_arc.clone()).await;
            
            service_arc
        }
        Err(e) => {
            app.transition_to_error(format!("Failed to initialize Bluetooth: {}", e));
            let _mesh_service: Arc<Mutex<Option<BluetoothMeshService>>> = Arc::new(Mutex::new(None));
            
            // Run UI loop even without Bluetooth
            terminal.draw(|f| bitchat_rust::tui::ui::render(&mut app, f))?;
            
            loop {
                if let Some(event) = event_handler.next().await {
                    if let Event::Key(key) = event {
                        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                            break;
                        }
                    }
                }
            }
            
            // Restore terminal
            disable_raw_mode()?;
            execute!(
                terminal.backend_mut(),
                LeaveAlternateScreen,
                DisableMouseCapture
            )?;
            terminal.show_cursor()?;
            
            return Ok(());
        }
    };
    
    // Start mesh service
    let mesh_service_clone = mesh_service.clone();
    let cancel_token_mesh = cancel_token.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = cancel_token_mesh.cancelled() => {
                info!("Mesh service start cancelled");
            }
            result = mesh_service_clone.start() => {
                if let Err(e) = result {
                    error!("Failed to start mesh service: {}", e);
                }
            }
        }
    });
    
    // Main event loop
    let mesh_service_for_run = mesh_service.clone();
    let delegate_for_run = delegate_clone.clone();
    let result = run_app(&mut terminal, &mut app, &mut event_handler, &mut app_receiver, app_sender, mesh_service_for_run, delegate_for_run, app_state, trust_manager, cancel_token.clone()).await;
    
    info!("Shutting down application...");
    
    // Cancel all spawned tasks
    cancel_token.cancel();
    
    // Stop mesh service first
    let _ = mesh_service.stop().await;
    
    // Give tasks a moment to clean up
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    
    // Restore terminal
    let _ = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    );
    let _ = terminal.show_cursor();
    
    // Drop everything explicitly
    drop(terminal);
    drop(mesh_service);
    drop(delegate_clone);
    
    // Force exit to ensure we don't hang
    std::process::exit(if result.is_ok() { 0 } else { 1 });
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    event_handler: &mut bitchat_rust::tui::event::EventHandler,
    app_receiver: &mut mpsc::UnboundedReceiver<AppEvent>,
    app_sender: mpsc::UnboundedSender<AppEvent>,
    mesh_service: Arc<BluetoothMeshService>,
    delegate: Arc<TuiMeshDelegate>,
    mut app_state: AppState,
    trust_manager: Arc<TrustManager>,
    cancel_token: CancellationToken,
) -> Result<()> {
    // Create a signal handler for graceful shutdown
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    
    loop {
        terminal.draw(|f| bitchat_rust::tui::ui::render(app, f))?;
        
        tokio::select! {
            // Handle SIGTERM
            _ = sigterm.recv() => {
                app.should_quit = true;
            }
            
            // Handle Ctrl+C
            _ = tokio::signal::ctrl_c() => {
                app.should_quit = true;
            }
            // Handle TUI events
            Some(event) = event_handler.next() => {
                match event {
                    Event::Key(key) => {
                        // Handle Ctrl+C globally
                        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                            app.should_quit = true;
                        }
                        
                        // Handle other keys based on focus area
                        match app.focus_area {
                            FocusArea::InputBox => {
                                match key.code {
                                    KeyCode::Enter => {
                                        let input = app.input.value().to_string();
                                        if !input.is_empty() {
                                            app.input.reset();
                                            
                                            // Check for commands
                                            if input.starts_with("/name ") {
                                                let new_name = input[6..].trim().to_string();
                                                if !new_name.is_empty() {
                                                    let old_name = app.nickname.clone();
                                                    app.nickname = new_name.clone();
                                                    
                                                    // Update persistent state
                                                    if let Err(e) = app_state.update_nickname(new_name.clone()) {
                                                        app.add_popup_message(format!("Warning: Failed to save nickname: {}", e));
                                                    }
                                                    
                                                    // Update delegate nickname and send new announce
                                                    let delegate_clone = delegate.clone();
                                                    let mesh_service_clone = mesh_service.clone();
                                                    let new_name_clone = new_name.clone();
                                                    tokio::spawn(async move {
                                                        delegate_clone.set_nickname(new_name_clone).await;
                                                        // Send announce with new nickname so other peers see the change
                                                        if let Err(e) = mesh_service_clone.send_announce().await {
                                                            error!("Failed to send announce after name change: {}", e);
                                                        }
                                                    });
                                                    
                                                    app.add_popup_message(format!("Name changed from '{}' to '{}'", old_name, new_name));
                                                } else {
                                                    app.add_popup_message("Usage: /name <new_name>".to_string());
                                                }
                                            } else if input.starts_with("/dm ") || input.starts_with("/m ") || input.starts_with("/msg ") {
                                                // Parse /dm|/m|/msg <nick> <message>
                                                let prefix_len = if input.starts_with("/dm ") { 4 } 
                                                    else if input.starts_with("/m ") { 3 }
                                                    else { 5 }; // "/msg "
                                                let parts: Vec<&str> = input[prefix_len..].splitn(2, ' ').collect();
                                                if parts.len() == 2 {
                                                    let recipient = parts[0].trim().to_string();
                                                    let message_content = parts[1].trim().to_string();
                                                    
                                                    if !recipient.is_empty() && !message_content.is_empty() {
                                                        let message = BitchatMessage {
                                                            id: uuid::Uuid::new_v4().to_string(),
                                                            sender: app.nickname.clone(),
                                                            content: message_content.clone(),
                                                            timestamp: chrono::Utc::now(),
                                                            channel: None,
                                                            is_private: true,
                                                            recipient_nickname: Some(recipient.clone()),
                                                            sender_peer_id: None,
                                                            mentions: None,
                                                            encrypted_content: None,
                                                            is_encrypted: false,
                                                            is_relay: false,
                                                            original_sender: None,
                                                        };
                                                        
                                                        // Check if recipient is trusted for showing checkmark
                                                        // Look up peer by nickname and check their fingerprint
                                                        let trust_manager = trust_manager.clone();
                                                        let mesh_service_for_trust = mesh_service.clone();
                                                        let recipient_for_check = recipient.clone();
                                                        let message_content_for_display = message_content.clone();
                                                        let is_trusted = tokio::task::block_in_place(|| {
                                                            tokio::runtime::Handle::current().block_on(async {
                                                                // Get peer by nickname
                                                                let peer_manager = mesh_service_for_trust.get_peer_manager();
                                                                if let Some(peer) = peer_manager.get_peer_by_nickname(&recipient_for_check).await {
                                                                    if let Some(static_key) = peer.static_public_key {
                                                                        // Calculate fingerprint and check if trusted
                                                                        let fingerprint = bitchat_rust::crypto::NoiseEncryptionService::calculate_fingerprint(&static_key);
                                                                        trust_manager.is_trusted(&fingerprint).await
                                                                    } else {
                                                                        false  // No static key available
                                                                    }
                                                                } else {
                                                                    false  // Peer not found
                                                                }
                                                            })
                                                        });
                                                        
                                                        app.add_sent_dm(recipient.clone(), message_content_for_display, true, is_trusted);  // true = encrypted
                                                        
                                                        let mesh_service = mesh_service.clone();
                                                        let app_sender_clone = app_sender.clone();
                                                        tokio::spawn(async move {
                                                            // Send private message using nickname lookup
                                                            match mesh_service.send_private_message_by_nickname(message, recipient.clone()).await {
                                                                Ok(_) => {
                                                                    info!("DM sent successfully to {}", recipient);
                                                                }
                                                                Err(e) => {
                                                                    error!("Failed to send DM to {}: {}", recipient, e);
                                                                    // Show error in UI
                                                                    let error_msg = format!("Failed to send DM: {}", e);
                                                                    let _ = app_sender_clone.send(AppEvent::Log(error_msg, log::Level::Error));
                                                                }
                                                            }
                                                        });
                                                    } else {
                                                        app.add_popup_message("Usage: /dm <nick> <message>".to_string());
                                                    }
                                                } else {
                                                    app.add_popup_message("Usage: /dm <nick> <message>".to_string());
                                                }
                                            } else if input == "/online" || input == "/w" {
                                                // Show online users
                                                if app.people.is_empty() {
                                                    app.add_popup_message("No users online".to_string());
                                                } else {
                                                    let online_msg = format!("Online users ({}): {}", app.people.len(), app.people.join(", "));
                                                    app.add_popup_message(online_msg);
                                                }
                                            } else if input == "/disconnect" {
                                                // Disconnect from Bluetooth mesh
                                                app.add_popup_message("Disconnecting from Bluetooth mesh...".to_string());
                                                let mesh_service = mesh_service.clone();
                                                tokio::spawn(async move {
                                                    if let Err(e) = mesh_service.stop().await {
                                                        error!("Failed to disconnect: {}", e);
                                                    }
                                                });
                                                app.transition_to_connecting();
                                                app.people.clear();
                                            } else if input == "/connect" {
                                                // Reconnect to Bluetooth mesh
                                                app.add_popup_message("Reconnecting to Bluetooth mesh...".to_string());
                                                app.transition_to_connecting();
                                                let mesh_service = mesh_service.clone();
                                                tokio::spawn(async move {
                                                    if let Err(e) = mesh_service.start().await {
                                                        error!("Failed to reconnect: {}", e);
                                                    }
                                                });
                                            } else if input.starts_with("/npeers") {
                                                // List all known peers
                                                let mesh_service = mesh_service.clone();
                                                let app_sender = app_sender.clone();
                                                
                                                tokio::spawn(async move {
                                                    let my_peer_id = mesh_service.get_peer_id_hex();
                                                    let mut peers_msg = format!("Our ID: {}\n", my_peer_id);
                                                    
                                                    // Get all peers from peer manager
                                                    let peer_manager = mesh_service.get_peer_manager();
                                                    let all_peers = peer_manager.get_all_peers().await;
                                                    
                                                    if all_peers.is_empty() {
                                                        peers_msg.push_str("No peers found");
                                                    } else {
                                                        peers_msg.push_str("\nPeers:\n");
                                                        for peer in all_peers {
                                                            let connected = if peer.is_connected { "🟢" } else { "🔴" };
                                                            let nickname = peer.nickname.as_deref().unwrap_or("unknown");
                                                            peers_msg.push_str(&format!("{} {} - {}\n", connected, peer.id, nickname));
                                                        }
                                                    }
                                                    
                                                    let _ = app_sender.send(AppEvent::CommandOutput(peers_msg));
                                                });
                                            } else if input.starts_with("/nstatus") {
                                                // Show Noise session status for a peer or all peers
                                                let parts: Vec<String> = input.split_whitespace().map(|s| s.to_string()).collect();
                                                let mesh_service = mesh_service.clone();
                                                let app_sender = app_sender.clone();
                                                
                                                tokio::spawn(async move {
                                                    let noise_service = mesh_service.get_encryption_service().get_noise_service();
                                                    let mut status_msg = String::new();
                                                    
                                                    if parts.len() > 1 {
                                                        let peer_prefix = &parts[1];
                                                        
                                                        // Find peer by prefix
                                                        let peer_manager = mesh_service.get_peer_manager();
                                                        let all_peers = peer_manager.get_all_peers().await;
                                                        let matching_peers: Vec<_> = all_peers.iter()
                                                            .filter(|p| p.id.starts_with(peer_prefix))
                                                            .collect();
                                                        
                                                        if matching_peers.is_empty() {
                                                            status_msg.push_str(&format!("❌ No peer found matching prefix: {}", peer_prefix));
                                                        } else if matching_peers.len() > 1 {
                                                            status_msg.push_str(&format!("⚠️ Multiple peers match prefix '{}':\n", peer_prefix));
                                                            for peer in matching_peers {
                                                                let nickname = peer.nickname.as_deref().unwrap_or("unknown");
                                                                status_msg.push_str(&format!("  {} - {}\n", peer.id, nickname));
                                                            }
                                                            status_msg.push_str("Please be more specific");
                                                        } else {
                                                            let peer = &matching_peers[0];
                                                            let peer_id = &peer.id;
                                                            let nickname = peer.nickname.as_deref().unwrap_or("unknown");
                                                            
                                                            status_msg.push_str(&format!("Target: {} ({})\n", peer_id, nickname));
                                                            
                                                            // Get detailed session info
                                                            if let Some(info) = noise_service.get_session_debug_info(peer_id).await {
                                                                status_msg.push_str(&info);
                                                            } else {
                                                                status_msg.push_str("❌ No session exists");
                                                            }
                                                        }
                                                    } else {
                                                        status_msg.push_str("Usage: /nstatus <peer_id_prefix> - Check specific peer");
                                                    }
                                                    
                                                    let _ = app_sender.send(AppEvent::CommandOutput(status_msg));
                                                });
                                            } else if input.starts_with("/nstart") {
                                                // Start automatic handshake with a peer
                                                let parts: Vec<String> = input.split_whitespace().map(|s| s.to_string()).collect();
                                                if parts.len() > 1 {
                                                    let peer_prefix = parts[1].clone();
                                                    let mesh_service = mesh_service.clone();
                                                    let app_sender = app_sender.clone();
                                                    
                                                    tokio::spawn(async move {
                                                        // Find peer by prefix
                                                        let peer_manager = mesh_service.get_peer_manager();
                                                        let all_peers = peer_manager.get_all_peers().await;
                                                        let matching_peers: Vec<_> = all_peers.iter()
                                                            .filter(|p| p.id.starts_with(&peer_prefix))
                                                            .collect();
                                                        
                                                        if matching_peers.is_empty() {
                                                            let _ = app_sender.send(AppEvent::Log(
                                                                format!("❌ No peer found matching prefix: {}", peer_prefix),
                                                                log::Level::Error
                                                            ));
                                                        } else if matching_peers.len() > 1 {
                                                            let mut msg = format!("⚠️ Multiple peers match prefix '{}':\n", peer_prefix);
                                                            for peer in matching_peers {
                                                                let nickname = peer.nickname.as_deref().unwrap_or("unknown");
                                                                msg.push_str(&format!("  {} - {}\n", peer.id, nickname));
                                                            }
                                                            msg.push_str("Please be more specific");
                                                            let _ = app_sender.send(AppEvent::Log(msg, log::Level::Warn));
                                                        } else {
                                                            let peer_id = matching_peers[0].id.clone();
                                                            info!("Starting automatic handshake with {}", peer_id);
                                                            
                                                            // Send handshake request (will check who should initiate)
                                                            if let Err(e) = mesh_service.send_handshake_request(peer_id.clone()).await {
                                                                error!("Failed to send handshake request: {}", e);
                                                                let _ = app_sender.send(AppEvent::Log(
                                                                    format!("Failed to start handshake with {}: {}", peer_id, e),
                                                                    log::Level::Error
                                                                ));
                                                            } else {
                                                                let _ = app_sender.send(AppEvent::CommandOutput(
                                                                    format!("Sent handshake request to {}", peer_id)
                                                                ));
                                                            }
                                                        }
                                                    });
                                                } else {
                                                    app.add_popup_message("Usage: /nstart <peer_id_prefix>".to_string());
                                                }
                                            } else if input.starts_with("/ninit") {
                                                // Force initiate handshake as initiator
                                                let parts: Vec<String> = input.split_whitespace().map(|s| s.to_string()).collect();
                                                if parts.len() > 1 {
                                                    let peer_prefix = parts[1].clone();
                                                    let mesh_service = mesh_service.clone();
                                                    let app_sender = app_sender.clone();
                                                    
                                                    tokio::spawn(async move {
                                                        // Resolve peer ID from prefix
                                                        match resolve_peer_id(&mesh_service, &peer_prefix).await {
                                                            Ok(peer_id) => {
                                                                info!("Forcing handshake initiation with {}", peer_id);
                                                                
                                                                // Clear any existing session first
                                                                let noise_service = mesh_service.get_encryption_service().get_noise_service();
                                                                noise_service.clear_session(&peer_id).await;
                                                                
                                                                // Initiate handshake
                                                                if let Err(e) = mesh_service.initiate_noise_handshake(peer_id.clone()).await {
                                                                    error!("Failed to initiate handshake: {}", e);
                                                                    let _ = app_sender.send(AppEvent::Log(
                                                                        format!("Failed to initiate handshake with {}: {}", peer_id, e),
                                                                        log::Level::Error
                                                                    ));
                                                                } else {
                                                                    let _ = app_sender.send(AppEvent::CommandOutput(
                                                                        format!("Initiated handshake with {} (as initiator)", peer_id)
                                                                    ));
                                                                }
                                                            }
                                                            Err(msg) => {
                                                                let _ = app_sender.send(AppEvent::Log(msg, log::Level::Error));
                                                            }
                                                        }
                                                    });
                                                } else {
                                                    app.add_popup_message("Usage: /ninit <peer_id_prefix>".to_string());
                                                }
                                            } else if input.starts_with("/nrespond") {
                                                // Send identity announcement to trigger handshake response
                                                let parts: Vec<String> = input.split_whitespace().map(|s| s.to_string()).collect();
                                                if parts.len() > 1 {
                                                    let peer_prefix = parts[1].clone();
                                                    let mesh_service = mesh_service.clone();
                                                    let app_sender = app_sender.clone();
                                                    
                                                    tokio::spawn(async move {
                                                        // Resolve peer ID from prefix
                                                        match resolve_peer_id(&mesh_service, &peer_prefix).await {
                                                            Ok(peer_id) => {
                                                                info!("Sending identity announcement to {} to trigger response", peer_id);
                                                                
                                                                // Send targeted identity announcement
                                                                if let Err(e) = mesh_service.send_noise_identity_announcement_to(Some(peer_id.clone())).await {
                                                                    error!("Failed to send identity announcement: {}", e);
                                                                    let _ = app_sender.send(AppEvent::Log(
                                                                        format!("Failed to send identity announcement to {}: {}", peer_id, e),
                                                                        log::Level::Error
                                                                    ));
                                                                } else {
                                                                    let _ = app_sender.send(AppEvent::Log(
                                                                        format!("Sent identity announcement to {} (they should initiate)", peer_id),
                                                                        log::Level::Info
                                                                    ));
                                                                }
                                                            }
                                                            Err(msg) => {
                                                                let _ = app_sender.send(AppEvent::Log(msg, log::Level::Error));
                                                            }
                                                        }
                                                    });
                                                } else {
                                                    app.add_popup_message("Usage: /nrespond <peer_id_prefix>".to_string());
                                                }
                                            } else if input.starts_with("/ninfo") {
                                                // Show detailed Noise info for debugging
                                                let mesh_service = mesh_service.clone();
                                                let app_sender = app_sender.clone();
                                                
                                                tokio::spawn(async move {
                                                    let my_peer_id = mesh_service.get_peer_id_hex();
                                                    let noise_service = mesh_service.get_encryption_service().get_noise_service();
                                                    
                                                    let mut info_msg = format!("=== Noise Protocol Debug Info ===\n");
                                                    info_msg.push_str(&format!("My Peer ID: {}\n", my_peer_id));
                                                    info_msg.push_str(&format!("My Public Key: {:?}\n", 
                                                        hex::encode(mesh_service.get_encryption_service().get_noise_service().get_static_public_key())));
                                                    
                                                    // TODO: Add method to get all sessions from noise service
                                                    info_msg.push_str("\nUse /nstatus <peer_id> to check specific peer sessions");
                                                    
                                                    let _ = app_sender.send(AppEvent::CommandOutput(info_msg));
                                                });
                                            } else if input.starts_with("/nclear") {
                                                // Clear session with a peer
                                                let parts: Vec<String> = input.split_whitespace().map(|s| s.to_string()).collect();
                                                if parts.len() > 1 {
                                                    let peer_prefix = parts[1].clone();
                                                    let mesh_service = mesh_service.clone();
                                                    let app_sender = app_sender.clone();
                                                    
                                                    tokio::spawn(async move {
                                                        // Resolve peer ID from prefix
                                                        match resolve_peer_id(&mesh_service, &peer_prefix).await {
                                                            Ok(peer_id) => {
                                                                info!("Clearing session with {}", peer_id);
                                                                
                                                                let noise_service = mesh_service.get_encryption_service().get_noise_service();
                                                                noise_service.clear_session(&peer_id).await;
                                                                
                                                                let _ = app_sender.send(AppEvent::CommandOutput(
                                                                    format!("Cleared session with {}", peer_id)
                                                                ));
                                                            }
                                                            Err(msg) => {
                                                                let _ = app_sender.send(AppEvent::Log(msg, log::Level::Error));
                                                            }
                                                        }
                                                    });
                                                } else {
                                                    app.add_popup_message("Usage: /nclear <peer_id_prefix>".to_string());
                                                }
                                            } else if input.starts_with("/trust ") {
                                                // Trust a peer by nickname
                                                let parts: Vec<String> = input.split_whitespace().map(|s| s.to_string()).collect();
                                                if parts.len() > 1 {
                                                    let nickname = parts[1].clone();
                                                    let mesh_service = mesh_service.clone();
                                                    let trust_manager = trust_manager.clone();
                                                    let app_sender = app_sender.clone();
                                                    
                                                    tokio::spawn(async move {
                                                        // Find peer by nickname
                                                        let peer_manager = mesh_service.get_peer_manager();
                                                        let peer = peer_manager.get_peer_by_nickname(&nickname).await;
                                                        
                                                        if let Some(peer) = peer {
                                                            if let Some(ref static_key) = peer.static_public_key {
                                                                let fingerprint = bitchat_rust::crypto::NoiseEncryptionService::calculate_fingerprint(static_key);
                                                                
                                                                // Trust the peer
                                                                if let Err(e) = trust_manager.trust_peer(
                                                                    fingerprint.clone(),
                                                                    Some(nickname.clone()),
                                                                    Some(peer.id.clone())
                                                                ).await {
                                                                    let _ = app_sender.send(AppEvent::Log(
                                                                        format!("Failed to trust {}: {}", nickname, e),
                                                                        log::Level::Error
                                                                    ));
                                                                } else {
                                                                    // Format the full fingerprint for display
                                                                    let formatted = bitchat_rust::crypto::NoiseEncryptionService::format_fingerprint(&fingerprint);
                                                                    let _ = app_sender.send(AppEvent::CommandOutput(
                                                                        format!("✅ Trusted {}\nFingerprint:\n{}", 
                                                                            nickname, formatted)
                                                                    ));
                                                                }
                                                            } else {
                                                                let _ = app_sender.send(AppEvent::Log(
                                                                    format!("❌ No public key available for {}", nickname),
                                                                    log::Level::Error
                                                                ));
                                                            }
                                                        } else {
                                                            let _ = app_sender.send(AppEvent::Log(
                                                                format!("❌ No peer found with nickname: {}", nickname),
                                                                log::Level::Error
                                                            ));
                                                        }
                                                    });
                                                } else {
                                                    app.add_popup_message("Usage: /trust <nickname>".to_string());
                                                }
                                            } else if input.starts_with("/fingerprint") || input.starts_with("/fp") {
                                                // Show fingerprint for a peer or self
                                                let parts: Vec<String> = input.split_whitespace().map(|s| s.to_string()).collect();
                                                let mesh_service = mesh_service.clone();
                                                let trust_manager = trust_manager.clone();
                                                let app_sender = app_sender.clone();
                                                
                                                tokio::spawn(async move {
                                                    if parts.len() > 1 {
                                                        // Show fingerprint for specific peer
                                                        let nickname = &parts[1];
                                                        let peer_manager = mesh_service.get_peer_manager();
                                                        let peer = peer_manager.get_peer_by_nickname(nickname).await;
                                                        
                                                        if let Some(peer) = peer {
                                                            if let Some(ref static_key) = peer.static_public_key {
                                                                let fingerprint = bitchat_rust::crypto::NoiseEncryptionService::calculate_fingerprint(static_key);
                                                                let formatted = bitchat_rust::crypto::NoiseEncryptionService::format_fingerprint(&fingerprint);
                                                                
                                                                let trust_status = if trust_manager.is_trusted(&fingerprint).await {
                                                                    "✅ TRUSTED"
                                                                } else {
                                                                    "❌ NOT TRUSTED"
                                                                };
                                                                
                                                                let msg = format!("Fingerprint for {} ({}):\n{}\n{}", 
                                                                    nickname, peer.id, formatted, trust_status);
                                                                let _ = app_sender.send(AppEvent::CommandOutput(msg));
                                                            } else {
                                                                // Debug: show what we know about this peer
                                                                let debug_info = format!(
                                                                    "Peer ID: {}\nNickname: {:?}\nFingerprint stored: {:?}\nStatic key: None",
                                                                    peer.id, peer.nickname, peer.fingerprint
                                                                );
                                                                let _ = app_sender.send(AppEvent::Log(
                                                                    format!("❌ No public key available for {}\nDebug info:\n{}", nickname, debug_info),
                                                                    log::Level::Error
                                                                ));
                                                            }
                                                        } else {
                                                            let _ = app_sender.send(AppEvent::Log(
                                                                format!("❌ No peer found with nickname: {}", nickname),
                                                                log::Level::Error
                                                            ));
                                                        }
                                                    } else {
                                                        // Show all known peers and our own fingerprint
                                                        let peer_manager = mesh_service.get_peer_manager();
                                                        let all_peers = peer_manager.get_all_peers().await;
                                                        
                                                        // First show our own fingerprint
                                                        let noise_service = mesh_service.get_encryption_service().get_noise_service();
                                                        let fingerprint = noise_service.get_fingerprint();
                                                        let formatted = bitchat_rust::crypto::NoiseEncryptionService::format_fingerprint(&fingerprint);
                                                        
                                                        // Send header
                                                        let _ = app_sender.send(AppEvent::CommandOutput(
                                                            "=== Your fingerprint ===".to_string()
                                                        ));
                                                        let _ = app_sender.send(AppEvent::CommandOutput(
                                                            formatted
                                                        ));
                                                        let _ = app_sender.send(AppEvent::CommandOutput(
                                                            "".to_string()
                                                        ));
                                                        let _ = app_sender.send(AppEvent::CommandOutput(
                                                            "=== Known Peers ===".to_string()
                                                        ));
                                                        
                                                        if all_peers.is_empty() {
                                                            let _ = app_sender.send(AppEvent::CommandOutput(
                                                                "No peers connected".to_string()
                                                            ));
                                                        } else {
                                                            for peer in all_peers {
                                                                // Check trust status if we have the static key
                                                                let trust_status = if let Some(ref key) = peer.static_public_key {
                                                                    let fp = bitchat_rust::crypto::NoiseEncryptionService::calculate_fingerprint(key);
                                                                    if trust_manager.is_trusted(&fp).await {
                                                                        "✅ TRUSTED"
                                                                    } else {
                                                                        "❌ NOT TRUSTED"
                                                                    }
                                                                } else {
                                                                    "⚠️ NO KEY"
                                                                };
                                                                
                                                                // Send each peer info as separate messages
                                                                let _ = app_sender.send(AppEvent::CommandOutput(
                                                                    format!("Peer: {} ({}) {}", 
                                                                        peer.nickname.as_deref().unwrap_or("no-nickname"),
                                                                        peer.id,
                                                                        trust_status
                                                                    )
                                                                ));
                                                                let _ = app_sender.send(AppEvent::CommandOutput(
                                                                    format!("  Connected: {}", peer.is_connected)
                                                                ));
                                                                let _ = app_sender.send(AppEvent::CommandOutput(
                                                                    format!("  Static key: {}", 
                                                                        if peer.static_public_key.is_some() { "Present" } else { "None" }
                                                                    )
                                                                ));
                                                                
                                                                // If we have the static key, show the formatted fingerprint
                                                                if let Some(ref key) = peer.static_public_key {
                                                                    let fp = bitchat_rust::crypto::NoiseEncryptionService::calculate_fingerprint(key);
                                                                    let formatted = bitchat_rust::crypto::NoiseEncryptionService::format_fingerprint(&fp);
                                                                    let _ = app_sender.send(AppEvent::CommandOutput(
                                                                        format!("  Fingerprint:\n    {}", formatted.replace("\n", "\n    "))
                                                                    ));
                                                                } else {
                                                                    let _ = app_sender.send(AppEvent::CommandOutput(
                                                                        "  Fingerprint: None".to_string()
                                                                    ));
                                                                }
                                                                
                                                                // Add blank line between peers
                                                                let _ = app_sender.send(AppEvent::CommandOutput(
                                                                    "".to_string()
                                                                ));
                                                            }
                                                        }
                                                    }
                                                });
                                            } else if input.starts_with("/plain ") {
                                                // Send unencrypted message to a peer
                                                let parts: Vec<&str> = input.split_whitespace().collect();
                                                if parts.len() < 3 {
                                                    app.add_popup_message("Usage: /plain <nickname> <message>".to_string());
                                                } else {
                                                    let nickname = parts[1].to_string();
                                                    let message = parts[2..].join(" ");
                                                    
                                                    // Add to sent messages display (no checkmark for unencrypted)
                                                    app.add_sent_dm(nickname.clone(), format!("[PLAIN] {}", message.clone()), false, false);  // false = unencrypted, false = no checkmark
                                                    
                                                    let mesh_service = mesh_service.clone();
                                                    let app_sender = app_sender.clone();
                                                    let my_nickname = app.nickname.clone();
                                                    
                                                    tokio::spawn(async move {
                                                        // Find peer by nickname
                                                        let peer_manager = mesh_service.get_peer_manager();
                                                        if let Some(peer) = peer_manager.get_peer_by_nickname(&nickname).await {
                                                            // Create a plain text message
                                                            // Mark it with [PLAIN] so receiver knows it's unencrypted
                                                            let plain_content = format!("[PLAIN/UNENCRYPTED] {}", message);
                                                            
                                                            // Create BitchatMessage using constructor
                                                            let mut msg = BitchatMessage::new(
                                                                my_nickname.clone(),
                                                                plain_content.clone(),
                                                                chrono::Utc::now()
                                                            );
                                                            msg.is_private = true;
                                                            msg.recipient_nickname = Some(nickname.clone());
                                                            
                                                            // Convert peer ID to bytes for recipient
                                                            if let Ok(peer_id_bytes) = hex::decode(&peer.id) {
                                                                if peer_id_bytes.len() == 8 {
                                                                    let mut recipient_id = [0u8; 8];
                                                                    recipient_id.copy_from_slice(&peer_id_bytes);
                                                                    
                                                                    // Create an unencrypted packet directly
                                                                    let msg_data = match msg.to_binary_payload() {
                                                                        Ok(data) => data,
                                                                        Err(e) => {
                                                                            let _ = app_sender.send(AppEvent::Log(
                                                                                format!("Failed to encode message: {}", e),
                                                                                log::Level::Error
                                                                            ));
                                                                            return;
                                                                        }
                                                                    };
                                                                    let packet = Packet::new(
                                                                        MessageType::Message,
                                                                        mesh_service.get_peer_id(),
                                                                        msg_data
                                                                    ).with_recipient(recipient_id);
                                                                    
                                                                    // Use mesh_service's internal broadcast_packet method
                                                                    // This properly routes through the mesh network
                                                                    use bitchat_rust::protocol::BinaryProtocol;
                                                                    let packet_data = match BinaryProtocol::encode(&packet) {
                                                                        Ok(data) => data,
                                                                        Err(e) => {
                                                                            let _ = app_sender.send(AppEvent::Log(
                                                                                format!("Failed to encode packet: {}", e),
                                                                                log::Level::Error
                                                                            ));
                                                                            return;
                                                                        }
                                                                    };
                                                                    
                                                                    // Send to all connected peers
                                                                    let conn_mgr = mesh_service.get_connection_manager();
                                                                    let addresses = conn_mgr.get_connected_addresses().await;
                                                                    let has_centrals = conn_mgr.has_subscribed_centrals().await;
                                                                    
                                                                    let mut sent = false;
                                                                    
                                                                    // Send to connected peripherals
                                                                    for address in &addresses {
                                                                        if let Ok(_) = conn_mgr.send_data(address, &packet_data).await {
                                                                            sent = true;
                                                                            debug!("Sent plain message to peripheral: {}", address);
                                                                        }
                                                                    }
                                                                    
                                                                    // Send to subscribed centrals via notification
                                                                    if has_centrals {
                                                                        if let Ok(_) = conn_mgr.send_notification(&packet_data).await {
                                                                            sent = true;
                                                                            debug!("Sent plain message notification to centrals");
                                                                        }
                                                                    }
                                                                    
                                                                    if sent {
                                                                        let _ = app_sender.send(AppEvent::Log(
                                                                            format!("✓ Sent PLAIN (unencrypted) message to {}: {}", nickname, message),
                                                                            log::Level::Info
                                                                        ));
                                                                    } else {
                                                                        let _ = app_sender.send(AppEvent::Log(
                                                                            format!("Failed to send plain message - no connected peers", ),
                                                                            log::Level::Error
                                                                        ));
                                                                    }
                                                                } else {
                                                                    let _ = app_sender.send(AppEvent::Log(
                                                                        format!("Invalid peer ID length for {}", nickname),
                                                                        log::Level::Error
                                                                    ));
                                                                }
                                                            } else {
                                                                let _ = app_sender.send(AppEvent::Log(
                                                                    format!("Failed to decode peer ID for {}", nickname),
                                                                    log::Level::Error
                                                                ));
                                                            }
                                                        } else {
                                                            let _ = app_sender.send(AppEvent::Log(
                                                                format!("Peer '{}' not found", nickname),
                                                                log::Level::Error
                                                            ));
                                                        }
                                                    });
                                                }
                                            } else if input.starts_with("/nkeys") {
                                                // Debug: show all keys stored in noise service
                                                let mesh_service = mesh_service.clone();
                                                let app_sender = app_sender.clone();
                                                
                                                tokio::spawn(async move {
                                                    let noise_service = mesh_service.get_encryption_service().get_noise_service();
                                                    let peer_manager = mesh_service.get_peer_manager();
                                                    let all_peers = peer_manager.get_all_peers().await;
                                                    
                                                    // Send header
                                                    let _ = app_sender.send(AppEvent::CommandOutput(
                                                        "=== Noise Service Key Storage ===".to_string()
                                                    ));
                                                    
                                                    for peer in all_peers {
                                                        let _ = app_sender.send(AppEvent::CommandOutput(
                                                            format!("Peer: {} ({})", 
                                                                peer.nickname.as_deref().unwrap_or("no-nickname"),
                                                                peer.id
                                                            )
                                                        ));
                                                        
                                                        // Check if noise service has key for this peer
                                                        if let Some(key) = noise_service.get_peer_static_key(&peer.id).await {
                                                            let fp = bitchat_rust::crypto::NoiseEncryptionService::calculate_fingerprint(&key);
                                                            let _ = app_sender.send(AppEvent::CommandOutput(
                                                                format!("  Noise service has key: {} bytes, FP: {}...", 
                                                                    key.len(), &fp[..16])
                                                            ));
                                                        } else {
                                                            let _ = app_sender.send(AppEvent::CommandOutput(
                                                                "  Noise service has NO key".to_string()
                                                            ));
                                                        }
                                                        
                                                        // Check if peer manager has key
                                                        if peer.static_public_key.is_some() {
                                                            let _ = app_sender.send(AppEvent::CommandOutput(
                                                                "  Peer manager has key: Yes".to_string()
                                                            ));
                                                        } else {
                                                            let _ = app_sender.send(AppEvent::CommandOutput(
                                                                "  Peer manager has key: No".to_string()
                                                            ));
                                                        }
                                                        
                                                        // Add blank line between peers
                                                        let _ = app_sender.send(AppEvent::CommandOutput(
                                                            "".to_string()
                                                        ));
                                                    }
                                                });
                                            } else if input.starts_with("/untrust ") {
                                                // Remove trust for a peer
                                                let parts: Vec<String> = input.split_whitespace().map(|s| s.to_string()).collect();
                                                if parts.len() > 1 {
                                                    let nickname = parts[1].clone();
                                                    let trust_manager = trust_manager.clone();
                                                    let app_sender = app_sender.clone();
                                                    
                                                    tokio::spawn(async move {
                                                        if trust_manager.untrust_peer(&nickname).await.unwrap_or(false) {
                                                            let _ = app_sender.send(AppEvent::CommandOutput(
                                                                format!("❌ Removed trust for {}", nickname)
                                                            ));
                                                        } else {
                                                            let _ = app_sender.send(AppEvent::CommandOutput(
                                                                format!("⚠️ {} was not trusted", nickname)
                                                            ));
                                                        }
                                                    });
                                                } else {
                                                    app.add_popup_message("Usage: /untrust <nickname>".to_string());
                                                }
                                            } else if input == "/debug" {
                                                // Toggle debug mode
                                                app.debug_mode = !app.debug_mode;
                                                let status = if app.debug_mode { "ON" } else { "OFF" };
                                                app.add_popup_message(format!("Debug mode: {}", status));
                                                app.add_popup_message(if app.debug_mode {
                                                    "Now showing INFO, WARN, and ERROR messages".to_string()
                                                } else {
                                                    "Now showing only WARN and ERROR messages".to_string()
                                                });
                                            } else if input == "/help" {
                                                // Show help
                                                app.add_popup_message("Available commands:".to_string());
                                                app.add_popup_message("/name <nickname> - Change your nickname".to_string());
                                                app.add_popup_message("/dm <user> <message> - Send a direct message (also: /m, /msg)".to_string());
                                                app.add_popup_message("/online - Show online users (also: /w)".to_string());
                                                app.add_popup_message("/connect - Reconnect to Bluetooth mesh".to_string());
                                                app.add_popup_message("/disconnect - Disconnect from Bluetooth mesh".to_string());
                                                app.add_popup_message("/debug - Toggle debug mode (show/hide INFO messages)".to_string());
                                                app.add_popup_message("-- Trust Commands --".to_string());
                                                app.add_popup_message("/trust <nickname> - Trust a user".to_string());
                                                app.add_popup_message("/untrust <nickname> - Remove trust".to_string());
                                                app.add_popup_message("/fingerprint [nickname] - Show fingerprint (also: /fp)".to_string());
                                                app.add_popup_message("-- Noise Debug Commands --".to_string());
                                                app.add_popup_message("/npeers - List all known peers".to_string());
                                                app.add_popup_message("/nstatus <peer_prefix> - Show Noise session status".to_string());
                                                app.add_popup_message("/ninfo - Show detailed Noise debug info".to_string());
                                                app.add_popup_message("/nstart <peer_prefix> - Start automatic handshake".to_string());
                                                app.add_popup_message("/ninit <peer_prefix> - Force initiate handshake (as initiator)".to_string());
                                                app.add_popup_message("/nrespond <peer_prefix> - Send identity announcement (as responder)".to_string());
                                                app.add_popup_message("/nclear <peer_prefix> - Clear existing session".to_string());
                                                app.add_popup_message("/help - Show this help".to_string());
                                            } else if input.starts_with('/') {
                                                // Unknown command
                                                app.add_popup_message(format!("Command not found: {}", input));
                                            } else {
                                                // Regular message
                                                let message = BitchatMessage {
                                                    id: uuid::Uuid::new_v4().to_string(),
                                                    sender: app.nickname.clone(),
                                                    content: input.clone(),
                                                    timestamp: chrono::Utc::now(),
                                                    channel: Some(app.get_selected_channel_name()),
                                                    is_private: false,
                                                    recipient_nickname: None,
                                                    sender_peer_id: None,
                                                    mentions: None,
                                                    encrypted_content: None,
                                                    is_encrypted: false,
                                                    is_relay: false,
                                                    original_sender: None,
                                                };
                                                
                                                app.add_sent_message(input);
                                                
                                                let mesh_service = mesh_service.clone();
                                                tokio::spawn(async move {
                                                    if let Err(e) = mesh_service.send_message(message).await {
                                                        error!("Failed to send message: {}", e);
                                                    }
                                                });
                                            }
                                        }
                                    }
                                    KeyCode::Tab => {
                                        app.focus_area = FocusArea::Sidebar;
                                    }
                                    _ => {
                                        app.input.handle_event(&crossterm::event::Event::Key(key));
                                    }
                                }
                            }
                            FocusArea::Sidebar => {
                                match key.code {
                                    KeyCode::Tab => {
                                        app.focus_area = FocusArea::MainPanel;
                                    }
                                    KeyCode::Up => {
                                        if app.sidebar_flat_selected > 0 {
                                            app.sidebar_flat_selected -= 1;
                                        }
                                    }
                                    KeyCode::Down => {
                                        app.sidebar_flat_selected += 1;
                                    }
                                    KeyCode::Enter => {
                                        // Handle sidebar selection
                                        // TODO: Implement sidebar selection logic
                                    }
                                    _ => {}
                                }
                            }
                            FocusArea::MainPanel => {
                                match key.code {
                                    KeyCode::Tab => {
                                        app.focus_area = FocusArea::InputBox;
                                    }
                                    KeyCode::Up => {
                                        // Scroll up (view older messages)
                                        let (messages, _, _) = app.get_current_messages();
                                        let max_scroll = messages.len().saturating_sub(app.message_viewport_height);
                                        app.msg_scroll = (app.msg_scroll + 1).min(max_scroll);
                                    }
                                    KeyCode::Down => {
                                        // Scroll down (view newer messages)
                                        app.msg_scroll = app.msg_scroll.saturating_sub(1);
                                    }
                                    KeyCode::PageUp => {
                                        // Scroll up by a page
                                        let (messages, _, _) = app.get_current_messages();
                                        let max_scroll = messages.len().saturating_sub(app.message_viewport_height);
                                        let page_size = app.message_viewport_height.saturating_sub(1);
                                        app.msg_scroll = (app.msg_scroll + page_size).min(max_scroll);
                                    }
                                    KeyCode::PageDown => {
                                        // Scroll down by a page
                                        let page_size = app.message_viewport_height.saturating_sub(1);
                                        app.msg_scroll = app.msg_scroll.saturating_sub(page_size);
                                    }
                                    KeyCode::Home => {
                                        // Scroll to the very top (oldest messages)
                                        let (messages, _, _) = app.get_current_messages();
                                        let max_scroll = messages.len().saturating_sub(app.message_viewport_height);
                                        app.msg_scroll = max_scroll;
                                    }
                                    KeyCode::End => {
                                        // Scroll to the bottom (newest messages)
                                        app.msg_scroll = 0;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    Event::Tick => {
                        // Handle periodic updates if needed
                    }
                    Event::Resize => {
                        // Terminal was resized, redraw will happen automatically
                    }
                }
            }
            
            // Handle mesh events
            Some(event) = app_receiver.recv() => {
                match event {
                    AppEvent::Message(message) => {
                        // Check if this is a WiFi request
                        if message.is_private && message.is_encrypted && message.content.trim().eq_ignore_ascii_case("wifi?") {
                            // Handle WiFi request
                            let sender_nickname = message.sender.clone();
                            let sender_peer_id = message.sender_peer_id.clone();
                            let mesh_service_clone = mesh_service.clone();
                            let app_sender_clone = app_sender.clone();
                            let mut app_state_clone = app_state.clone();
                            
                            tokio::spawn(async move {
                                // Ensure we have a WiFi secret salt
                                if let Err(e) = app_state_clone.ensure_wifi_secret_salt() {
                                    error!("Failed to ensure WiFi secret salt: {}", e);
                                    return;
                                }
                                
                                // Get the peer's static key to calculate fingerprint
                                if let Some(peer_id) = sender_peer_id {
                                    let peer_manager = mesh_service_clone.get_peer_manager();
                                    if let Some(peer) = peer_manager.get_peer(&peer_id).await {
                                        if let Some(static_key) = peer.static_public_key {
                                            // Calculate fingerprint
                                            let fingerprint = bitchat_rust::crypto::NoiseEncryptionService::calculate_fingerprint(&static_key);
                                            
                                            // Get WiFi secret salt
                                            match app_state_clone.get_wifi_secret_salt_bytes() {
                                                Ok(salt) => {
                                                    // Handle WiFi request
                                                    match bitchat_rust::wifi::handle_wifi_request(&salt, &fingerprint, &sender_nickname).await {
                                                        Ok(response) => {
                                                            // Send response back to the requester
                                                            let response_msg = BitchatMessage {
                                                                id: uuid::Uuid::new_v4().to_string(),
                                                                sender: "system".to_string(),
                                                                content: response,
                                                                timestamp: chrono::Utc::now(),
                                                                channel: None,
                                                                is_private: true,
                                                                recipient_nickname: Some(sender_nickname.clone()),
                                                                sender_peer_id: None,
                                                                mentions: None,
                                                                encrypted_content: None,
                                                                is_encrypted: false,
                                                                is_relay: false,
                                                                original_sender: None,
                                                            };
                                                            
                                                            if let Err(e) = mesh_service_clone.send_private_message_by_nickname(response_msg, sender_nickname.clone()).await {
                                                                error!("Failed to send WiFi response to {}: {}", sender_nickname, e);
                                                            }
                                                        }
                                                        Err(e) => {
                                                            // Send error response
                                                            let error_msg = BitchatMessage {
                                                                id: uuid::Uuid::new_v4().to_string(),
                                                                sender: "system".to_string(),
                                                                content: format!("❌ WiFi request failed: {}", e),
                                                                timestamp: chrono::Utc::now(),
                                                                channel: None,
                                                                is_private: true,
                                                                recipient_nickname: Some(sender_nickname.clone()),
                                                                sender_peer_id: None,
                                                                mentions: None,
                                                                encrypted_content: None,
                                                                is_encrypted: false,
                                                                is_relay: false,
                                                                original_sender: None,
                                                            };
                                                            
                                                            if let Err(e) = mesh_service_clone.send_private_message_by_nickname(error_msg, sender_nickname.clone()).await {
                                                                error!("Failed to send WiFi error to {}: {}", sender_nickname, e);
                                                            }
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("Failed to get WiFi secret salt: {}", e);
                                                }
                                            }
                                        } else {
                                            warn!("No static key available for peer {}", sender_nickname);
                                        }
                                    }
                                }
                            });
                            
                            // Still show the request in the UI
                            app.add_received_message(
                                message.sender.clone(),
                                "wifi? (request processing...)".to_string(),
                                message.channel,
                                message.is_private,
                                message.recipient_nickname,
                                false,
                            );
                        } else {
                            // Normal message handling
                            // Only show trust checkmark for private/encrypted messages, not public broadcasts
                            let is_trusted = if message.is_private && message.is_encrypted {
                                // Check trust based on peer's actual public key fingerprint, not nickname
                                if let Some(ref peer_id) = message.sender_peer_id {
                                    let peer_manager = mesh_service.get_peer_manager();
                                    tokio::task::block_in_place(|| {
                                        tokio::runtime::Handle::current().block_on(async {
                                            // Get peer's static key
                                            if let Some(peer) = peer_manager.get_peer(peer_id).await {
                                                if let Some(static_key) = peer.static_public_key {
                                                    // Calculate fingerprint and check if trusted
                                                    let fingerprint = bitchat_rust::crypto::NoiseEncryptionService::calculate_fingerprint(&static_key);
                                                    trust_manager.is_trusted(&fingerprint).await
                                                } else {
                                                    false  // No static key available
                                                }
                                            } else {
                                                false  // Peer not found
                                            }
                                        })
                                    })
                                } else {
                                    false  // No peer ID in message
                                }
                            } else {
                                false  // No checkmark for public messages or unencrypted messages
                            };
                            
                            app.add_received_message(
                                message.sender,
                                message.content,
                                message.channel,
                                message.is_private,
                                message.recipient_nickname,
                                is_trusted,
                            );
                        }
                    }
                    AppEvent::PeerConnected(peer_id) => {
                        app.add_popup_message(format!("Connected to peer: {}", peer_id));
                        if app.connected == false {
                            app.transition_to_connected();
                        }
                        
                        // Update peer list with nicknames
                        let mesh_service_clone = mesh_service.clone();
                        let app_sender_clone = app_sender.clone();
                        tokio::spawn(async move {
                            let nicknames = mesh_service_clone.get_peer_manager().get_connected_peer_nicknames().await;
                            let _ = app_sender_clone.send(AppEvent::PeerListUpdated(nicknames));
                        });
                    }
                    AppEvent::PeerDisconnected(peer_id) => {
                        app.add_popup_message(format!("Disconnected from peer: {}", peer_id));
                        
                        // Update peer list to remove disconnected peer
                        let mesh_service_clone = mesh_service.clone();
                        let app_sender_clone = app_sender.clone();
                        tokio::spawn(async move {
                            let nicknames = mesh_service_clone.get_peer_manager().get_connected_peer_nicknames().await;
                            let _ = app_sender_clone.send(AppEvent::PeerListUpdated(nicknames));
                        });
                    }
                    AppEvent::PeerListUpdated(peers) => {
                        app.people = peers;
                    }
                    AppEvent::NoiseHandshakeComplete(peer_id) => {
                        app.add_popup_message(format!("Secure channel established with: {}", peer_id));
                        
                        // Update peer's static public key after handshake completes
                        let mesh_service_clone = mesh_service.clone();
                        let peer_id_clone = peer_id.clone();
                        let app_sender_clone = app_sender.clone();
                        tokio::spawn(async move {
                            // Get the peer's static key from the noise service
                            let noise_service = mesh_service_clone.get_encryption_service().get_noise_service();
                            if let Some(static_key) = noise_service.get_peer_static_key(&peer_id_clone).await {
                                let peer_manager = mesh_service_clone.get_peer_manager();
                                if let Err(e) = peer_manager.update_peer_static_key(&peer_id_clone, static_key.clone()).await {
                                    warn!("Failed to update peer static key: {}", e);
                                    let _ = app_sender_clone.send(AppEvent::Log(
                                        format!("Failed to store static key for {}: {}", peer_id_clone, e),
                                        log::Level::Error
                                    ));
                                } else {
                                    debug!("Updated static key for peer {}", peer_id_clone);
                                    let fingerprint = bitchat_rust::crypto::NoiseEncryptionService::calculate_fingerprint(&static_key);
                                    let _ = app_sender_clone.send(AppEvent::Log(
                                        format!("Stored static key for {} (fingerprint: {}...)", peer_id_clone, &fingerprint[..16]),
                                        log::Level::Debug
                                    ));
                                }
                            } else {
                                let _ = app_sender_clone.send(AppEvent::Log(
                                    format!("No static key found in noise service for {}", peer_id_clone),
                                    log::Level::Warn
                                ));
                            }
                        });
                    }
                    AppEvent::NoiseHandshakeFailed(peer_id, error) => {
                        app.add_popup_message(format!("Failed to establish secure channel with {}: {}", peer_id, error));
                    }
                    AppEvent::Error(error) => {
                        app.transition_to_error(error);
                    }
                    AppEvent::CommandOutput(msg) => {
                        // Command output is ALWAYS shown regardless of debug mode
                        let timestamp = chrono::Local::now().format("%H:%M").to_string();
                        let output_msg = bitchat_rust::tui::app::Message {
                            sender: "system".to_string(),
                            timestamp,
                            content: msg,
                            is_self: false,
                            is_trusted: false,
                        };
                        
                        // Add to current channel/DM
                        let (_, dm_target, channel_name) = app.get_current_messages();
                        if let Some(target) = dm_target {
                            app.dm_messages.entry(target).or_default().push(output_msg);
                        } else if let Some(channel) = channel_name {
                            app.channel_messages.entry(channel).or_default().push(output_msg);
                        } else {
                            app.channel_messages.entry("#public".to_string()).or_default().push(output_msg);
                        }
                        app.scroll_to_bottom_current_conversation();
                    }
                    AppEvent::Log(msg, level) => {
                        // Filter log messages based on debug mode
                        let should_show = match level {
                            log::Level::Error | log::Level::Warn => true,  // Always show errors and warnings
                            log::Level::Info => app.debug_mode,  // Only show info if debug mode is on
                            _ => app.debug_mode,  // Show debug/trace only in debug mode
                        };
                        
                        if should_show {
                            // Add log messages to the current conversation as system messages
                            let timestamp = chrono::Local::now().format("%H:%M").to_string();
                            let log_msg = bitchat_rust::tui::app::Message {
                                sender: "system".to_string(),
                                timestamp,
                                content: msg,
                                is_self: false,
                                is_trusted: false,
                            };
                            
                            // Add to current channel/DM
                            let (_, dm_target, channel_name) = app.get_current_messages();
                            if let Some(target) = dm_target {
                                app.dm_messages.entry(target).or_default().push(log_msg);
                            } else if let Some(channel) = channel_name {
                                app.channel_messages.entry(channel).or_default().push(log_msg);
                            } else {
                                app.channel_messages.entry("#public".to_string()).or_default().push(log_msg);
                            }
                            app.scroll_to_bottom_current_conversation();
                        }
                    }
                    AppEvent::ConnectToPeer(peer_address) => {
                        info!("Received ConnectToPeer event for: {}", peer_address);
                        let mesh_service = mesh_service.clone();
                        tokio::spawn(async move {
                            match peer_address.parse() {
                                Ok(addr) => {
                                    info!("Parsed address {} successfully, connecting...", peer_address);
                                    match mesh_service.get_connection_manager().connect_to_device(addr).await {
                                        Ok(connected_peer) => {
                                            info!("ConnectToPeer event successfully connected to: {}", connected_peer);
                                            // Send announce to newly connected peer
                                            if let Err(e) = mesh_service.send_announce().await {
                                                error!("Failed to send announce after connection: {}", e);
                                            }
                                        }
                                        Err(e) => {
                                            error!("ConnectToPeer event failed to connect to peer {}: {}", peer_address, e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to parse peer address {}: {}", peer_address, e);
                                }
                            }
                        });
                    }
                    AppEvent::DeliveryAck(message_id, from_peer) => {
                        app.add_popup_message(format!("Message {} delivered to {}", message_id, from_peer));
                    }
                    AppEvent::ReadReceipt(message_id, from_peer) => {
                        app.add_popup_message(format!("Message {} read by {}", message_id, from_peer));
                    }
                    AppEvent::TypingIndicator(peer_id, is_typing) => {
                        if is_typing {
                            app.add_popup_message(format!("{} is typing...", peer_id));
                        }
                    }
                    AppEvent::VersionNegotiated(peer_id, version) => {
                        app.add_popup_message(format!("Version {} negotiated with {}", version, peer_id));
                    }
                    AppEvent::SendVersionAck(peer_id, version) => {
                        let mesh_service = mesh_service.clone();
                        tokio::spawn(async move {
                            if let Err(e) = mesh_service.send_version_ack(peer_id.clone(), version).await {
                                error!("Failed to send version ack to {}: {}", peer_id, e);
                            }
                        });
                    }
                    AppEvent::InitiateHandshake(peer_id) => {
                        let mesh_service = mesh_service.clone();
                        tokio::spawn(async move {
                            // Check if we already have a session before initiating
                            let noise_service = mesh_service.get_encryption_service().get_noise_service();
                            if noise_service.has_session(&peer_id).await {
                                debug!("Already have session with {} - skipping handshake initiation", peer_id);
                                return;
                            }
                            
                            if let Err(e) = mesh_service.initiate_noise_handshake(peer_id.clone()).await {
                                // Only log actual errors, not "already in progress" messages
                                if !e.to_string().contains("already in progress") && !e.to_string().contains("Already have") {
                                    error!("Failed to initiate handshake with {}: {}", peer_id, e);
                                } else {
                                    debug!("Handshake with {} already in progress or completed", peer_id);
                                }
                            }
                        });
                    }
                    AppEvent::SendNoiseIdentityAnnouncement => {
                        let mesh_service = mesh_service.clone();
                        tokio::spawn(async move {
                            if let Err(e) = mesh_service.send_noise_identity_announcement().await {
                                error!("Failed to send noise identity announcement: {}", e);
                            }
                        });
                    }
                    AppEvent::SendTargetedNoiseIdentityAnnouncement(target_peer_id) => {
                        let mesh_service = mesh_service.clone();
                        tokio::spawn(async move {
                            if let Err(e) = mesh_service.send_noise_identity_announcement_to(Some(target_peer_id)).await {
                                error!("Failed to send targeted noise identity announcement: {}", e);
                            }
                        });
                    }
                    AppEvent::CheckHandshakeNeeded(my_peer_id, other_peer_id) => {
                        // Use lexicographical comparison to decide who initiates
                        if my_peer_id < other_peer_id {
                            // We should initiate
                            let mesh_service = mesh_service.clone();
                            tokio::spawn(async move {
                                if let Err(e) = mesh_service.initiate_noise_handshake(other_peer_id.clone()).await {
                                    error!("Failed to initiate handshake with {}: {}", other_peer_id, e);
                                }
                            });
                        } else {
                            // They should initiate, send identity announcement
                            let mesh_service = mesh_service.clone();
                            tokio::spawn(async move {
                                if let Err(e) = mesh_service.send_noise_identity_announcement().await {
                                    error!("Failed to send noise identity announcement: {}", e);
                                }
                            });
                        }
                    }
                    AppEvent::SendAnnounce => {
                        info!("Sending announce message");
                        let mesh_service = mesh_service.clone();
                        tokio::spawn(async move {
                            if let Err(e) = mesh_service.send_announce().await {
                                error!("Failed to send announce: {}", e);
                            }
                        });
                    }
                    AppEvent::NoiseHandshakeInit(peer_id, packet) => {
                        info!("Processing NoiseHandshakeInit from {}", peer_id);
                        let mesh_service = mesh_service.clone();
                        tokio::spawn(async move {
                            if let Err(e) = mesh_service.handle_noise_handshake_init(peer_id.clone(), packet).await {
                                error!("Failed to handle noise handshake init from {}: {}", peer_id, e);
                            }
                        });
                    }
                    AppEvent::NoiseHandshakeResponse(peer_id, packet) => {
                        info!("Processing NoiseHandshakeResponse from {}", peer_id);
                        let mesh_service = mesh_service.clone();
                        tokio::spawn(async move {
                            if let Err(e) = mesh_service.handle_noise_handshake_response(peer_id.clone(), packet).await {
                                error!("Failed to handle noise handshake response from {}: {}", peer_id, e);
                            }
                        });
                    }
                    AppEvent::SendHandshakeRequest(target_peer_id) => {
                        info!("Sending handshake request to {}", target_peer_id);
                        let mesh_service = mesh_service.clone();
                        tokio::spawn(async move {
                            if let Err(e) = mesh_service.send_handshake_request(target_peer_id.clone()).await {
                                error!("Failed to send handshake request to {}: {}", target_peer_id, e);
                            }
                        });
                    }
                    AppEvent::NoiseEncrypted(peer_id, packet) => {
                        info!("Processing NoiseEncrypted from {} ({} bytes)", peer_id, packet.payload.len());
                        let mesh_service = mesh_service.clone();
                        let app_sender_clone = app_sender.clone();
                        tokio::spawn(async move {
                            // Get the noise service to decrypt the message
                            let noise_service = mesh_service.get_encryption_service().get_noise_service();
                            
                            match noise_service.decrypt_packet(&peer_id, packet.clone()).await {
                                Ok(decrypted_data) => {
                                    info!("Successfully decrypted {} bytes from {}", decrypted_data.len(), peer_id);
                                    
                                    // Try to decode as a full packet first (our format)
                                    match bitchat_rust::protocol::BinaryProtocol::decode(&decrypted_data) {
                                        Ok(inner_packet) => {
                                            // It's a full packet - process the inner message
                                            info!("Decrypted full packet from {}, type: {:?}", peer_id, inner_packet.message_type);
                                            
                                            // Parse the message from the inner packet's payload
                                            match BitchatMessage::from_binary_payload(&inner_packet.payload) {
                                                Ok(mut message) => {
                                                    info!("Parsed decrypted message: {} -> {}", message.sender, message.content);
                                                    message.sender_peer_id = Some(peer_id);
                                                    message.is_encrypted = true;  // Mark as encrypted since it came through Noise
                                                    
                                                    // Send the decrypted message to the UI
                                                    let _ = app_sender_clone.send(AppEvent::Message(message));
                                                }
                                                Err(e) => {
                                                    error!("Failed to parse message from inner packet: {}", e);
                                                }
                                            }
                                        }
                                        Err(_) => {
                                            // Not a full packet - check if it's a raw payload from client
                                            if decrypted_data.len() > 0 {
                                                let type_marker = decrypted_data[0];
                                                
                                                // Check for DeliveryAck (0x0A)
                                                if type_marker == 0x0A {
                                                    info!("Received DeliveryAck from client {}", peer_id);
                                                    // TODO: Parse DeliveryAck structure
                                                }
                                                // Check for ReadReceipt (0x0C)
                                                else if type_marker == 0x0C {
                                                    info!("Received ReadReceipt from client {}", peer_id);
                                                    // TODO: Parse ReadReceipt structure
                                                }
                                                // Try to parse as raw message payload
                                                else {
                                                    info!("failed to decrypt message from client {}", peer_id);

                                                    match BitchatMessage::from_binary_payload(&decrypted_data) {
                                                        Ok(mut message) => {
                                                            message.sender_peer_id = Some(peer_id);
                                                            
                                                            // Send the decrypted message to the UI
                                                            let _ = app_sender_clone.send(AppEvent::Message(message));
                                                        }
                                                        Err(e) => {
                                                            error!("Failed to parse plaintext data as message: {}", e);
                                                        }
                                                    }
                                                }
                                            } else {
                                                error!("Decrypted data is empty from {}", peer_id);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to decrypt message from {}: {}", peer_id, e);
                                    
                                    // Send NACK for decryption failure
                                    if let Err(nack_err) = mesh_service.send_protocol_nack(
                                        packet,
                                        peer_id.clone(),
                                        format!("Decryption failed: {}", e),
                                        bitchat_rust::protocol::NackErrorCode::DecryptionFailed,
                                    ).await {
                                        error!("Failed to send NACK to {}: {}", peer_id, nack_err);
                                    }
                                }
                            }
                        });
                    }
                    AppEvent::SystemValidation(peer_id, packet) => {
                        info!("Processing SystemValidation from {}", peer_id);
                        let mesh_service = mesh_service.clone();
                        tokio::spawn(async move {
                            // Try to decrypt the validation ping
                            let noise_service = mesh_service.get_encryption_service().get_noise_service();
                            
                            match noise_service.decrypt_packet(&peer_id, packet.clone()).await {
                                Ok(decrypted_data) => {
                                    info!("System validation successful from {} ({} bytes)", peer_id, decrypted_data.len());
                                    // Update last successful message time would go here
                                }
                                Err(e) => {
                                    error!("System validation failed from {}: {}", peer_id, e);
                                    
                                    // Send NACK for validation failure
                                    if let Err(nack_err) = mesh_service.send_protocol_nack(
                                        packet,
                                        peer_id.clone(),
                                        format!("System validation failed: {}", e),
                                        bitchat_rust::protocol::NackErrorCode::SystemValidationFailed,
                                    ).await {
                                        error!("Failed to send NACK to {}: {}", peer_id, nack_err);
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }
        
        if app.should_quit {
            break;
        }
    }
    
    // Stop mesh service
    mesh_service.stop().await?;
    
    Ok(())
}
