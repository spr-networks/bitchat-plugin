use crate::Result;
use crate::protocol::{BinaryProtocol, MessageType, Packet};
use crate::mesh::{BluetoothMeshDelegate, PeerManager};
use std::collections::{HashSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::Duration as TokioDuration;
use chrono::{Utc, Duration};
use log::{debug, info, warn, error};
use bloomfilter::Bloom;
use rand::Rng;
use sha2::{Sha256, Digest};

#[derive(Clone)]
pub struct PacketProcessor {
    delegate: Arc<dyn BluetoothMeshDelegate>,
    peer_manager: Arc<PeerManager>,
    seen_packet_ids: Arc<RwLock<HashSet<String>>>,
    last_cleanup: Arc<RwLock<chrono::DateTime<Utc>>>,
    seen_announces: Arc<RwLock<HashSet<String>>>,
    
    // Bloom filter for message deduplication
    message_bloom: Arc<RwLock<Bloom<String>>>,
    // Scheduled relays to prevent duplicates
    relay_queue: Arc<RwLock<HashMap<String, JoinHandle<()>>>>,
    // Network size estimate for adaptive relaying
    network_size_estimate: Arc<AtomicUsize>,
}

impl PacketProcessor {
    pub fn new(delegate: Arc<dyn BluetoothMeshDelegate>, peer_manager: Arc<PeerManager>) -> Self {
        let processor = Self {
            delegate,
            peer_manager,
            seen_packet_ids: Arc::new(RwLock::new(HashSet::new())),
            last_cleanup: Arc::new(RwLock::new(Utc::now())),
            seen_announces: Arc::new(RwLock::new(HashSet::new())),
            
            // Initialize bloom filter with iOS default parameters (500 items, 1% FPR)
            message_bloom: Arc::new(RwLock::new(Bloom::new_for_fp_rate(500, 0.01))),
            relay_queue: Arc::new(RwLock::new(HashMap::new())),
            network_size_estimate: Arc::new(AtomicUsize::new(1)),
        };
        
        // Start bloom filter maintenance task
        processor.start_bloom_maintenance();
        
        processor
    }
    
    // Bloom filter and relay management methods
    async fn is_duplicate_bloom(&self, message_id: &str) -> bool {
        let bloom = self.message_bloom.read().await;
        bloom.check(&message_id.to_string())
    }
    
    async fn mark_message_seen_bloom(&self, message_id: &str) {
        let mut bloom = self.message_bloom.write().await;
        bloom.set(&message_id.to_string());
    }
    
    fn generate_message_id(&self, packet: &Packet) -> String {
        // iOS-style message ID generation using SHA256 hash
        let mut hasher = Sha256::new();
        
        // Add immutable packet fields (matching iOS implementation)
        hasher.update(&packet.sender_id);
        hasher.update(packet.timestamp.timestamp_millis().to_be_bytes());
        hasher.update([packet.message_type.as_u8()]);
        
        // Include first 32 bytes of payload for uniqueness (iOS does this)
        let payload_prefix = &packet.payload[..packet.payload.len().min(32)];
        hasher.update(payload_prefix);
        
        let hash = hasher.finalize();
        
        // Format as UUID-style string (like iOS)
        let hash_bytes = &hash[..16]; // Use first 16 bytes for UUID format
        format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            hash_bytes[0], hash_bytes[1], hash_bytes[2], hash_bytes[3],
            hash_bytes[4], hash_bytes[5],
            hash_bytes[6], hash_bytes[7], 
            hash_bytes[8], hash_bytes[9],
            hash_bytes[10], hash_bytes[11], hash_bytes[12], hash_bytes[13], hash_bytes[14], hash_bytes[15]
        )
    }
    
    async fn cancel_pending_relay(&self, message_id: &str) {
        if let Some(handle) = self.relay_queue.write().await.remove(message_id) {
            handle.abort();
            debug!("Cancelled pending relay for message: {}", message_id);
        }
    }
    
    fn calculate_relay_probability(&self) -> f64 {
        // iOS adaptive relay probability with bell curve pattern
        let network_size = self.network_size_estimate.load(Ordering::Relaxed);
        match network_size {
            0..=2 => 0.3,      // 30%
            3..=5 => 0.5,      // 50%
            6..=10 => 0.6,     // 60%
            11..=30 => 0.7,    // 70% - peak
            31..=50 => 0.6,    // 60% - starts decreasing
            51..=100 => 0.5,   // 50%
            _ => 0.4           // 40% minimum for very large networks
        }
    }
    
    fn exponential_relay_delay(&self) -> TokioDuration {
        // iOS delay parameters: 10ms min, 100ms max (matching iOS exactly)
        let min_delay_ms = 10u64;   // 10ms minimum  
        let max_delay_ms = 100u64;  // 100ms maximum
        let mean_delay_ms = (min_delay_ms + max_delay_ms) / 2; // 55ms mean
        
        let lambda = 1.0 / mean_delay_ms as f64;
        let u: f64 = rand::thread_rng().gen();
        let delay_ms = -((1.0 - u).ln()) / lambda;
        
        let clamped_delay = (delay_ms as u64).clamp(min_delay_ms, max_delay_ms);
        TokioDuration::from_millis(clamped_delay)
    }
    
    async fn schedule_relay(&self, packet: Packet, delay: TokioDuration) {
        let message_id = self.generate_message_id(&packet);
        
        // Cancel any existing relay for this message
        self.cancel_pending_relay(&message_id).await;
        
        let processor_clone = self.clone();
        let message_id_clone = message_id.clone();
        
        let handle = tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            
            // Check if message was seen from another relay before we relay
            if !processor_clone.is_duplicate_bloom(&message_id_clone).await {
                debug!("Executing scheduled relay for message: {}", message_id_clone);
                if let Err(e) = processor_clone.execute_relay(packet).await {
                    warn!("Failed to execute relay: {}", e);
                }
            } else {
                debug!("Skipping relay - message {} already seen", message_id_clone);
            }
        });
        
        self.relay_queue.write().await.insert(message_id, handle);
    }
    
    async fn execute_relay(&self, mut packet: Packet) -> Result<()> {
        // Prepare packet for relay (decrement TTL)
        packet = self.prepare_for_relay(packet);
        
        // For now, we just log that we would relay - the actual relay mechanism 
        // should be handled by the mesh service layer, not the packet processor
        debug!("Would relay packet with TTL {} (relay logic placeholder)", packet.ttl);
        
        // TODO: Implement actual relay through the mesh service
        // This requires refactoring the mesh service to provide a relay interface
        
        Ok(())
    }
    
    fn start_bloom_maintenance(&self) {
        let processor = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(TokioDuration::from_secs(300)); // 5 minutes
            
            loop {
                interval.tick().await;
                if let Err(e) = processor.maintain_bloom_filter().await {
                    warn!("Error maintaining bloom filter: {}", e);
                }
            }
        });
    }
    
    async fn maintain_bloom_filter(&self) -> Result<()> {
        let _current_network_size = self.network_size_estimate.load(Ordering::Relaxed);
        
        // Update network size estimate based on known peers
        let peer_count = self.peer_manager.get_peer_count().await;
        self.network_size_estimate.store(peer_count.max(1), Ordering::Relaxed);
        
        // Check if we need to reset the bloom filter
        let mut bloom = self.message_bloom.write().await;
        
        // Reset bloom filter with iOS-style adaptive sizing
        let (expected_items, fp_rate) = self.get_adaptive_bloom_params(peer_count);
        info!("Resetting bloom filter for network size: {} (items: {}, fp_rate: {})", 
              peer_count, expected_items, fp_rate);
        *bloom = Bloom::new_for_fp_rate(expected_items, fp_rate);
        
        Ok(())
    }
    
    fn get_adaptive_bloom_params(&self, network_size: usize) -> (usize, f64) {
        // iOS adaptive bloom filter parameters
        match network_size {
            0..=49 => (500, 0.01),    // 500 items, 1% FPR
            50..=199 => (2000, 0.02), // 2000 items, 2% FPR
            200..=499 => (5000, 0.03), // 5000 items, 3% FPR
            _ => (10000, 0.05)         // 10000 items, 5% FPR
        }
    }
    
    pub async fn process_raw_data(&self, data: &[u8], from_bluetooth_address: String) -> Result<()> {
        debug!("Processing {} bytes from bluetooth {}", data.len(), from_bluetooth_address);
        
        let packet = BinaryProtocol::decode(data)?;
        self.process_packet(packet, from_bluetooth_address).await
    }
    
    pub async fn process_packet(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        // Check if this is our own packet - don't process our own messages
        let my_peer_id = self.delegate.get_my_peer_id().await;
        let sender_id_hex = packet.sender_id_hex();
        if sender_id_hex == my_peer_id {
            debug!("Dropping our own packet");
            return Ok(());
        }
        
        // Generate message ID for bloom filter
        let message_id = self.generate_message_id(&packet);
        
        // Fast bloom filter duplicate check first
        if self.is_duplicate_bloom(&message_id).await {
            debug!("Bloom filter detected duplicate message: {}", message_id);
            // Cancel any pending relay for this message since we've seen it
            self.cancel_pending_relay(&message_id).await;
            return Ok(());
        }
        
        // Update peer's last seen time
        let _ = self.peer_manager.update_peer_last_seen(&sender_id_hex).await;
        
        // Check for duplicate packets (slower but more detailed check)
        if self.is_duplicate(&packet).await {
            debug!("Dropping duplicate packet from bluetooth {}", from_bluetooth_address);
            // Mark as seen in bloom filter
            self.mark_message_seen_bloom(&message_id).await;
            return Ok(());
        }
        
        // Mark message as seen in bloom filter
        self.mark_message_seen_bloom(&message_id).await;
        
        // Validate TTL
        if packet.ttl == 0 {
            debug!("Dropping packet with TTL 0");
            return Ok(());
        }
        
        // Save a clone for relay logic later (before packet gets moved)
        let packet_for_relay = packet.clone();
        
        // Handle public packet types (no address check needed) - matching Android logic
        match packet.message_type {
            MessageType::NoiseIdentityAnnounce => {
                self.handle_noise_identity_announce(packet, from_bluetooth_address).await?;
            }
            MessageType::Announce => {
                self.handle_announce(packet, from_bluetooth_address).await?;
            }
            MessageType::Message => {
                self.handle_message(packet, from_bluetooth_address).await?;
            }
            MessageType::Leave => {
                self.handle_leave(packet, from_bluetooth_address).await?;
            }
            MessageType::FragmentStart | MessageType::FragmentContinue | MessageType::FragmentEnd => {
                // Fragments should be reassembled here like Android does
                self.handle_fragment(packet, from_bluetooth_address).await?;
            }
            _ => {
                // Handle private packet types (address check required) - matching Android logic
                if self.is_packet_addressed_to_me(&packet).await {
                    match packet.message_type {
                        MessageType::NoiseHandshakeInit => {
                            // Android doesn't check recipient for handshakes
                            let sender_id_hex = packet.sender_id_hex();
                            info!("Received NoiseHandshakeInit from bluetooth {} (sender_id: {}) - forwarding to delegate", 
                                from_bluetooth_address, sender_id_hex);
                            self.delegate.did_receive_noise_handshake_init(sender_id_hex, packet).await;
                        }
                        MessageType::NoiseHandshakeResp => {
                            // Android doesn't check recipient for handshakes
                            let sender_id_hex = packet.sender_id_hex();
                            info!("Received NoiseHandshakeResp from bluetooth {} (sender_id: {}) - forwarding to delegate", 
                                from_bluetooth_address, sender_id_hex);
                            self.delegate.did_receive_noise_handshake_response(sender_id_hex, packet).await;
                        }
                        MessageType::NoiseEncrypted => {
                            // Moved to private messages section to match Android
                            info!("Received NoiseEncrypted packet from {} - processing for decryption", from_bluetooth_address);
                            self.handle_noise_encrypted(packet, from_bluetooth_address).await?;
                        }
                        // DeliveryAck and ReadReceipt are handled inside NoiseEncrypted in Android
                        // We'll comment them out as separate handlers
                        /*
                        MessageType::DeliveryAck => {
                            self.handle_delivery_ack(packet, from_bluetooth_address).await?;
                        }
                        MessageType::ReadReceipt => {
                            self.handle_read_receipt(packet, from_bluetooth_address).await?;
                        }
                        */
                        MessageType::ChannelAnnounce => {
                            self.handle_channel_announce(packet, from_bluetooth_address).await?;
                        }
                        MessageType::ChannelRetention => {
                            self.handle_channel_retention(packet, from_bluetooth_address).await?;
                        }
                        MessageType::ChannelKeyVerifyRequest => {
                            self.handle_channel_key_verify_request(packet, from_bluetooth_address).await?;
                        }
                        MessageType::ChannelKeyVerifyResponse => {
                            self.handle_channel_key_verify_response(packet, from_bluetooth_address).await?;
                        }
                        MessageType::ChannelPasswordUpdate => {
                            self.handle_channel_password_update(packet, from_bluetooth_address).await?;
                        }
                        MessageType::ChannelMetadata => {
                            self.handle_channel_metadata(packet, from_bluetooth_address).await?;
                        }
                        MessageType::VersionHello => {
                            self.handle_version_hello(packet, from_bluetooth_address).await?;
                        }
                        MessageType::VersionAck => {
                            self.handle_version_ack(packet, from_bluetooth_address).await?;
                        }
                        MessageType::HandshakeRequest => {
                            self.handle_handshake_request(packet, from_bluetooth_address).await?;
                        }
                        MessageType::DeliveryStatusRequest => {
                            self.handle_delivery_status_request(packet, from_bluetooth_address).await?;
                        }
                        MessageType::ProtocolAck => {
                            self.handle_protocol_ack(packet, from_bluetooth_address).await?;
                        }
                        MessageType::ProtocolNack => {
                            self.handle_protocol_nack(packet, from_bluetooth_address).await?;
                        }
                        MessageType::SystemValidation => {
                            self.handle_system_validation(packet, from_bluetooth_address).await?;
                        }
                        MessageType::Favorited => {
                            self.handle_favorited(packet, from_bluetooth_address).await?;
                        }
                        MessageType::Unfavorited => {
                            self.handle_unfavorited(packet, from_bluetooth_address).await?;
                        }
                        _ => {
                            warn!("Unknown private message type: {:?} from {} ({} bytes payload)", 
                                packet.message_type, from_bluetooth_address, packet.payload.len());
                        }
                    }
                } else {
                    debug!("Private packet type {:?} not addressed to us, skipping", packet.message_type);
                }
            }
        }
        
        // Determine if we should relay this packet with probabilistic flooding
        if self.should_relay_with_probability(&packet_for_relay).await {
            let delay = self.exponential_relay_delay();
            debug!("Scheduling relay for message {} with delay {:?}", message_id, delay);
            self.schedule_relay(packet_for_relay, delay).await;
        } else {
            debug!("Not relaying message {} (probability or TTL check failed)", message_id);
        }
        
        Ok(())
    }
    
    async fn is_duplicate(&self, packet: &Packet) -> bool {
        // Create packet ID from sender + timestamp
        let packet_id = format!("{}-{}", 
            packet.sender_id_hex(),
            packet.timestamp.timestamp_millis()
        );
        
        let mut seen_ids = self.seen_packet_ids.write().await;
        
        // Cleanup old IDs periodically
        let mut last_cleanup = self.last_cleanup.write().await;
        if Utc::now() - *last_cleanup > Duration::minutes(5) {
            self.cleanup_seen_ids(&mut seen_ids).await;
            *last_cleanup = Utc::now();
        }
        
        // Check if already seen
        if seen_ids.contains(&packet_id) {
            true
        } else {
            seen_ids.insert(packet_id);
            false
        }
    }
    
    async fn cleanup_seen_ids(&self, seen_ids: &mut HashSet<String>) {
        // Keep only recent packet IDs (last 10 minutes)
        let cutoff = Utc::now() - Duration::minutes(10);
        seen_ids.retain(|id| {
            if let Some(timestamp_str) = id.split('-').nth(1) {
                if let Ok(timestamp) = timestamp_str.parse::<i64>() {
                    if let Some(packet_time) = chrono::DateTime::<Utc>::from_timestamp_millis(timestamp) {
                        return packet_time > cutoff;
                    }
                }
            }
            false
        });
    }
    
    async fn handle_announce(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling announce from {}", from_bluetooth_address);
        
        let sender_id_hex = packet.sender_id_hex();
        
        // Parse nickname from payload (matching Android/iOS implementation)
        let nickname = if !packet.payload.is_empty() {
            String::from_utf8_lossy(&packet.payload).trim().to_string()
        } else {
            format!("peer_{}", &sender_id_hex[..8]) // Fallback if no nickname provided
        };
        
        debug!("Received announce from {}: {}", sender_id_hex, nickname);
        
        // Check if this is the first announce from this peer
        let is_first_announce = !self.seen_announces.read().await.contains(&sender_id_hex);
        
        // Only show "joined the chat" message for first-time connections
        if is_first_announce {
            // Create a system message for the join
            let join_message = crate::model::BitchatMessage {
                id: format!("announce-{}-{}", sender_id_hex, chrono::Utc::now().timestamp_millis()),
                content: format!("{} joined the chat", nickname),
                sender: "System".to_string(),
                sender_peer_id: Some(sender_id_hex.clone()),
                timestamp: chrono::Utc::now(),
                is_private: false,
                is_relay: false,
                original_sender: None,
                recipient_nickname: None,
                mentions: None,
                channel: None,
                is_encrypted: false,
                encrypted_content: None,
            };
            
            // Send the system message
            self.delegate.did_receive_message(join_message).await;
        }
        
        // Always send peer connection notification (for UI updates)
        self.delegate.did_connect_to_peer(sender_id_hex.clone()).await;
        
        // Ensure peer exists in peer manager first
        let _ = self.peer_manager.add_peer(sender_id_hex.clone()).await;
        
        // Update peer manager with nickname and connection status
        if let Err(e) = self.peer_manager.update_peer_nickname(&sender_id_hex, nickname.clone()).await {
            debug!("Failed to update peer nickname: {}", e);
        }
        
        // Mark peer as connected
        let _ = self.peer_manager.update_peer_connected(&sender_id_hex, true).await;
        
        // Note: We don't initiate connection based on Bluetooth address
        // Connections are managed at the Bluetooth layer
        
        // Record announce to track if we've seen this peer before
        self.seen_announces.write().await.insert(sender_id_hex.clone());
        
        // If this is first announce from this peer, send our announce back
        if is_first_announce {
            debug!("First announce from {} - sending our announce in response", sender_id_hex);
            self.delegate.should_send_announce().await;
        }
        
        // Check if we need to initiate a Noise handshake with this peer - matching iOS logic
        // Use lexicographical comparison to decide who initiates (prevents both sides from initiating)
        let my_peer_id = self.delegate.get_my_peer_id().await;
        if my_peer_id < sender_id_hex {
            // We should initiate the handshake (same as iOS handshakeCoordinator.shouldInitiateHandshake)
            self.delegate.should_initiate_noise_handshake(sender_id_hex.clone()).await;
        } else {
            // They should initiate, we send a Noise identity announcement
            self.delegate.should_send_noise_identity_announcement().await;
        }
        
        Ok(())
    }
    
    async fn handle_message(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        // Store sender ID before consuming the packet
        let sender_id_hex = packet.sender_id_hex();
        
        // Parse BitChat message from binary payload
        let mut message = crate::model::BitchatMessage::from_binary_payload(&packet.payload)?;
            
        // Set sender peer ID
        message.sender_peer_id = Some(sender_id_hex.clone());
        
        
        // Look up the actual nickname from peer manager
        if let Some(peer) = self.peer_manager.get_peer(&sender_id_hex).await {
            if let Some(nickname) = peer.nickname {
                debug!("Replacing sender '{}' with actual nickname '{}'", message.sender, nickname);
                message.sender = nickname;
            } else {
                debug!("No nickname found for peer {}, keeping sender as '{}'", sender_id_hex, message.sender);
            }
        } else {
            debug!("Peer {} not found in peer manager, keeping sender as '{}'", sender_id_hex, message.sender);
        }
        
        // Notify delegate
        self.delegate.did_receive_message(message).await;
        
        Ok(())
    }
    
    async fn handle_noise_encrypted(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        info!("Handling noise encrypted packet from {} ({} bytes)", from_bluetooth_address, packet.payload.len());
        
        // Android handles DeliveryAck and ReadReceipt inside NoiseEncrypted
        // For now, delegate to main handler which will decrypt and check for these types
        self.delegate.did_receive_noise_encrypted(packet.sender_id_hex(), packet).await;
        
        // TODO: Move decryption logic here to match Android's architecture:
        // 1. Decrypt the payload
        // 2. Check first byte for MessageType::DeliveryAck or MessageType::ReadReceipt
        // 3. If it's one of those, handle directly
        // 4. Otherwise, try to parse as inner packet and process recursively
        
        Ok(())
    }
    
    pub fn should_relay(&self, packet: &Packet) -> bool {
        // Relay if TTL > 1 and not a direct message
        packet.ttl > 1 && packet.recipient_id.is_none()
    }
    
    pub fn prepare_for_relay(&self, mut packet: Packet) -> Packet {
        packet.ttl = packet.ttl.saturating_sub(1);
        packet
    }
    
    async fn should_relay_with_probability(&self, packet: &Packet) -> bool {
        // Basic relay check first
        if !self.should_relay(packet) {
            return false;
        }
        
        // Apply probabilistic flooding based on network size
        let probability = self.calculate_relay_probability();
        let random: f64 = rand::thread_rng().gen();
        
        let should_relay = random < probability;
        debug!("Relay decision for packet: TTL={}, probability={:.2}, random={:.2}, relay={}", 
               packet.ttl, probability, random, should_relay);
        
        should_relay
    }
    
    async fn is_packet_addressed_to_me(&self, packet: &Packet) -> bool {
        // If no recipient ID specified, it's a broadcast (not addressed to anyone specifically)
        if let Some(recipient_id) = &packet.recipient_id {
            // Get our peer ID and compare with recipient ID
            let my_peer_id = self.delegate.get_my_peer_id().await;
            
            // Convert our hex peer ID to bytes for comparison
            if let Ok(my_peer_id_bytes) = hex::decode(&my_peer_id) {
                // Ensure we have exactly 8 bytes and compare
                if my_peer_id_bytes.len() >= 8 {
                    let my_id_8_bytes = &my_peer_id_bytes[..8];
                    return recipient_id == my_id_8_bytes;
                }
            }
            
            false
        } else {
            false
        }
    }
    
    async fn handle_noise_identity_announce(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        let sender_id_hex = packet.sender_id_hex();
        let payload_len = packet.payload.len();
        info!("Handling NoiseIdentityAnnouncement from {} (packet sender: {}, {} bytes)", 
            from_bluetooth_address, sender_id_hex, payload_len);
        
        // Parse the announcement to update peer info first (before moving packet)
        if let Ok(announcement) = crate::protocol::NoiseIdentityAnnouncement::from_binary(&packet.payload) {
            info!("Parsed identity announcement: peerID={}, nickname={}, publicKey={} bytes, signingKey={} bytes", 
                announcement.peer_id, announcement.nickname, 
                announcement.public_key.len(), announcement.signing_public_key.len());
            
            // Update peer manager with nickname
            let _ = self.peer_manager.update_peer_nickname(&announcement.peer_id, announcement.nickname).await;
            
            // IMPORTANT: iOS/Mac expect us to respond with our own identity announcement
            // This is the "lazy handshake mode" - exchange identities first
            info!("Responding to identity announce from {} with targeted announcement", announcement.peer_id);
            // Send targeted announcement to the specific peer
            self.delegate.should_send_targeted_noise_identity_announcement(announcement.peer_id.clone()).await;
            
            // After exchanging identity announcements, the mesh service will handle
            // checking for existing sessions and sending handshake requests if needed
            info!("Identity announcement processed - mesh service will handle session establishment for {}", announcement.peer_id);
        } else {
            warn!("Failed to parse NoiseIdentityAnnouncement payload from {} ({} bytes)", 
                sender_id_hex, payload_len);
            if packet.payload.len() >= 10 {
                debug!("First 10 bytes: {:02x?}", &packet.payload[..10]);
            }
        }
        
        // Process similar to announce but for noise identity
        self.delegate.did_receive_noise_identity_announce(sender_id_hex.clone(), packet).await;
        
        Ok(())
    }
    
    // Placeholder handlers for all message types - can be enhanced later
    async fn handle_leave(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling leave from {}", from_bluetooth_address);
        
        let sender_id_hex = packet.sender_id_hex();
        
        // Get peer nickname before removing
        let nickname = if let Some(peer) = self.peer_manager.get_peer(&sender_id_hex).await {
            peer.nickname.unwrap_or_else(|| format!("peer-{}", &sender_id_hex[..8]))
        } else {
            format!("peer-{}", &sender_id_hex[..8])
        };
        
        // Create a system message for the leave
        let leave_message = crate::model::BitchatMessage {
            id: format!("leave-{}-{}", sender_id_hex, chrono::Utc::now().timestamp_millis()),
            content: format!("{} left the chat", nickname),
            sender: "System".to_string(),
            sender_peer_id: Some(sender_id_hex.clone()),
            timestamp: chrono::Utc::now(),
            is_private: false,
            is_relay: false,
            original_sender: None,
            recipient_nickname: None,
            mentions: None,
            channel: None,
            is_encrypted: false,
            encrypted_content: None,
        };
        
        // Remove peer from peer manager
        let _ = self.peer_manager.remove_peer(&sender_id_hex).await;
        
        // Remove from seen_announces so they get "joined" message if they reconnect
        self.seen_announces.write().await.remove(&sender_id_hex);
        
        // Send both the system message and peer disconnection notification
        self.delegate.did_receive_message(leave_message).await;
        self.delegate.did_disconnect_from_peer(sender_id_hex).await;
        
        Ok(())
    }
    
    async fn handle_channel_announce(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling channel announce from {}", from_bluetooth_address);
        
        // Parse channel information from payload
        if packet.payload.len() < 2 {
            debug!("Channel announce payload too short");
            return Ok(());
        }
        
        let channel_name_len = packet.payload[0] as usize;
        if packet.payload.len() < 1 + channel_name_len {
            debug!("Invalid channel announce payload length");
            return Ok(());
        }
        
        let channel_name = String::from_utf8_lossy(&packet.payload[1..1 + channel_name_len]).to_string();
        
        // Create system message about channel announce
        let sender_id_hex = packet.sender_id_hex();
        let announce_message = crate::model::BitchatMessage {
            id: format!("channel-announce-{}-{}", sender_id_hex, chrono::Utc::now().timestamp_millis()),
            content: format!("{} announced channel: {}", &sender_id_hex[..8], channel_name),
            sender: "System".to_string(),
            sender_peer_id: Some(sender_id_hex),
            timestamp: chrono::Utc::now(),
            is_private: false,
            is_relay: false,
            original_sender: None,
            recipient_nickname: None,
            mentions: None,
            channel: Some(channel_name),
            is_encrypted: false,
            encrypted_content: None,
        };
        
        self.delegate.did_receive_message(announce_message).await;
        Ok(())
    }
    
    async fn handle_channel_retention(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling channel retention from {}", from_bluetooth_address);
        
        // Parse retention settings from payload
        if packet.payload.len() < 4 {
            debug!("Channel retention payload too short");
            return Ok(());
        }
        
        let retention_seconds = u32::from_be_bytes([
            packet.payload[0], packet.payload[1], packet.payload[2], packet.payload[3]
        ]);
        
        debug!("Channel retention setting: {} seconds from {}", retention_seconds, from_bluetooth_address);
        
        // For now, just log the retention setting
        // In a full implementation, this would update channel retention policies
        
        Ok(())
    }
    
    async fn handle_delivery_ack(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        let sender_id_hex = packet.sender_id_hex();
        debug!("Handling delivery ack from {} (sender: {})", from_bluetooth_address, sender_id_hex);
        
        // Parse message ID from payload
        if packet.payload.len() < 16 {
            debug!("Delivery ack payload too short");
            return Ok(());
        }
        
        let message_id = String::from_utf8_lossy(&packet.payload[..16]).to_string();
        debug!("Delivery acknowledged for message {} by {}", message_id, sender_id_hex);
        
        // Notify delegate about delivery acknowledgment - use actual sender ID
        self.delegate.did_receive_delivery_ack(message_id, sender_id_hex).await;
        
        Ok(())
    }
    
    async fn handle_read_receipt(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        let sender_id_hex = packet.sender_id_hex();
        debug!("Handling read receipt from {} (sender: {})", from_bluetooth_address, sender_id_hex);
        
        // Parse message ID from payload
        if packet.payload.len() < 16 {
            debug!("Read receipt payload too short");
            return Ok(());
        }
        
        let message_id = String::from_utf8_lossy(&packet.payload[..16]).to_string();
        debug!("Read receipt for message {} from {}", message_id, sender_id_hex);
        
        // Notify delegate about read receipt - use actual sender ID
        self.delegate.did_receive_read_receipt(message_id, sender_id_hex).await;
        
        Ok(())
    }
    
    async fn handle_channel_key_verify_request(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling channel key verify request from {}", from_bluetooth_address);
        
        // Parse channel key verification request
        if packet.payload.len() < 32 {
            debug!("Channel key verify request payload too short");
            return Ok(());
        }
        
        let key_hash = &packet.payload[..32];
        let sender_id_hex = packet.sender_id_hex();
        
        debug!("Channel key verification request from {} with hash: {}", 
            sender_id_hex, hex::encode(key_hash));
        
        // Notify delegate to handle key verification
        self.delegate.did_receive_key_verify_request(sender_id_hex, key_hash.to_vec()).await;
        
        Ok(())
    }
    
    async fn handle_channel_key_verify_response(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling channel key verify response from {}", from_bluetooth_address);
        
        // Parse channel key verification response
        if packet.payload.is_empty() {
            debug!("Channel key verify response payload is empty");
            return Ok(());
        }
        
        let verified = packet.payload[0] != 0;
        let sender_id_hex = packet.sender_id_hex();
        
        debug!("Channel key verification response from {}: {}", 
            sender_id_hex, if verified { "verified" } else { "failed" });
        
        // Notify delegate about verification result
        self.delegate.did_receive_key_verify_response(sender_id_hex, verified).await;
        
        Ok(())
    }
    
    async fn handle_channel_password_update(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling channel password update from {}", from_bluetooth_address);
        
        // Parse channel password update
        if packet.payload.len() < 33 { // 32 bytes hash + 1 byte channel name length
            debug!("Channel password update payload too short");
            return Ok(());
        }
        
        let password_hash = &packet.payload[..32];
        let channel_name_len = packet.payload[32] as usize;
        
        if packet.payload.len() < 33 + channel_name_len {
            debug!("Invalid channel password update payload length");
            return Ok(());
        }
        
        let channel_name = String::from_utf8_lossy(&packet.payload[33..33 + channel_name_len]).to_string();
        let sender_id_hex = packet.sender_id_hex();
        
        debug!("Channel password update for {} from {}", channel_name, sender_id_hex);
        
        // Notify delegate about password update
        self.delegate.did_receive_password_update(channel_name, password_hash.to_vec(), sender_id_hex).await;
        
        Ok(())
    }
    
    async fn handle_channel_metadata(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling channel metadata from {}", from_bluetooth_address);
        
        // Parse channel metadata
        if packet.payload.len() < 2 {
            debug!("Channel metadata payload too short");
            return Ok(());
        }
        
        let channel_name_len = packet.payload[0] as usize;
        if packet.payload.len() < 1 + channel_name_len {
            debug!("Invalid channel metadata payload length");
            return Ok(());
        }
        
        let channel_name = String::from_utf8_lossy(&packet.payload[1..1 + channel_name_len]).to_string();
        let metadata = &packet.payload[1 + channel_name_len..];
        let sender_id_hex = packet.sender_id_hex();
        
        debug!("Channel metadata for {} from {} ({} bytes)", 
            channel_name, sender_id_hex, metadata.len());
        
        // Notify delegate about metadata update
        self.delegate.did_receive_channel_metadata(channel_name, metadata.to_vec(), sender_id_hex).await;
        
        Ok(())
    }
    
    async fn handle_version_hello(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling version hello from {}", from_bluetooth_address);
        
        let peer_version = if !packet.payload.is_empty() {
            packet.payload[0]
        } else {
            1 // Default to version 1 if no payload
        };
        
        let sender_id_hex = packet.sender_id_hex();
        debug!("Peer {} supports version {}", sender_id_hex, peer_version);
        
        // Send VERSION_ACK response with our supported version
        self.delegate.should_send_version_ack(sender_id_hex, peer_version).await;
        
        Ok(())
    }
    
    async fn handle_version_ack(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling version ack from {}", from_bluetooth_address);
        
        let agreed_version = if !packet.payload.is_empty() {
            packet.payload[0]
        } else {
            1 // Default to version 1
        };
        
        let sender_id_hex = packet.sender_id_hex();
        debug!("Version negotiation completed with {}: using version {}", 
            sender_id_hex, agreed_version);
        
        // Notify delegate that version negotiation is complete
        self.delegate.did_complete_version_negotiation(sender_id_hex, agreed_version).await;
        
        Ok(())
    }
    
    async fn handle_handshake_request(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        info!("Handling handshake request from {}", from_bluetooth_address);
        
        // Try to parse as iOS/Android format handshake request
        match crate::protocol::HandshakeRequest::from_binary(&packet.payload) {
            Ok(request) => {
                let sender_id_hex = packet.sender_id_hex();
                info!("Handshake request from {} (nickname: {}, target: {}, pending: {})", 
                    sender_id_hex, request.requester_nickname, request.target_id, request.pending_message_count);
                
                // Update peer nickname if we have it
                let _ = self.peer_manager.update_peer_nickname(&request.requester_id, request.requester_nickname.clone()).await;
                
                // Check if we're the target - if so, we should initiate the handshake
                let my_peer_id = self.delegate.get_my_peer_id().await;
                info!("My peer ID: {}, target ID: {}", my_peer_id, request.target_id);
                
                if request.target_id == my_peer_id {
                    info!("We are the target of handshake request, initiating Noise handshake with {}", request.requester_id);
                    self.delegate.should_initiate_noise_handshake(request.requester_id).await;
                } else {
                    info!("We are NOT the target (target is {}), waiting for them to initiate", request.target_id);
                }
            }
            Err(e) => {
                // Fallback to old simple format for backward compatibility
                debug!("Failed to parse as iOS handshake request: {}, trying simple format", e);
                
                let handshake_type = if !packet.payload.is_empty() {
                    packet.payload[0]
                } else {
                    0 // Default handshake type
                };
                
                let sender_id_hex = packet.sender_id_hex();
                debug!("Simple handshake request from {} (type: {})", sender_id_hex, handshake_type);
                
                // Initiate noise handshake if requested
                if handshake_type == 1 { // Noise handshake
                    self.delegate.should_initiate_noise_handshake(sender_id_hex).await;
                }
            }
        }
        
        Ok(())
    }
    
    // Placeholder handlers for iOS-compatible message types
    async fn handle_delivery_status_request(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling delivery status request from {}", from_bluetooth_address);
        
        // Parse the message ID being requested from payload
        if packet.payload.len() < 16 {
            debug!("Delivery status request payload too short");
            return Ok(());
        }
        
        let message_id = String::from_utf8_lossy(&packet.payload[..16]).to_string();
        let sender_id_hex = packet.sender_id_hex();
        
        debug!("Delivery status requested for message {} by {}", message_id, sender_id_hex);
        
        // In iOS this is low priority - just log for now since we don't have delivery tracking yet
        // TODO: Implement actual delivery status lookup and response
        
        Ok(())
    }
    
    async fn handle_protocol_ack(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling protocol ACK from {}", from_bluetooth_address);
        
        let sender_id_hex = packet.sender_id_hex();
        
        // Based on iOS implementation, protocol ACKs are used to confirm packet delivery
        // For now, just log the acknowledgment - in a full implementation this would:
        // 1. Parse the ProtocolAck structure from payload
        // 2. Remove from pending ACKs tracking
        // 3. Mark packet as acknowledged in delivery tracking
        
        debug!("Protocol ACK received from {} ({} bytes payload)", sender_id_hex, packet.payload.len());
        
        // TODO: Parse ProtocolAck structure and update pending ACK tracking
        
        Ok(())
    }
    
    async fn handle_protocol_nack(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling protocol NACK from {}", from_bluetooth_address);
        
        let sender_id_hex = packet.sender_id_hex();
        
        // Based on iOS implementation, protocol NACKs indicate failure/rejection
        // This can indicate version mismatches, decryption failures, etc.
        
        // Parse the NACK structure to understand the error
        match crate::protocol::ProtocolNack::from_binary(&packet.payload) {
            Ok(nack) => {
                error!("Protocol NACK from {}: packet_type={}, error_code={:?}, reason: {}", 
                       sender_id_hex, nack.packet_type, nack.error_code, nack.reason);
                
                // Handle specific error codes
                match nack.error_code {
                    crate::protocol::NackErrorCode::DecryptionFailed => {
                        error!("Decryption failure reported by {} - may need to re-establish session", sender_id_hex);
                        // Could clear crypto state here if needed
                    }
                    crate::protocol::NackErrorCode::UnsupportedVersion => {
                        error!("Version mismatch with {}", sender_id_hex);
                    }
                    crate::protocol::NackErrorCode::HandshakeFailed => {
                        error!("Handshake failure with {} - {}", sender_id_hex, nack.reason);
                    }
                    _ => {
                        error!("Protocol error from {}: {:?} - {}", sender_id_hex, nack.error_code, nack.reason);
                    }
                }
                
                // Notify delegate with detailed error
                let nack_message = crate::model::BitchatMessage {
                    id: format!("protocol-nack-{}-{}", sender_id_hex, chrono::Utc::now().timestamp_millis()),
                    content: format!("Protocol error: {}", nack.reason),
                    sender: "System".to_string(),
                    sender_peer_id: Some(sender_id_hex.clone()),
                    timestamp: chrono::Utc::now(),
                    is_private: false,
                    is_relay: false,
                    original_sender: None,
                    recipient_nickname: None,
                    mentions: None,
                    channel: None,
                    is_encrypted: false,
                    encrypted_content: None,
                };
                
                self.delegate.did_receive_message(nack_message).await;
            }
            Err(e) => {
                error!("Failed to parse NACK from {}: {}", sender_id_hex, e);
            }
        }
        
        Ok(())
    }
    
    async fn handle_system_validation(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling system validation from {}", from_bluetooth_address);
        
        let sender_id_hex = packet.sender_id_hex();
        
        // System validation is an encrypted ping to verify session health
        // We need to decrypt it to validate the session is working
        
        debug!("System validation ping received from {} ({} bytes encrypted payload)", 
               sender_id_hex, packet.payload.len());
        
        // Forward to delegate for validation - it will handle decryption and send NACK if needed
        self.delegate.did_receive_system_validation(sender_id_hex, packet).await;
        
        Ok(())
    }
    
    async fn handle_favorited(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling favorited notification from {}", from_bluetooth_address);
        
        let sender_id_hex = packet.sender_id_hex();
        
        // Create a system message for the favorite notification
        let favorite_message = crate::model::BitchatMessage {
            id: format!("favorited-{}-{}", sender_id_hex, chrono::Utc::now().timestamp_millis()),
            content: format!("{} added you as a favorite", &sender_id_hex[..8]),
            sender: "System".to_string(),
            sender_peer_id: Some(sender_id_hex),
            timestamp: chrono::Utc::now(),
            is_private: false,
            is_relay: false,
            original_sender: None,
            recipient_nickname: None,
            mentions: None,
            channel: None,
            is_encrypted: false,
            encrypted_content: None,
        };
        
        self.delegate.did_receive_message(favorite_message).await;
        Ok(())
    }
    
    async fn handle_fragment(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling fragment from {} (type: {:?})", from_bluetooth_address, packet.message_type);
        
        // Android reassembles fragments in PacketProcessor
        // For now, we're handling this in bluetooth_mesh_service
        // TODO: Move fragment reassembly here to match Android's architecture
        
        warn!("Fragment handling should be moved from bluetooth_mesh_service to here");
        Ok(())
    }
    
    async fn handle_unfavorited(&self, packet: Packet, from_bluetooth_address: String) -> Result<()> {
        debug!("Handling unfavorited notification from {}", from_bluetooth_address);
        
        let sender_id_hex = packet.sender_id_hex();
        
        // Create a system message for the unfavorite notification
        let unfavorite_message = crate::model::BitchatMessage {
            id: format!("unfavorited-{}-{}", sender_id_hex, chrono::Utc::now().timestamp_millis()),
            content: format!("{} removed you as a favorite", &sender_id_hex[..8]),
            sender: "System".to_string(),
            sender_peer_id: Some(sender_id_hex),
            timestamp: chrono::Utc::now(),
            is_private: false,
            is_relay: false,
            original_sender: None,
            recipient_nickname: None,
            mentions: None,
            channel: None,
            is_encrypted: false,
            encrypted_content: None,
        };
        
        self.delegate.did_receive_message(unfavorite_message).await;
        Ok(())
    }
}
