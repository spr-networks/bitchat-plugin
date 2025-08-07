use crate::{Error, Result};
use crate::mesh::{
    BluetoothConnectionManager, BluetoothMeshDelegate, PeerManager, 
    FragmentManager, PacketProcessor
};
use crate::protocol::{BinaryProtocol, MessageType, Packet, SpecialRecipients};
use crate::model::BitchatMessage;
use crate::crypto::EncryptionService;
use std::sync::Arc;
use log::{debug, error, info, warn};

pub struct BluetoothMeshService {
    connection_manager: Arc<BluetoothConnectionManager>,
    peer_manager: Arc<PeerManager>,
    fragment_manager: Arc<FragmentManager>,
    packet_processor: Arc<PacketProcessor>,
    delegate: Arc<dyn BluetoothMeshDelegate>,
    peer_id: [u8; 8],
    encryption_service: Arc<EncryptionService>,
}

impl BluetoothMeshService {
    pub async fn new(delegate: Arc<dyn BluetoothMeshDelegate>) -> Result<Self> {
        let connection_manager = Arc::new(BluetoothConnectionManager::new().await?);
        let peer_manager = Arc::new(PeerManager::new());
        let fragment_manager = Arc::new(FragmentManager::new());
        let packet_processor = Arc::new(PacketProcessor::new(delegate.clone(), peer_manager.clone()));
        let encryption_service = Arc::new(EncryptionService::new()?);
        
        // Generate random peer ID (will be overridden by with_peer_id if needed)
        let mut peer_id = [0u8; 8];
        getrandom::getrandom(&mut peer_id)
            .map_err(|e| Error::Other(format!("Failed to generate peer ID: {}", e)))?;
        
        Ok(Self {
            connection_manager,
            peer_manager,
            fragment_manager,
            packet_processor,
            delegate,
            peer_id,
            encryption_service,
        })
    }
    
    pub fn with_peer_id(mut self, peer_id: [u8; 8]) -> Self {
        self.peer_id = peer_id;
        self
    }
    
    pub async fn start(&self) -> Result<()> {
        info!("Starting Bluetooth mesh service with peer ID: {}", self.get_peer_id_hex());
        
        // Set up data handler
        let fragment_manager = self.fragment_manager.clone();
        let packet_processor = self.packet_processor.clone();
        let peer_manager = self.peer_manager.clone();
        
        let data_handler: crate::mesh::bluetooth_connection_manager::DataHandler = 
            Arc::new(move |data, from_address| {
                let fragment_manager = fragment_manager.clone();
                let packet_processor = packet_processor.clone();
                let _peer_manager = peer_manager.clone();
                
                tokio::spawn(async move {
                    // Clone from_address at the beginning
                    let from_address_clone = from_address.clone();
                    
                    
                    // Check for special connection event
                    if data.len() == 2 && data[0] == 0xFF && data[1] == 0xFF && from_address.starts_with("CONNECTED:") {
                        debug!("Connection event received");
                        return;
                    }
                    
                    // First, try to parse as a packet to check message type
                    match BinaryProtocol::decode(&data) {
                        Ok(packet) => {
                            debug!("Decoded packet: type={:?}, sender={}, payload_len={}", 
                                packet.message_type, packet.sender_id_hex(), packet.payload.len());
                            match packet.message_type {
                                MessageType::FragmentStart | MessageType::FragmentContinue | MessageType::FragmentEnd => {
                                    // This is a fragment, decode the payload
                                    match FragmentManager::decode_fragment_payload(&packet.payload) {
                                        Ok((header, original_type, fragment_data)) => {
                                            match fragment_manager.add_fragment(header, original_type, fragment_data.to_vec()).await {
                                                Ok(Some(complete_data)) => {
                                                    // Process complete packet
                                                    if let Err(e) = packet_processor.process_raw_data(&complete_data, from_address_clone.clone()).await {
                                                        error!("Failed to process reassembled packet: {}", e);
                                                    }
                                                }
                                                Ok(None) => {
                                                    // Fragment stored, waiting for more
                                                    debug!("Fragment stored, waiting for more");
                                                }
                                                Err(e) => {
                                                    error!("Failed to handle fragment: {}", e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!("Failed to decode fragment payload: {}", e);
                                        }
                                    }
                                }
                                _ => {
                                    // Not a fragment, process normally
                                    if let Err(e) = packet_processor.process_packet(packet, from_address_clone.clone()).await {
                                        error!("Failed to process packet: {}", e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to decode packet: {}", e);
                        }
                    }
                    
                    // Note: We don't add the Bluetooth address as a peer ID here
                    // The actual peer ID comes from inside the packet (sender_id)
                });
            });
        
        self.connection_manager.set_data_handler(data_handler).await;
        
        // Start GATT server
        self.connection_manager.start_gatt_server().await?;
        
        // Start advertising
        self.connection_manager.start_advertising().await?;
        
        // Start scanning
        self.connection_manager.start_scanning().await?;
        
        // Start device discovery monitor
        self.connection_manager.start_device_discovery_monitor().await?;
        
        // Send initial announce after a short delay to allow connections to establish
        // and periodically thereafter
        let service_clone = self.clone();
        tokio::spawn(async move {
            // Initial delay to allow connections
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            
            // Send announces periodically (every 10 seconds to maintain peer availability)
            // iOS marks peers unavailable after ~30s of no messages
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
            let mut first_run = true;
            
            loop {
                if let Err(e) = service_clone.send_announce().await {
                    error!("Failed to send announce: {}", e);
                }
                
                // Also send NoiseIdentityAnnouncement (especially important on first run)
                if first_run {
                    tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;
                }
                
                if let Err(e) = service_clone.send_noise_identity_announcement().await {
                    error!("Failed to send noise identity announcement: {}", e);
                }
                
                first_run = false;
                interval.tick().await;
            }
        });
        
        // Start periodic cleanup of stale peers
        let service_clone = self.clone();
        let delegate_clone = self.delegate.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                
                // Clean up peers that haven't been seen in 60 seconds
                let removed_peers = service_clone.peer_manager.cleanup_stale_peers(60).await;
                
                // Notify delegate about disconnections
                for peer_id in removed_peers {
                    info!("Removing stale peer: {}", peer_id);
                    delegate_clone.did_disconnect_from_peer(peer_id).await;
                }
            }
        });
        
        Ok(())
    }
    
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Bluetooth mesh service");
        
        // Send leave announcement before stopping
        self.send_leave().await?;
        
        // Stop advertising
        self.connection_manager.stop_advertising().await?;
        
        // Stop scanning
        self.connection_manager.stop_scanning().await?;
        
        // Stop GATT server
        self.connection_manager.stop_gatt_server().await?;
        
        // Disconnect all peers
        let addresses = self.connection_manager.get_connected_addresses().await;
        for address in addresses {
            self.connection_manager.disconnect_from_device(&address).await?;
        }
        
        Ok(())
    }
    
    pub async fn send_message(&self, message: BitchatMessage) -> Result<()> {
        let message_binary = message.to_binary_payload()
            .map_err(|e| Error::Protocol(format!("Failed to serialize message: {}", e)))?;
            
        let packet = Packet::new(
            MessageType::Message,
            self.peer_id,
            message_binary,
        ).with_recipient(SpecialRecipients::BROADCAST);
        
        self.broadcast_packet(packet).await
    }
    
    pub async fn send_private_message(&self, message: BitchatMessage, recipient_id: [u8; 8]) -> Result<()> {
        let recipient_id_hex = hex::encode(&recipient_id);
        
        // Check if we have a completed Noise session with this peer
        let noise_service = self.encryption_service.get_noise_service();
        if noise_service.has_completed_session(&recipient_id_hex).await {
            info!("Sending encrypted private message to {}", recipient_id_hex);
            
            // Serialize the message
            let message_binary = message.to_binary_payload()
                .map_err(|e| Error::Protocol(format!("Failed to serialize message: {}", e)))?;
            
            // Create a regular packet with the message
            let inner_packet = Packet::new(
                MessageType::Message,
                self.peer_id,
                message_binary,
            ).with_recipient(recipient_id);
            
            // Encrypt the entire packet
            let encrypted_packet = noise_service.encrypt_packet(self.peer_id, &recipient_id_hex, inner_packet).await?;
            
            info!("Sending NoiseEncrypted packet to {} (type: {:?}, {} bytes encrypted)", 
                recipient_id_hex, encrypted_packet.message_type, encrypted_packet.payload.len());
            
            // Send the encrypted packet
            self.broadcast_packet(encrypted_packet).await
        } else {
            warn!("No Noise session with {} - refusing to send unencrypted DM", recipient_id_hex);
            
            // Send a noise identity announcement to start handshake
            info!("Sending NoiseIdentityAnnouncement to {} to initiate handshake", recipient_id_hex);
            self.send_noise_identity_announcement_to(Some(recipient_id_hex.clone())).await?;
            
            // Always send handshake request - it will determine internally who should initiate
            info!("Sending handshake request to establish secure connection with {}", recipient_id_hex);
            self.send_handshake_request(recipient_id_hex).await?;
            
            Err(Error::Protocol("No secure session established - handshake initiated, please try again".to_string()))
        }
    }
    
    pub async fn send_private_message_by_nickname(&self, message: BitchatMessage, recipient_nickname: String) -> Result<()> {
        // Look up peer by nickname
        if let Some(peer) = self.peer_manager.get_peer_by_nickname(&recipient_nickname).await {
            // Convert hex peer ID to bytes
            let peer_id_bytes = hex::decode(&peer.id)
                .map_err(|e| Error::Protocol(format!("Invalid peer ID hex: {}", e)))?;
            
            if peer_id_bytes.len() != 8 {
                return Err(Error::Protocol("Peer ID must be 8 bytes".to_string()));
            }
            
            let mut recipient_id = [0u8; 8];
            recipient_id.copy_from_slice(&peer_id_bytes);
            
            self.send_private_message(message, recipient_id).await
        } else {
            Err(Error::Protocol(format!("No peer found with nickname: {}", recipient_nickname)))
        }
    }
    
    pub async fn send_announce(&self) -> Result<()> {
        // Get current nickname from delegate
        let nickname = self.delegate.get_my_nickname().await;
        let payload = nickname.as_bytes().to_vec();
        
        
        let packet = Packet::new(
            MessageType::Announce,
            self.peer_id,
            payload,
        );
        
        self.broadcast_packet(packet).await
    }
    
    async fn send_leave(&self) -> Result<()> {
        let packet = Packet::new(
            MessageType::Leave,
            self.peer_id,
            Vec::new(),
        );
        
        self.broadcast_packet(packet).await
    }
    
    async fn broadcast_packet(&self, packet: Packet) -> Result<()> {
        let data = BinaryProtocol::encode(&packet)?;
        
        // Send to all connected peers (outgoing connections where we are central)
        let addresses = self.connection_manager.get_connected_addresses().await;
        
        // Check if we have subscribed centrals (incoming connections where we are peripheral)
        let has_centrals = self.connection_manager.has_subscribed_centrals().await;
        let centrals_count = self.connection_manager.get_subscribed_centrals_count().await;
        
        debug!("Broadcasting {:?} to {} peripherals, {} centrals", 
              packet.message_type, addresses.len(), centrals_count);
        
        
        if addresses.is_empty() && !has_centrals {
            debug!("No connected peers for {:?} message", packet.message_type);
            
            return Ok(());
        }
        
        // Check if needs fragmentation (matching Android's threshold)
        if data.len() > 512 {
            // Generate fragment ID (8 random bytes)
            let mut fragment_id = [0u8; 8];
            getrandom::getrandom(&mut fragment_id)
                .map_err(|e| Error::Other(format!("Failed to generate fragment ID: {}", e)))?;
            
            // Calculate total fragments
            let total_fragments = ((data.len() + 499) / 500) as u16; // 500 byte fragments
            
            for (index, chunk) in data.chunks(500).enumerate() {
                // Create fragment payload
                let fragment_payload = FragmentManager::create_fragment_payload(
                    &fragment_id,
                    index as u16,
                    total_fragments,
                    packet.message_type.as_u8(),
                    chunk,
                );
                
                // Determine fragment type
                let fragment_type = if index == 0 {
                    MessageType::FragmentStart
                } else if index == (total_fragments - 1) as usize {
                    MessageType::FragmentEnd
                } else {
                    MessageType::FragmentContinue
                };
                
                // Create fragment packet
                let mut fragment_packet = Packet::new(
                    fragment_type,
                    packet.sender_id,
                    fragment_payload,
                );
                fragment_packet.ttl = packet.ttl;
                fragment_packet.timestamp = packet.timestamp;
                
                // Encode and send fragment packet
                let fragment_data = BinaryProtocol::encode(&fragment_packet)?;
                
                for address in &addresses {
                    match self.connection_manager.send_data(address, &fragment_data).await {
                        Ok(_) => debug!("Sent fragment {}/{} to {}", index + 1, total_fragments, address),
                        Err(e) => {
                            error!("Failed to send fragment to {}: {}", address, e);
                            // Remove disconnected peer from our connection list
                            if let Err(cleanup_err) = self.connection_manager.disconnect_from_device(address).await {
                                warn!("Failed to cleanup disconnected device {}: {}", address, cleanup_err);
                            }
                        }
                    }
                }
                
                // Also send fragments to subscribed centrals
                if has_centrals {
                    match self.connection_manager.send_notification(&fragment_data).await {
                        Ok(_) => debug!("Sent fragment {}/{} notification to centrals", index + 1, total_fragments),
                        Err(e) => error!("Failed to send fragment notification: {}", e),
                    }
                }
            }
        } else {
            // Send without fragmentation for small messages
            
            // Send to connected peripherals (where we are central)
            for address in addresses {
                match self.connection_manager.send_data(&address, &data).await {
                    Ok(_) => debug!("Sent message to peripheral {}", address),
                    Err(e) => {
                        error!("Failed to send data to peripheral {}: {}", address, e);
                        // Remove disconnected peer from our connection list
                        if let Err(cleanup_err) = self.connection_manager.disconnect_from_device(&address).await {
                            warn!("Failed to cleanup disconnected device {}: {}", address, cleanup_err);
                        }
                    }
                }
            }
            
            // Also send to subscribed centrals via notifications (where we are peripheral)
            if has_centrals {
                match self.connection_manager.send_notification(&data).await {
                    Ok(_) => debug!("Sent notification to subscribed centrals"),
                    Err(e) => error!("Failed to send notification to centrals: {}", e),
                }
            }
        }
        
        Ok(())
    }
    
    pub fn get_peer_id(&self) -> [u8; 8] {
        self.peer_id
    }
    
    pub fn get_peer_id_hex(&self) -> String {
        hex::encode(&self.peer_id)
    }
    
    pub fn get_peer_manager(&self) -> Arc<PeerManager> {
        self.peer_manager.clone()
    }
    
    pub fn get_connection_manager(&self) -> Arc<BluetoothConnectionManager> {
        self.connection_manager.clone()
    }
    
    pub fn get_encryption_service(&self) -> Arc<EncryptionService> {
        self.encryption_service.clone()
    }
    
    pub fn get_packet_processor(&self) -> Arc<PacketProcessor> {
        self.packet_processor.clone()
    }
    
    pub async fn send_version_ack(&self, peer_id_hex: String, agreed_version: u8) -> Result<()> {
        debug!("Sending version ack to {} with version {}", peer_id_hex, agreed_version);
        
        let packet = Packet::new(
            MessageType::VersionAck,
            self.peer_id,
            vec![agreed_version],
        );
        
        self.broadcast_packet(packet).await
    }
    
    pub async fn initiate_noise_handshake(&self, peer_id_hex: String) -> Result<()> {
        info!("Initiating noise handshake with {}", peer_id_hex);
        
        // Get the noise encryption service and initiate handshake
        let noise_service = self.encryption_service.get_noise_service();
        let packet = noise_service.initiate_handshake(self.peer_id, peer_id_hex.clone()).await?;
        
        info!("Sending NoiseHandshakeInit to {} (payload: {} bytes)", peer_id_hex, packet.payload.len());
        self.broadcast_packet(packet).await
    }
    
    pub async fn send_handshake_request(&self, target_peer_id: String) -> Result<()> {
        info!("Sending handshake request to {}", target_peer_id);
        
        // Check if we already have an established session
        let noise_service = self.encryption_service.get_noise_service();
        if noise_service.has_completed_session(&target_peer_id).await {
            debug!("Already have established session with {} - skipping handshake request", target_peer_id);
            return Ok(());
        }
        
        let my_peer_id = self.get_peer_id_hex();
        let my_nickname = self.delegate.get_my_nickname().await;
        
        // Determine who should initiate based on peer ID comparison
        // Lower peer ID becomes the initiator (matching iOS/Android logic)
        let initiator_id = if my_peer_id < target_peer_id {
            my_peer_id.clone()
        } else {
            target_peer_id.clone()
        };
        
        info!("HandshakeRequest: my_id={}, target_id={}, initiator will be: {}", 
            my_peer_id, target_peer_id, initiator_id);
        
        let handshake_request = crate::protocol::HandshakeRequest::new(
            my_peer_id.clone(),
            my_nickname,
            initiator_id.clone(), // The peer with lower ID should initiate
            1, // Default pending message count
        );
        
        let packet = Packet::new(
            MessageType::HandshakeRequest,
            self.peer_id,
            handshake_request.to_binary(),
        );
        
        // Only initiate if we're the one who should (lower peer ID)
        if initiator_id == my_peer_id {
            info!("We have lower peer ID, initiating handshake with {}", target_peer_id);
            if let Err(e) = self.initiate_noise_handshake(target_peer_id).await {
                warn!("Failed to initiate noise handshake: {}", e);
            }
        } else {
            info!("They have lower peer ID, waiting for {} to initiate", target_peer_id);
        }
        
        self.broadcast_packet(packet).await
    }
    
    pub async fn send_noise_identity_announcement(&self) -> Result<()> {
        self.send_noise_identity_announcement_to(None).await
    }
    
    pub async fn handle_noise_handshake_init(&self, peer_id: String, packet: Packet) -> Result<()> {
        info!("Handling NoiseHandshakeInit from {}", peer_id);
        
        let my_peer_id = self.get_peer_id_hex();
        let noise_service = self.encryption_service.get_noise_service();
        
        // Check if we already have an established session
        if noise_service.has_completed_session(&peer_id).await {
            // Determine who should be initiator based on peer ID comparison
            let should_be_initiator = my_peer_id < peer_id;
            
            if should_be_initiator {
                // We should be initiator but peer is initiating - likely they had a session failure
                warn!("Received handshake init from {} who should be responder - likely session mismatch, clearing and accepting", peer_id);
            } else {
                // Peer is initiating despite us having a session - they must have cleared for a reason
                info!("Received handshake init from {} with existing session - clearing and accepting to re-establish encryption", peer_id);
            }
            // Clear the existing session to allow new handshake
            noise_service.clear_session(&peer_id).await;
        }
        
        // If we have a handshaking session (not established), reset it to allow new handshake
        if noise_service.has_session(&peer_id).await && !noise_service.has_completed_session(&peer_id).await {
            info!("Received handshake init from {} while already handshaking - resetting to allow new handshake", peer_id);
            // Clear the incomplete session
            noise_service.clear_session(&peer_id).await;
        }
        
        // Handle the handshake initiation
        let response_packet = noise_service.handle_handshake_init(self.peer_id, peer_id.clone(), packet.clone()).await?;
        
        info!("Sending NoiseHandshakeResp to {} (payload: {} bytes)", peer_id, response_packet.payload.len());
        self.broadcast_packet(response_packet).await?;
        
        // Send protocol ACK for successfully processed handshake initiation
        self.send_protocol_ack(packet, peer_id.clone()).await?;
        
        Ok(())
    }
    
    pub async fn handle_noise_handshake_response(&self, peer_id: String, packet: Packet) -> Result<()> {
        info!("Handling NoiseHandshakeResp from {}", peer_id);
        
        // Process the response
        let noise_service = self.encryption_service.get_noise_service();
        let third_message = noise_service.handle_handshake_response(self.peer_id, peer_id.clone(), packet.clone()).await?;
        
        // If we need to send a third message (for XX pattern completion)
        if let Some(third_packet) = third_message {
            info!("Sending third handshake message to {} to complete XX pattern", peer_id);
            self.broadcast_packet(third_packet).await?;
            // Initiator's handshake is complete after sending third message
            debug!("Noise handshake completed with {} (as initiator)", peer_id);
        } else {
            // Responder's handshake is complete after processing third message (no response needed)
            debug!("Noise handshake completed with {} (as responder)", peer_id);
        }
        
        // Sync the static key from noise service to peer manager
        if let Some(static_key) = noise_service.get_peer_static_key(&peer_id).await {
            if let Err(e) = self.peer_manager.update_peer_static_key(&peer_id, static_key).await {
                warn!("Failed to sync static key to peer manager for {}: {}", peer_id, e);
            } else {
                info!("Successfully synced static key to peer manager for {}", peer_id);
            }
        } else {
            warn!("No static key available from noise service for {} after handshake", peer_id);
        }
        
        // Notify delegate about successful handshake
        self.delegate.did_complete_noise_handshake(peer_id.clone()).await;
        
        // Send protocol ACK for successfully processed handshake response
        self.send_protocol_ack(packet, peer_id).await?;
        
        Ok(())
    }
    
    async fn send_protocol_ack(&self, original_packet: Packet, to_peer_id: String) -> Result<()> {
        // Create protocol ACK packet
        let ack_packet = Packet::new(
            MessageType::ProtocolAck,
            self.peer_id,
            vec![], // Empty payload for ACK
        );
        
        info!("Sending ProtocolAck to {} for message type {:?}", to_peer_id, original_packet.message_type);
        self.broadcast_packet(ack_packet).await
    }
    
    pub async fn send_protocol_nack(&self, original_packet: Packet, to_peer_id: String, reason: String, error_code: crate::protocol::NackErrorCode) -> Result<()> {
        // Generate packet ID from packet content hash
        let packet_id = self.generate_packet_id(&original_packet);
        
        let my_peer_id = self.get_peer_id_hex();
        
        let nack = crate::protocol::ProtocolNack::new(
            packet_id,
            hex::encode(original_packet.sender_id),
            my_peer_id,
            original_packet.message_type.as_u8(),
            reason,
            error_code,
        );
        
        let nack_packet = Packet::new(
            MessageType::ProtocolNack,
            self.peer_id,
            nack.to_binary(),
        );
        
        info!("Sending ProtocolNack to {} for message type {:?}, reason: {}", 
            to_peer_id, original_packet.message_type, nack.reason);
        self.broadcast_packet(nack_packet).await
    }
    
    fn generate_packet_id(&self, packet: &Packet) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(&[packet.message_type.as_u8()]);
        hasher.update(&packet.sender_id);
        if let Some(recipient_id) = &packet.recipient_id {
            hasher.update(recipient_id);
        }
        hasher.update(&packet.timestamp.timestamp_millis().to_be_bytes());
        hasher.update(&packet.payload);
        
        hasher.finalize()[..16].to_vec() // Use first 16 bytes of hash as packet ID
    }
    
    pub async fn send_noise_identity_announcement_to(&self, target_peer_id: Option<String>) -> Result<()> {
        
        let my_peer_id = self.get_peer_id_hex();
        let my_nickname = self.delegate.get_my_nickname().await;
        
        // Get real keys from encryption service
        let noise_service = self.encryption_service.get_noise_service();
        let static_public_key = noise_service.get_static_public_key();
        let signing_public_key = noise_service.get_identity_public_key();
        
        // Create the announcement timestamp first, then use it for signature
        let timestamp = chrono::Utc::now();
        let timestamp_ms = timestamp.timestamp_millis() as u64;
        
        // Create signature binding data (matching iOS/Android format)
        let binding_data = [
            my_peer_id.as_bytes(),
            &static_public_key,
            timestamp_ms.to_string().as_bytes(),
        ].concat();
        
        // Sign with real Ed25519 key
        let signature = noise_service.sign_data(&binding_data).await?;
        
        let announcement = crate::protocol::NoiseIdentityAnnouncement::new_with_timestamp(
            my_peer_id,
            static_public_key,
            signing_public_key,
            my_nickname,
            timestamp,
            None, // No previous peer ID for now
            signature,
        );
        
        let announcement_data = announcement.to_binary();
        let mut packet = Packet::new(
            MessageType::NoiseIdentityAnnounce,
            self.peer_id,
            announcement_data.clone(),
        );
        
        // If target specified, make it a private message
        if let Some(target_id) = target_peer_id {
            // Convert hex peer ID to bytes
            if let Ok(target_bytes) = hex::decode(&target_id) {
                if target_bytes.len() == 8 {
                    let mut recipient_id = [0u8; 8];
                    recipient_id.copy_from_slice(&target_bytes);
                    packet = packet.with_recipient(recipient_id);
                    info!("Targeting NoiseIdentityAnnouncement to {}", target_id);
                }
            }
        }
        
        
        self.broadcast_packet(packet).await
    }
    
    pub async fn send_delivery_ack(&self, message_id: String, recipient_peer_id: String) -> Result<()> {
        debug!("Sending delivery ack for message {} to {}", message_id, recipient_peer_id);
        
        // Convert recipient peer ID to bytes
        let recipient_id_bytes = hex::decode(&recipient_peer_id)
            .map_err(|e| Error::Other(format!("Failed to decode peer ID: {}", e)))?;
        if recipient_id_bytes.len() != 8 {
            return Err(Error::Other("Invalid recipient peer ID length".to_string()));
        }
        let mut recipient_id = [0u8; 8];
        recipient_id.copy_from_slice(&recipient_id_bytes);
        
        // Create payload with proper DeliveryAck structure
        let mut payload = Vec::new();
        
        // Convert UUID string to 16 bytes (removing hyphens)
        let clean_uuid = message_id.replace("-", "");
        let uuid_bytes = hex::decode(&clean_uuid)
            .map_err(|e| Error::Other(format!("Failed to decode message UUID: {}", e)))?;
        if uuid_bytes.len() != 16 {
            return Err(Error::Other(format!("Invalid UUID length: {} (expected 16)", uuid_bytes.len())));
        }
        payload.extend_from_slice(&uuid_bytes); // originalMessageID (16 bytes)
        
        // Generate ackID
        let ack_id = uuid::Uuid::new_v4();
        let ack_id_bytes = hex::decode(&ack_id.to_string().replace("-", ""))
            .map_err(|e| Error::Other(format!("Failed to encode ack UUID: {}", e)))?;
        payload.extend_from_slice(&ack_id_bytes); // ackID (16 bytes)
        
        // Add recipientID (8 bytes) - same as the target we're sending to
        payload.extend_from_slice(&recipient_id_bytes);
        
        // Add hopCount (1 byte)
        payload.push(3); // Default hop count
        
        // Add timestamp (8 bytes, milliseconds since epoch)
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;
        payload.extend_from_slice(&timestamp.to_be_bytes());
        
        // Add recipientNickname (string with length prefix)
        // For now, use empty string since we don't track nicknames in acks
        let nickname = "ack";
        payload.push(nickname.len() as u8);
        payload.extend_from_slice(nickname.as_bytes());
        
        // Create and send packet
        let packet = Packet::new(
            MessageType::DeliveryAck,
            self.peer_id,
            payload
        ).with_recipient(recipient_id);
        
        self.broadcast_packet(packet).await
    }
    
    pub async fn send_read_receipt(&self, message_id: String, recipient_peer_id: String) -> Result<()> {
        debug!("Sending read receipt for message {} to {}", message_id, recipient_peer_id);
        
        // Convert recipient peer ID to bytes
        let recipient_id_bytes = hex::decode(&recipient_peer_id)
            .map_err(|e| Error::Other(format!("Failed to decode peer ID: {}", e)))?;
        if recipient_id_bytes.len() != 8 {
            return Err(Error::Other("Invalid recipient peer ID length".to_string()));
        }
        let mut recipient_id = [0u8; 8];
        recipient_id.copy_from_slice(&recipient_id_bytes);
        
        // Create payload with proper ReadReceipt structure
        let mut payload = Vec::new();
        
        // Convert UUID string to 16 bytes (removing hyphens)
        let clean_uuid = message_id.replace("-", "");
        let uuid_bytes = hex::decode(&clean_uuid)
            .map_err(|e| Error::Other(format!("Failed to decode message UUID: {}", e)))?;
        if uuid_bytes.len() != 16 {
            return Err(Error::Other(format!("Invalid UUID length: {} (expected 16)", uuid_bytes.len())));
        }
        payload.extend_from_slice(&uuid_bytes); // originalMessageID (16 bytes)
        
        // Generate receiptID
        let receipt_id = uuid::Uuid::new_v4();
        let receipt_id_bytes = hex::decode(&receipt_id.to_string().replace("-", ""))
            .map_err(|e| Error::Other(format!("Failed to encode receipt UUID: {}", e)))?;
        payload.extend_from_slice(&receipt_id_bytes); // receiptID (16 bytes)
        
        // Add readerID (8 bytes) - our own peer ID
        payload.extend_from_slice(&self.peer_id);
        
        // Add timestamp (8 bytes, milliseconds since epoch)
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;
        payload.extend_from_slice(&timestamp.to_be_bytes());
        
        // Add readerNickname (string with length prefix)
        // For now, use empty string since we'll get nickname from delegate
        let nickname = "reader";
        payload.push(nickname.len() as u8);
        payload.extend_from_slice(nickname.as_bytes());
        
        // Create and send packet
        let packet = Packet::new(
            MessageType::ReadReceipt,
            self.peer_id,
            payload
        ).with_recipient(recipient_id);
        
        self.broadcast_packet(packet).await
    }
}

impl Clone for BluetoothMeshService {
    fn clone(&self) -> Self {
        Self {
            connection_manager: self.connection_manager.clone(),
            peer_manager: self.peer_manager.clone(),
            fragment_manager: self.fragment_manager.clone(),
            packet_processor: self.packet_processor.clone(),
            delegate: self.delegate.clone(),
            peer_id: self.peer_id,
            encryption_service: self.encryption_service.clone(),
        }
    }
}
