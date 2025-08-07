use crate::{Error, Result};
use crate::protocol::{Packet, MessageType};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use snow::{Builder, HandshakeState, TransportState};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{info, warn, debug};
use sha2::{Sha256, Digest};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

struct NoiseSession {
    peer_id: String,
    handshake_state: Option<HandshakeState>,
    transport_state: Option<TransportState>,
    is_initiator: bool,
    send_nonce: u32,
    recv_nonce: u32,
}

pub struct SnowNoiseService {
    // Ed25519 identity keys
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    
    // X25519 static keys for Noise (stored as raw bytes)
    static_private_key: [u8; 32],
    static_public_key: [u8; 32],
    
    // Active sessions
    sessions: Arc<RwLock<HashMap<String, NoiseSession>>>,
    
    // Peer public keys
    peer_keys: Arc<RwLock<HashMap<String, VerifyingKey>>>,
    peer_static_keys: Arc<RwLock<HashMap<String, [u8; 32]>>>,
}

impl SnowNoiseService {
    pub fn new() -> Result<Self> {
        // Generate Ed25519 identity keys
        let mut signing_key_bytes = [0u8; 32];
        getrandom::getrandom(&mut signing_key_bytes)
            .map_err(|e| Error::Encryption(format!("Failed to generate signing key: {}", e)))?;
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let verifying_key = signing_key.verifying_key();
        
        // Generate X25519 static keys
        let mut static_private_key = [0u8; 32];
        getrandom::getrandom(&mut static_private_key)
            .map_err(|e| Error::Encryption(format!("Failed to generate static key: {}", e)))?;
        
        // Calculate public key using snow's builder
        let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
        let keypair = builder.generate_keypair()
            .map_err(|e| Error::Encryption(format!("Failed to generate keypair: {}", e)))?;
        
        // Use the generated keypair for consistency
        let mut static_public_key = [0u8; 32];
        static_public_key.copy_from_slice(&keypair.public[..32]);
        
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&keypair.private[..32]);
        
        Ok(Self {
            signing_key,
            verifying_key,
            static_private_key: private_key,
            static_public_key,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            peer_keys: Arc::new(RwLock::new(HashMap::new())),
            peer_static_keys: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    pub fn get_identity_public_key(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }
    
    pub fn get_static_public_key(&self) -> Vec<u8> {
        self.static_public_key.to_vec()
    }
    
    pub fn get_fingerprint(&self) -> String {
        // Generate fingerprint from SHA256 of static public key (iOS style)
        let mut hasher = Sha256::new();
        hasher.update(&self.static_public_key);
        let hash = hasher.finalize();
        
        // Convert to hex string
        hex::encode(hash)
    }
    
    pub fn calculate_fingerprint(public_key: &[u8]) -> String {
        // Calculate fingerprint from any public key
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let hash = hasher.finalize();
        
        hex::encode(hash)
    }
    
    pub fn format_fingerprint(fingerprint: &str) -> String {
        // Format fingerprint for display (4 groups of 4 chars per line, like iOS)
        let uppercased = fingerprint.to_uppercase();
        let mut formatted = String::new();
        
        for (index, char) in uppercased.chars().enumerate() {
            if index > 0 && index % 4 == 0 {
                if index % 16 == 0 {
                    formatted.push('\n');  // New line after every 16 characters
                } else {
                    formatted.push(' ');   // Space after every 4 characters
                }
            }
            formatted.push(char);
        }
        
        formatted
    }
    
    pub async fn get_peer_static_key(&self, peer_id: &str) -> Option<Vec<u8>> {
        let peer_keys = self.peer_static_keys.read().await;
        peer_keys.get(peer_id).map(|k| k.to_vec())
    }
    
    pub async fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signature = self.signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
    
    pub async fn store_peer_static_key(&self, peer_id: &str, public_key: &[u8]) -> Result<()> {
        if public_key.len() != 32 {
            return Err(Error::Encryption("Invalid static key length".to_string()));
        }
        
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(public_key);
        
        self.peer_static_keys.write().await.insert(peer_id.to_string(), key_bytes);
        info!("Stored static key for peer {}", peer_id);
        Ok(())
    }
    
    pub async fn initiate_handshake(&self, my_peer_id: [u8; 8], target_peer_id: String) -> Result<Packet> {
        info!("Initiating Noise handshake with {}", target_peer_id);
        
        // Check if we already have a session
        let mut sessions = self.sessions.write().await;
        if sessions.contains_key(&target_peer_id) {
            if sessions[&target_peer_id].transport_state.is_some() {
                return Err(Error::Noise("Already have completed session with peer".to_string()));
            }
        }
        
        // Create initiator handshake state
        let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
        let mut handshake = builder
            .local_private_key(&self.static_private_key)
            .build_initiator()
            .map_err(|e| Error::Encryption(format!("Failed to build initiator: {}", e)))?;
        
        // Create first handshake message (e)
        let mut buffer = vec![0u8; 65535];
        let msg_len = handshake.write_message(&[], &mut buffer)
            .map_err(|e| Error::Encryption(format!("Failed to write first message: {}", e)))?;
        buffer.truncate(msg_len);
        
        info!("Generated first handshake message ({} bytes)", buffer.len());
        
        // Store session
        sessions.insert(target_peer_id.clone(), NoiseSession {
            peer_id: target_peer_id.clone(),
            handshake_state: Some(handshake),
            transport_state: None,
            is_initiator: true,
            send_nonce: 0,
            recv_nonce: 0,
        });
        
        // Convert target peer ID to bytes
        let recipient_bytes = hex::decode(&target_peer_id)
            .map_err(|e| Error::Noise(format!("Invalid target peer ID: {}", e)))?;
        if recipient_bytes.len() != 8 {
            return Err(Error::Noise("Target peer ID must be 8 bytes".to_string()));
        }
        let mut recipient_id = [0u8; 8];
        recipient_id.copy_from_slice(&recipient_bytes);
        
        Ok(Packet::new(
            MessageType::NoiseHandshakeInit,
            my_peer_id,
            buffer,
        ).with_recipient(recipient_id))
    }
    
    pub async fn handle_handshake_init(&self, my_peer_id: [u8; 8], peer_id: String, packet: Packet) -> Result<Packet> {
        info!("Handling Noise handshake init from {} ({} bytes)", peer_id, packet.payload.len());
        
        let mut sessions = self.sessions.write().await;
        
        // Check if we already have a session
        if sessions.contains_key(&peer_id) {
            warn!("Already have session with {} - replacing", peer_id);
            sessions.remove(&peer_id);
        }
        
        // Get peer's static key if we have it
        let peer_static_keys = self.peer_static_keys.read().await;
        let peer_static_key = peer_static_keys.get(&peer_id);
        
        // Create responder handshake state
        let mut builder = Builder::new(NOISE_PATTERN.parse().unwrap());
        builder = builder.local_private_key(&self.static_private_key);
        
        // If we know the peer's static key, set it as remote static
        if let Some(key) = peer_static_key {
            debug!("Using known static key for peer {}", peer_id);
            builder = builder.remote_public_key(key);
        }
        
        let mut handshake = builder
            .build_responder()
            .map_err(|e| Error::Encryption(format!("Failed to build responder: {}", e)))?;
        
        // Process first message (e)
        let mut payload_buffer = vec![0u8; 65535];
        let payload_len = handshake.read_message(&packet.payload, &mut payload_buffer)
            .map_err(|e| Error::Encryption(format!("Failed to read first message: {}", e)))?;
        
        if payload_len > 0 {
            debug!("First message contained {} bytes of payload", payload_len);
        }
        
        // Generate second message (e, ee, s, es)
        let mut response_buffer = vec![0u8; 65535];
        let response_len = handshake.write_message(&[], &mut response_buffer)
            .map_err(|e| Error::Encryption(format!("Failed to write second message: {}", e)))?;
        response_buffer.truncate(response_len);
        
        info!("Generated second handshake message ({} bytes)", response_buffer.len());
        
        // Store session
        sessions.insert(peer_id.clone(), NoiseSession {
            peer_id: peer_id.clone(),
            handshake_state: Some(handshake),
            transport_state: None,
            is_initiator: false,
            send_nonce: 0,
            recv_nonce: 0,
        });
        
        Ok(Packet::new(
            MessageType::NoiseHandshakeResp,
            my_peer_id,
            response_buffer,
        ).with_recipient(packet.sender_id))
    }
    
    pub async fn handle_handshake_response(&self, my_peer_id: [u8; 8], peer_id: String, packet: Packet) -> Result<Option<Packet>> {
        info!("Handling Noise handshake response from {} ({} bytes)", peer_id, packet.payload.len());
        
        let mut sessions = self.sessions.write().await;
        
        // Get existing session
        let session = sessions.get_mut(&peer_id)
            .ok_or_else(|| Error::Noise(format!("No session found for {}", peer_id)))?;
        
        if !session.is_initiator {
            // We're the responder, process the third message (s, se)
            let mut handshake = session.handshake_state.take()
                .ok_or_else(|| Error::Noise("No handshake state".to_string()))?;
            
            let mut payload_buffer = vec![0u8; 65535];
            let payload_len = handshake.read_message(&packet.payload, &mut payload_buffer)
                .map_err(|e| Error::Encryption(format!("Failed to read third message: {}", e)))?;
            
            if payload_len > 0 {
                debug!("Third message contained {} bytes of payload", payload_len);
            }
            
            // Extract remote static key before converting to transport
            let remote_static_key = handshake.get_remote_static().map(|k| k.to_vec());
            if let Some(ref key) = remote_static_key {
                info!("Got remote static key for {} ({} bytes) as responder", peer_id, key.len());
                // Store the peer's static key
                let mut peer_keys = self.peer_static_keys.write().await;
                // Convert Vec<u8> to [u8; 32]
                if key.len() == 32 {
                    let mut key_array = [0u8; 32];
                    key_array.copy_from_slice(&key);
                    peer_keys.insert(peer_id.clone(), key_array);
                } else {
                    warn!("Invalid static key length for {}: {} bytes", peer_id, key.len());
                }
            } else {
                warn!("No remote static key available after third message for {} (responder)", peer_id);
            }
            
            // Handshake complete - convert to transport state
            let transport = handshake.into_transport_mode()
                .map_err(|e| Error::Encryption(format!("Failed to convert to transport: {}", e)))?;
            
            session.transport_state = Some(transport);
            info!("Handshake complete with {} (as responder)", peer_id);
            
            Ok(None)
        } else {
            // We're the initiator, process the second message (e, ee, s, es)
            let mut handshake = session.handshake_state.take()
                .ok_or_else(|| Error::Noise("No handshake state".to_string()))?;
            
            let mut payload_buffer = vec![0u8; 65535];
            let payload_len = handshake.read_message(&packet.payload, &mut payload_buffer)
                .map_err(|e| Error::Encryption(format!("Failed to read second message: {}", e)))?;
            
            if payload_len > 0 {
                debug!("Second message contained {} bytes of payload", payload_len);
            }
            
            // Extract remote static key after processing second message (initiator gets it here!)
            let remote_static_key = handshake.get_remote_static().map(|k| k.to_vec());
            if let Some(ref key) = remote_static_key {
                info!("Got remote static key for {} ({} bytes) as initiator", peer_id, key.len());
                // Store the peer's static key
                let mut peer_keys = self.peer_static_keys.write().await;
                // Convert Vec<u8> to [u8; 32]
                if key.len() == 32 {
                    let mut key_array = [0u8; 32];
                    key_array.copy_from_slice(&key);
                    peer_keys.insert(peer_id.clone(), key_array);
                } else {
                    warn!("Invalid static key length for {}: {} bytes", peer_id, key.len());
                }
            } else {
                warn!("No remote static key available after second message for {}", peer_id);
            }
            
            // Generate third message (s, se)
            let mut response_buffer = vec![0u8; 65535];
            let response_len = handshake.write_message(&[], &mut response_buffer)
                .map_err(|e| Error::Encryption(format!("Failed to write third message: {}", e)))?;
            response_buffer.truncate(response_len);
            
            info!("Generated third handshake message ({} bytes)", response_buffer.len());
            
            // Extract remote static key before converting to transport
            let remote_static_key = handshake.get_remote_static().map(|k| k.to_vec());
            if let Some(ref key) = remote_static_key {
                info!("Got remote static key for {} ({} bytes)", peer_id, key.len());
                // Store the peer's static key
                let mut peer_keys = self.peer_static_keys.write().await;
                // Convert Vec<u8> to [u8; 32]
                if key.len() == 32 {
                    let mut key_array = [0u8; 32];
                    key_array.copy_from_slice(&key);
                    peer_keys.insert(peer_id.clone(), key_array);
                } else {
                    warn!("Invalid static key length for {}: {} bytes", peer_id, key.len());
                }
            }
            
            // Handshake complete - convert to transport state
            let transport = handshake.into_transport_mode()
                .map_err(|e| Error::Encryption(format!("Failed to convert to transport: {}", e)))?;
            
            session.transport_state = Some(transport);
            info!("Handshake complete with {} (as initiator)", peer_id);
            
            // Return the third message
            Ok(Some(Packet::new(
                MessageType::NoiseHandshakeResp,
                my_peer_id,
                response_buffer,
            ).with_recipient(packet.sender_id)))
        }
    }
    
    pub async fn encrypt_packet(&self, my_peer_id: [u8; 8], peer_id: &str, inner_packet: Packet) -> Result<Packet> {
        // Encode inner packet
        let inner_data = crate::protocol::BinaryProtocol::encode(&inner_packet)?;
        
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(peer_id)
            .ok_or_else(|| Error::Noise(format!("No session with {}", peer_id)))?;
        
        let transport = session.transport_state.as_mut()
            .ok_or_else(|| Error::Noise(format!("No transport state with {}", peer_id)))?;
        
        // Encrypt with transport state
        // Snow handles nonce management internally - we prepend 4-byte big-endian nonce for Mac compatibility
        let mut buffer = vec![0u8; inner_data.len() + 16 + 4]; // data + tag + nonce prefix
        
        // Use per-session nonce counter for Mac compatibility
        let nonce = session.send_nonce;
        session.send_nonce += 1;
        
        // Write 4-byte big-endian nonce prefix for Mac client
        buffer[0..4].copy_from_slice(&nonce.to_be_bytes());
        
        // Encrypt the message
        let encrypted_len = transport.write_message(&inner_data, &mut buffer[4..])
            .map_err(|e| Error::Encryption(format!("Failed to encrypt: {}", e)))?;
        
        buffer.truncate(4 + encrypted_len);
        
        debug!("Encrypted {} bytes to {} bytes (with nonce prefix)", inner_data.len(), buffer.len());
        
        // Parse peer ID to get recipient bytes
        let recipient_bytes = hex::decode(peer_id)
            .map_err(|_| Error::InvalidPeerId(peer_id.to_string()))?;
        if recipient_bytes.len() != 8 {
            return Err(Error::InvalidPeerId(peer_id.to_string()));
        }
        let mut recipient_id = [0u8; 8];
        recipient_id.copy_from_slice(&recipient_bytes);
        
        Ok(Packet::new(
            MessageType::NoiseEncrypted,
            my_peer_id,
            buffer,
        ).with_recipient(recipient_id))
    }
    
    pub async fn decrypt_packet(&self, peer_id: &str, packet: Packet) -> Result<Vec<u8>> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(peer_id)
            .ok_or_else(|| Error::Noise(format!("No session with {}", peer_id)))?;
        
        let transport = session.transport_state.as_mut()
            .ok_or_else(|| Error::Noise(format!("No transport state with {}", peer_id)))?;
        
        // Extract and validate nonce prefix (4 bytes big-endian)
        let (encrypted_data, received_nonce) = if packet.payload.len() >= 4 {
            let nonce_bytes = &packet.payload[0..4];
            let received_nonce = u32::from_be_bytes([
                nonce_bytes[0], nonce_bytes[1], 
                nonce_bytes[2], nonce_bytes[3]
            ]);
            
            debug!("Received message with nonce: {}, expected: {}", received_nonce, session.recv_nonce);
            
            // For Mac compatibility, validate nonce sequence
            if received_nonce != session.recv_nonce {
                warn!("Nonce mismatch: received {}, expected {}", received_nonce, session.recv_nonce);
                // Continue anyway - snow library will handle the actual crypto validation
            }
            
            (&packet.payload[4..], Some(received_nonce))
        } else {
            debug!("No nonce prefix found, processing full payload");
            (&packet.payload[..], None)
        };
        
        // Decrypt with transport state
        let mut buffer = vec![0u8; encrypted_data.len()];
        let decrypted_len = transport.read_message(encrypted_data, &mut buffer)
            .map_err(|e| Error::Encryption(format!("Failed to decrypt: {}", e)))?;
        
        buffer.truncate(decrypted_len);
        
        // If decryption succeeded and we had a nonce, increment our receive counter
        if received_nonce.is_some() {
            session.recv_nonce += 1;
            debug!("Decryption successful, incremented recv_nonce to {}", session.recv_nonce);
        }
        
        debug!("Decrypted {} bytes to {} bytes", encrypted_data.len(), buffer.len());
        
        Ok(buffer)
    }
    
    pub async fn has_session(&self, peer_id: &str) -> bool {
        self.sessions.read().await.contains_key(peer_id)
    }
    
    pub async fn has_completed_session(&self, peer_id: &str) -> bool {
        if let Some(session) = self.sessions.read().await.get(peer_id) {
            session.transport_state.is_some()
        } else {
            false
        }
    }
    
    pub async fn clear_session(&self, peer_id: &str) {
        self.sessions.write().await.remove(peer_id);
        info!("Cleared session with {}", peer_id);
    }
    
    pub async fn get_session_debug_info(&self, peer_id: &str) -> Option<String> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(peer_id) {
            Some(format!(
                "Session with {}: initiator={}, handshake={}, transport={}, send_nonce={}, recv_nonce={}",
                peer_id,
                session.is_initiator,
                session.handshake_state.is_some(),
                session.transport_state.is_some(),
                session.send_nonce,
                session.recv_nonce
            ))
        } else {
            None
        }
    }
    
    pub async fn sign_packet(&self, mut packet: Packet) -> Result<Packet> {
        // Create signature over packet data (excluding signature field)
        let mut data_to_sign = Vec::new();
        data_to_sign.push(packet.version);
        data_to_sign.push(packet.message_type.as_u8());
        data_to_sign.push(packet.ttl);
        data_to_sign.extend_from_slice(&(packet.timestamp.timestamp_millis() as u64).to_be_bytes());
        data_to_sign.push(packet.flags.to_byte());
        data_to_sign.extend_from_slice(&(packet.payload.len() as u16).to_be_bytes());
        data_to_sign.extend_from_slice(&packet.sender_id);
        if let Some(recipient_id) = &packet.recipient_id {
            data_to_sign.extend_from_slice(recipient_id);
        }
        data_to_sign.extend_from_slice(&packet.payload);
        
        let signature = self.signing_key.sign(&data_to_sign);
        packet = packet.with_signature(signature.to_bytes());
        
        Ok(packet)
    }
    
    pub async fn verify_packet(&self, packet: &Packet, peer_key: &VerifyingKey) -> Result<bool> {
        if let Some(signature_bytes) = &packet.signature {
            // Recreate data that was signed
            let mut data_to_verify = Vec::new();
            data_to_verify.push(packet.version);
            data_to_verify.push(packet.message_type.as_u8());
            data_to_verify.push(packet.ttl);
            data_to_verify.extend_from_slice(&(packet.timestamp.timestamp_millis() as u64).to_be_bytes());
            data_to_verify.push(packet.flags.to_byte());
            data_to_verify.extend_from_slice(&(packet.payload.len() as u16).to_be_bytes());
            data_to_verify.extend_from_slice(&packet.sender_id);
            if let Some(recipient_id) = &packet.recipient_id {
                data_to_verify.extend_from_slice(recipient_id);
            }
            data_to_verify.extend_from_slice(&packet.payload);
            
            let signature = Signature::from_bytes(signature_bytes);
            
            match peer_key.verify(&data_to_verify, &signature) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            Ok(false)
        }
    }
    
    pub async fn store_peer_key(&self, peer_id: String, public_key: Vec<u8>) -> Result<()> {
        if public_key.len() != 32 {
            return Err(Error::Encryption("Invalid public key length".to_string()));
        }
        
        let key_bytes: [u8; 32] = public_key.try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| Error::Encryption(format!("Invalid public key: {}", e)))?;
            
        self.peer_keys.write().await.insert(peer_id, verifying_key);
        Ok(())
    }
    
    pub async fn get_peer_key(&self, peer_id: &str) -> Option<VerifyingKey> {
        self.peer_keys.read().await.get(peer_id).cloned()
    }
    
    pub async fn remove_session(&self, peer_id: &str) {
        self.clear_session(peer_id).await;
    }
}