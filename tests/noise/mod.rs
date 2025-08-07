use bitchat_rust::crypto::NoiseEncryptionService;
use bitchat_rust::protocol::{MessageType, Packet};

#[tokio::test]
async fn test_noise_handshake_basic() {
    // Create two encryption services
    let alice_service = NoiseEncryptionService::new().expect("Failed to create Alice service");
    let bob_service = NoiseEncryptionService::new().expect("Failed to create Bob service");
    
    let alice_peer_id = "ALICE123";
    let bob_peer_id = "BOB45678";
    
    // Alice initiates handshake
    let init_packet = alice_service.initiate_handshake(bob_peer_id.to_string()).await
        .expect("Failed to initiate handshake");
    
    assert_eq!(init_packet.message_type, MessageType::NoiseHandshakeInit);
    assert!(!init_packet.payload.is_empty());
    
    // Bob responds
    let resp_packet = bob_service.handle_handshake_init(alice_peer_id.to_string(), init_packet).await
        .expect("Failed to handle handshake init");
    
    assert_eq!(resp_packet.message_type, MessageType::NoiseHandshakeResp);
    assert!(!resp_packet.payload.is_empty());
    
    // Alice completes handshake
    alice_service.handle_handshake_response(bob_peer_id.to_string(), resp_packet).await
        .expect("Failed to handle handshake response");
    
    // Both sessions should be established
    assert!(alice_service.has_session(bob_peer_id).await);
    assert!(bob_service.has_session(alice_peer_id).await);
}

#[tokio::test]
async fn test_noise_encryption_decryption() {
    let alice_service = NoiseEncryptionService::new().expect("Failed to create Alice service");
    let bob_service = NoiseEncryptionService::new().expect("Failed to create Bob service");
    
    let alice_peer_id = "ALICE123";
    let bob_peer_id = "BOB45678";
    
    // Establish sessions
    establish_noise_sessions(&alice_service, &bob_service, alice_peer_id, bob_peer_id).await;
    
    // Test encryption from Alice to Bob
    let plaintext = b"Hello, Bob!";
    let inner_packet = Packet::new(
        MessageType::Message,
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], // Alice's ID
        plaintext.to_vec(),
    );
    
    let encrypted_packet = alice_service.encrypt_packet(
        bob_peer_id,
        inner_packet.clone()
    ).await.expect("Failed to encrypt");
    
    assert_eq!(encrypted_packet.message_type, MessageType::NoiseEncrypted);
    assert_ne!(encrypted_packet.payload, plaintext);
    
    // Bob decrypts
    let decrypted_packet = bob_service.decrypt_packet(alice_peer_id, encrypted_packet).await
        .expect("Failed to decrypt");
    
    assert_eq!(decrypted_packet.payload, plaintext);
}

#[tokio::test]
async fn test_bidirectional_encryption() {
    let alice_service = NoiseEncryptionService::new().expect("Failed to create Alice service");
    let bob_service = NoiseEncryptionService::new().expect("Failed to create Bob service");
    
    let alice_peer_id = "ALICE123";
    let bob_peer_id = "BOB45678";
    
    establish_noise_sessions(&alice_service, &bob_service, alice_peer_id, bob_peer_id).await;
    
    // Alice -> Bob
    let alice_msg = b"Message from Alice";
    let alice_inner = Packet::new(
        MessageType::Message,
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        alice_msg.to_vec(),
    );
    let encrypted_a = alice_service.encrypt_packet(bob_peer_id, alice_inner).await
        .expect("Failed to encrypt Alice message");
    let decrypted_a = bob_service.decrypt_packet(alice_peer_id, encrypted_a).await
        .expect("Failed to decrypt Alice message");
    assert_eq!(decrypted_a.payload, alice_msg);
    
    // Bob -> Alice
    let bob_msg = b"Message from Bob";
    let bob_inner = Packet::new(
        MessageType::Message,
        [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        bob_msg.to_vec(),
    );
    let encrypted_b = bob_service.encrypt_packet(alice_peer_id, bob_inner).await
        .expect("Failed to encrypt Bob message");
    let decrypted_b = alice_service.decrypt_packet(bob_peer_id, encrypted_b).await
        .expect("Failed to decrypt Bob message");
    assert_eq!(decrypted_b.payload, bob_msg);
}

#[tokio::test]
async fn test_identity_announcement() {
    let alice_service = NoiseEncryptionService::new().expect("Failed to create Alice service");
    let bob_service = NoiseEncryptionService::new().expect("Failed to create Bob service");
    
    let alice_peer_id = "ALICE123";
    let bob_peer_id = "BOB45678";
    
    establish_noise_sessions(&alice_service, &bob_service, alice_peer_id, bob_peer_id).await;
    
    // Alice announces her identity
    let identity_packet = alice_service.create_identity_announcement(bob_peer_id.to_string()).await
        .expect("Failed to create identity announcement");
    
    assert_eq!(identity_packet.message_type, MessageType::NoiseIdentityAnnounce);
    
    // Bob verifies the announcement
    bob_service.handle_identity_announcement(alice_peer_id.to_string(), identity_packet).await
        .expect("Failed to handle identity announcement");
}

#[tokio::test]
async fn test_encryption_without_session() {
    let service = NoiseEncryptionService::new().expect("Failed to create service");
    
    let dummy_packet = Packet::new(
        MessageType::Message,
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        b"test".to_vec(),
    );
    
    // Try to encrypt without established session
    let result = service.encrypt_packet("UNKNOWN", dummy_packet).await;
    
    assert!(result.is_err());
}

#[tokio::test]
async fn test_large_message_encryption() {
    let alice_service = NoiseEncryptionService::new().expect("Failed to create Alice service");
    let bob_service = NoiseEncryptionService::new().expect("Failed to create Bob service");
    
    let alice_peer_id = "ALICE123";
    let bob_peer_id = "BOB45678";
    
    establish_noise_sessions(&alice_service, &bob_service, alice_peer_id, bob_peer_id).await;
    
    // Create a large message (100KB)
    let large_msg = vec![0x42u8; 100_000];
    let large_packet = Packet::new(
        MessageType::Message,
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        large_msg.clone(),
    );
    
    let encrypted = alice_service.encrypt_packet(bob_peer_id, large_packet).await
        .expect("Failed to encrypt large message");
    let decrypted = bob_service.decrypt_packet(alice_peer_id, encrypted).await
        .expect("Failed to decrypt large message");
    
    assert_eq!(decrypted.payload, large_msg);
}

#[tokio::test]
async fn test_tampered_ciphertext_detection() {
    let alice_service = NoiseEncryptionService::new().expect("Failed to create Alice service");
    let bob_service = NoiseEncryptionService::new().expect("Failed to create Bob service");
    
    let alice_peer_id = "ALICE123";
    let bob_peer_id = "BOB45678";
    
    establish_noise_sessions(&alice_service, &bob_service, alice_peer_id, bob_peer_id).await;
    
    let plaintext = b"Secret message";
    let inner_packet = Packet::new(
        MessageType::Message,
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        plaintext.to_vec(),
    );
    
    let mut encrypted_packet = alice_service.encrypt_packet(bob_peer_id, inner_packet).await
        .expect("Failed to encrypt");
    
    // Tamper with the ciphertext
    let tamper_index = encrypted_packet.payload.len() / 2;
    encrypted_packet.payload[tamper_index] ^= 0xFF;
    
    // Decryption should fail
    let result = bob_service.decrypt_packet(alice_peer_id, encrypted_packet).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_session_restart() {
    let alice_service = NoiseEncryptionService::new().expect("Failed to create Alice service");
    let bob_service = NoiseEncryptionService::new().expect("Failed to create Bob service");
    
    let alice_peer_id = "ALICE123";
    let bob_peer_id = "BOB45678";
    
    // First handshake
    establish_noise_sessions(&alice_service, &bob_service, alice_peer_id, bob_peer_id).await;
    
    // Exchange a message to verify first session works
    let msg1 = b"First session";
    let packet1 = Packet::new(
        MessageType::Message,
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        msg1.to_vec(),
    );
    let enc1 = alice_service.encrypt_packet(bob_peer_id, packet1).await
        .expect("Failed to encrypt with first session");
    let dec1 = bob_service.decrypt_packet(alice_peer_id, enc1).await
        .expect("Failed to decrypt with first session");
    assert_eq!(dec1.payload, msg1);
    
    // Clear Bob's session (simulate restart)
    bob_service.clear_session(alice_peer_id).await;
    
    // Bob initiates new handshake
    let init_packet = bob_service.initiate_handshake(alice_peer_id.to_string()).await
        .expect("Failed to initiate new handshake");
    
    // Alice should accept new handshake
    let resp_packet = alice_service.handle_handshake_init(bob_peer_id.to_string(), init_packet).await
        .expect("Failed to handle new handshake");
    
    bob_service.handle_handshake_response(alice_peer_id.to_string(), resp_packet).await
        .expect("Failed to complete new handshake");
    
    // New session should work
    let msg2 = b"Second session";
    let packet2 = Packet::new(
        MessageType::Message,
        [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        msg2.to_vec(),
    );
    let enc2 = bob_service.encrypt_packet(alice_peer_id, packet2).await
        .expect("Failed to encrypt with second session");
    let dec2 = alice_service.decrypt_packet(bob_peer_id, enc2).await
        .expect("Failed to decrypt with second session");
    assert_eq!(dec2.payload, msg2);
}

// Helper function to establish Noise sessions
async fn establish_noise_sessions(
    alice_service: &NoiseEncryptionService,
    bob_service: &NoiseEncryptionService,
    alice_peer_id: &str,
    bob_peer_id: &str,
) {
    // Alice initiates
    let init_packet = alice_service.initiate_handshake(bob_peer_id.to_string()).await
        .expect("Failed to initiate handshake");
    
    // Bob responds
    let resp_packet = bob_service.handle_handshake_init(alice_peer_id.to_string(), init_packet).await
        .expect("Failed to handle handshake init");
    
    // Alice completes
    alice_service.handle_handshake_response(bob_peer_id.to_string(), resp_packet).await
        .expect("Failed to complete handshake");
}
