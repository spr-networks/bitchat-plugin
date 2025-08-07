use crate::model::BitchatMessage;
use crate::protocol::Packet;
use async_trait::async_trait;

#[async_trait]
pub trait BluetoothMeshDelegate: Send + Sync {
    async fn did_receive_message(&self, message: BitchatMessage);
    async fn did_connect_to_peer(&self, peer_id: String);
    async fn did_disconnect_from_peer(&self, peer_id: String);
    async fn did_update_peer_list(&self, peers: Vec<String>);
    async fn did_receive_noise_handshake_init(&self, peer_id: String, packet: Packet);
    async fn did_receive_noise_handshake_response(&self, peer_id: String, packet: Packet);
    async fn did_receive_noise_identity_announce(&self, peer_id: String, packet: Packet);
    async fn did_complete_noise_handshake(&self, peer_id: String);
    async fn did_fail_noise_handshake(&self, peer_id: String, error: String);
    async fn did_receive_noise_encrypted(&self, peer_id: String, packet: Packet);
    async fn did_receive_system_validation(&self, peer_id: String, packet: Packet);
    
    // Connection management
    async fn should_connect_to_peer(&self, peer_address: String);
    
    // Message acknowledgments
    async fn did_receive_delivery_ack(&self, message_id: String, from_peer: String);
    async fn did_receive_read_receipt(&self, message_id: String, from_peer: String);
    
    // UI indicators
    async fn did_receive_typing_indicator(&self, peer_id: String, is_typing: bool);
    
    // Channel key verification
    async fn did_receive_key_verify_request(&self, peer_id: String, key_hash: Vec<u8>);
    async fn did_receive_key_verify_response(&self, peer_id: String, verified: bool);
    
    // Channel management
    async fn did_receive_password_update(&self, channel: String, password_hash: Vec<u8>, from_peer: String);
    async fn did_receive_channel_metadata(&self, channel: String, metadata: Vec<u8>, from_peer: String);
    
    // Version negotiation
    async fn should_send_version_ack(&self, peer_id: String, peer_version: u8);
    async fn did_complete_version_negotiation(&self, peer_id: String, agreed_version: u8);
    
    // Handshake management
    async fn should_initiate_noise_handshake(&self, peer_id: String);
    async fn should_send_handshake_request(&self, target_peer_id: String);
    async fn should_send_noise_identity_announcement(&self);
    async fn should_send_targeted_noise_identity_announcement(&self, target_peer_id: String);
    async fn get_my_peer_id(&self) -> String;
    async fn get_my_nickname(&self) -> String;
    
    // Announce management
    async fn should_send_announce(&self);
}