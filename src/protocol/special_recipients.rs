/// Special recipient IDs - exact same as iOS/Android version
pub struct SpecialRecipients;

impl SpecialRecipients {
    /// All 0xFF = broadcast recipient for public messages
    pub const BROADCAST: [u8; 8] = [0xFF; 8];
}