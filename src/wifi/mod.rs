use crate::{Error, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde_json::json;

type HmacSha256 = Hmac<Sha256>;

/// Generate WiFi password using HMAC(secret_salt, peer_fingerprint, SHA256)
/// Returns 16-byte password as hex string
pub fn generate_wifi_password(secret_salt: &[u8; 32], peer_fingerprint: &str) -> Result<String> {
    // Create HMAC with secret salt as key
    let mut mac = HmacSha256::new_from_slice(secret_salt)
        .map_err(|e| Error::Other(format!("Failed to create HMAC: {}", e)))?;
    
    // Update with peer fingerprint
    mac.update(peer_fingerprint.as_bytes());
    
    // Get result and truncate to 16 bytes
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    
    // Take first 16 bytes and convert to hex
    let password = hex::encode(&code_bytes[..16]);
    
    Ok(password)
}

/// Load API token from file
pub async fn load_api_token() -> Result<String> {
    // Try the user's home directory first
    let home_dir = dirs::home_dir()
        .ok_or_else(|| Error::Other("Could not determine home directory".to_string()))?;
    
    let token_path = home_dir.join(".bitchat").join("api-token");
    
    // Check if file exists
    if !token_path.exists() {
        return Err(Error::Other(format!("API token file not found at {}", token_path.display())));
    }
    
    // Read token from file
    let token = tokio::fs::read_to_string(&token_path)
        .await
        .map_err(|e| Error::Other(format!("Failed to read API token: {}", e)))?;
    
    // Trim whitespace
    Ok(token.trim().to_string())
}

/// Add WiFi access for a peer using SPR API
pub async fn add_wifi_access(peer_fingerprint: &str, psk: &str) -> Result<()> {
    // Load API token
    let token = match load_api_token().await {
        Ok(t) => t,
        Err(e) => {
            log::warn!("Failed to load API token: {}", e);
            return Err(Error::Other("SPR API token not available".to_string()));
        }
    };
    
    // Prepare request body
    let body = json!({
        "MAC": "pending",
        "Name": peer_fingerprint,
        "Groups": [""],
        "Policies": ["dns", "wan"],
        "DeviceTags": [],
        "PSKEntry": {
            "Psk": psk,
            "Type": "sae"
        },
        "Style": {
            "Color": "blueGray",
            "Icon": "Laptop"
        },
        "DeviceExpiration": -1,
        "DeleteExpiration": false,
        "DeviceDisabled": false
    });
    
    // Create HTTP client
    let client = reqwest::Client::new();
    
    // Make API request
    let response = client
        .put("http://localhost/device?identity=pending")
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| Error::Other(format!("SPR API request failed: {}", e)))?;
    
    // Check response status
    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        return Err(Error::Other(format!("SPR API error ({}): {}", status, error_text)));
    }
    
    log::info!("Successfully added WiFi access for fingerprint: {}", peer_fingerprint);
    Ok(())
}

/// Fetch SSID from hostapd config
pub async fn fetch_ssid() -> Result<String> {
    // Load API token
    let token = load_api_token().await?;
    
    // Create HTTP client
    let client = reqwest::Client::new();
    
    // Try to fetch from hostapd config endpoint with auth
    let response = client
        .get("http://localhost/hostapd/wlan1/config")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| Error::Other(format!("Failed to fetch hostapd config: {}", e)))?;
    
    if !response.status().is_success() {
        return Err(Error::Other(format!("Failed to get hostapd config: {}", response.status())));
    }
    
    let config_json = response.json::<serde_json::Value>().await
        .map_err(|e| Error::Other(format!("Failed to parse hostapd config JSON: {}", e)))?;
    
    // Extract SSID from JSON
    if let Some(ssid) = config_json.get("ssid").and_then(|v| v.as_str()) {
        if !ssid.is_empty() {
            log::info!("Found SSID: {}", ssid);
            return Ok(ssid.to_string());
        }
    }
    
    // Return error if SSID not found
    Err(Error::Other("SSID not found in hostapd config JSON".to_string()))
}

/// Handle WiFi request from a peer
pub async fn handle_wifi_request(
    secret_salt: &[u8; 32],
    peer_fingerprint: &str,
    peer_nickname: &str,
) -> Result<String> {
    // Generate password
    let psk = generate_wifi_password(secret_salt, peer_fingerprint)?;
    
    log::info!("Generated WiFi password for {} ({}): {}", peer_nickname, peer_fingerprint, psk);
    
    // Add to SPR first
    add_wifi_access(peer_fingerprint, &psk).await?;
    
    // Try to fetch SSID - if it fails, still return the password
    let response = match fetch_ssid().await {
        Ok(ssid) => {
            format!("🛜  WiFi access granted!\nGenerating unique password 🔐 from peer fingerprint 🕵️...\nSSID: {}\nPassword: {}", ssid, psk)
        }
        Err(e) => {
            log::warn!("Failed to fetch SSID: {}", e);
            format!("🛜 WiFi access granted!\nGenerating unique password 🔐 from peer fingerprint 🕵️...\nPassword: {}\n(Check router for SSID)", psk)
        }
    };
    
    Ok(response)
}
