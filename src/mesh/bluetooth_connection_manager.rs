use crate::{Error, Result};
use bluer::{
    Adapter, Address, Device, Session,
    adv::{Advertisement, AdvertisementHandle},
    gatt::{
        local::{Application, ApplicationHandle, Characteristic, CharacteristicNotify, CharacteristicNotifyMethod, 
                CharacteristicWrite, CharacteristicWriteMethod, Service},
        remote::Characteristic as RemoteCharacteristic,
    },
};
use futures::{pin_mut, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;
use log::{debug, info, warn};

// Service and characteristic UUIDs (matching iOS/Android)
pub const SERVICE_UUID: Uuid = Uuid::from_u128(0xF47B5E2D_4A9E_4C5A_9B3F_8E1D2C3A4B5C);
pub const CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0xA1B2C3D4_E5F6_4A5B_8C9D_0E1F2A3B4C5D);

pub type DataHandler = Arc<dyn Fn(Vec<u8>, String) + Send + Sync>;

#[derive(Clone)]
pub struct BluetoothConnectionManager {
    session: Arc<Session>,
    adapter: Arc<Adapter>,
    connections: Arc<RwLock<HashMap<Address, Device>>>,
    characteristics: Arc<RwLock<HashMap<Address, RemoteCharacteristic>>>,
    is_scanning: Arc<Mutex<bool>>,
    adv_handle: Arc<Mutex<Option<AdvertisementHandle>>>,
    app_handle: Arc<Mutex<Option<ApplicationHandle>>>,
    data_handler: Arc<Mutex<Option<DataHandler>>>,
    notifier: Arc<Mutex<Option<bluer::gatt::local::CharacteristicNotifier>>>,
    subscribed_centrals: Arc<RwLock<Vec<Address>>>,
}

impl BluetoothConnectionManager {
    pub async fn new() -> Result<Self> {
        let session = Session::new().await
            .map_err(|e| Error::Bluetooth(format!("Failed to create session: {}", e)))?;
            
        let adapter_names = session.adapter_names().await
            .map_err(|e| Error::Bluetooth(format!("Failed to get adapter names: {}", e)))?;
            
        let adapter_name = adapter_names.into_iter().next()
            .ok_or_else(|| Error::Bluetooth("No Bluetooth adapter found".to_string()))?;
            
        let adapter = session.adapter(&adapter_name)
            .map_err(|e| Error::Bluetooth(format!("Failed to get adapter: {}", e)))?;
            
        // Power on the adapter
        adapter.set_powered(true).await
            .map_err(|e| Error::Bluetooth(format!("Failed to power on adapter: {}", e)))?;
            
        Ok(Self {
            session: Arc::new(session),
            adapter: Arc::new(adapter),
            connections: Arc::new(RwLock::new(HashMap::new())),
            characteristics: Arc::new(RwLock::new(HashMap::new())),
            is_scanning: Arc::new(Mutex::new(false)),
            adv_handle: Arc::new(Mutex::new(None)),
            app_handle: Arc::new(Mutex::new(None)),
            data_handler: Arc::new(Mutex::new(None)),
            notifier: Arc::new(Mutex::new(None)),
            subscribed_centrals: Arc::new(RwLock::new(Vec::new())),
        })
    }
    
    pub async fn set_data_handler(&self, handler: DataHandler) {
        *self.data_handler.lock().await = Some(handler);
    }
    
    pub async fn start_advertising(&self) -> Result<()> {
        info!("Starting BLE advertising");
        
        let advertisement = Advertisement {
            service_uuids: vec![SERVICE_UUID].into_iter().collect(),
            discoverable: Some(true),
            local_name: Some("BitChat".to_string()),
            ..Default::default()
        };
        
        let handle = self.adapter.advertise(advertisement).await
            .map_err(|e| Error::Bluetooth(format!("Failed to start advertising: {}", e)))?;
            
        *self.adv_handle.lock().await = Some(handle);
        
        Ok(())
    }
    
    pub async fn stop_advertising(&self) -> Result<()> {
        if let Some(handle) = self.adv_handle.lock().await.take() {
            drop(handle);
            info!("Stopped BLE advertising");
        }
        Ok(())
    }
    
    pub async fn start_gatt_server(&self) -> Result<()> {
        info!("Starting GATT server");
        
        let data_handler = self.data_handler.clone();
        let subscribed_centrals = self.subscribed_centrals.clone();
        
        let write_handle = CharacteristicWrite {
            write: true,
            write_without_response: true,
            method: CharacteristicWriteMethod::Fun(Box::new(move |new_value, req| {
                let data_handler = data_handler.clone();
                let subscribed_centrals = subscribed_centrals.clone();
                Box::pin(async move {
                    // Extract the device address from the request
                    let device_address = req.device_address;
                    let device_address_str = device_address.to_string();
                    debug!("Received {} bytes via GATT write from {}", new_value.len(), device_address_str);
                    
                    // Track this central
                    {
                        let mut centrals = subscribed_centrals.write().await;
                        if !centrals.contains(&device_address) {
                            centrals.push(device_address);
                            info!("Added {} to subscribed centrals list", device_address_str);
                            info!("Current subscribed centrals count: {}", centrals.len());
                        }
                    }
                    
                    if let Some(handler) = data_handler.lock().await.as_ref() {
                        handler(new_value, device_address_str);
                    }
                    
                    Ok(())
                })
            })),
            ..Default::default()
        };
        
        let notifier_ref = self.notifier.clone();
        let subscribed_centrals = self.subscribed_centrals.clone();
        
        let notify_handle = CharacteristicNotify {
            notify: true,
            method: CharacteristicNotifyMethod::Fun(Box::new(move |notifier| {
                let notifier_ref = notifier_ref.clone();
                let _subscribed_centrals = subscribed_centrals.clone();
                
                Box::pin(async move {
                    // Store the notifier for later use
                    *notifier_ref.lock().await = Some(notifier);
                    
                    // Track subscribed centrals
                    // Note: BlueR doesn't provide subscription events directly,
                    // but we can infer from write requests
                    info!("GATT characteristic notify handler initialized");
                })
            })),
            ..Default::default()
        };
        
        let service = Service {
            uuid: SERVICE_UUID,
            primary: true,
            characteristics: vec![
                Characteristic {
                    uuid: CHARACTERISTIC_UUID,
                    write: Some(write_handle),
                    notify: Some(notify_handle),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        
        let app = Application {
            services: vec![service],
            ..Default::default()
        };
        
        let app_handle = self.adapter.serve_gatt_application(app).await
            .map_err(|e| Error::Bluetooth(format!("Failed to serve GATT application: {}", e)))?;
            
        *self.app_handle.lock().await = Some(app_handle);
        
        Ok(())
    }
    
    pub async fn stop_gatt_server(&self) -> Result<()> {
        if let Some(handle) = self.app_handle.lock().await.take() {
            drop(handle);
            info!("Stopped GATT server");
        }
        Ok(())
    }
    
    pub async fn start_scanning(&self) -> Result<()> {
        let mut is_scanning = self.is_scanning.lock().await;
        if *is_scanning {
            return Ok(());
        }
        
        info!("Starting BLE scan");
        
        let filter = bluer::DiscoveryFilter {
            uuids: vec![SERVICE_UUID].into_iter().collect(),
            ..Default::default()
        };
        
        self.adapter.set_discovery_filter(filter).await
            .map_err(|e| Error::Bluetooth(format!("Failed to set discovery filter: {}", e)))?;
            
        self.adapter.set_powered(true).await
            .map_err(|e| Error::Bluetooth(format!("Failed to power on: {}", e)))?;
        
        // Discovery is started by calling discover_devices() in start_device_discovery_monitor()
            
        *is_scanning = true;
        info!("BLE scanning started successfully");
        Ok(())
    }
    
    pub async fn stop_scanning(&self) -> Result<()> {
        let mut is_scanning = self.is_scanning.lock().await;
        if !*is_scanning {
            return Ok(());
        }
        
        info!("Stopping BLE scan");
        
        // Discovery is stopped when the discover_devices stream is dropped
        
        *is_scanning = false;
        Ok(())
    }
    
    pub async fn connect_to_device(&self, address: Address) -> Result<String> {
        info!("Connecting to device: {}", address);
        debug!("Connection attempt started for {}", address);
        
        let device = self.adapter.device(address)
            .map_err(|e| Error::Bluetooth(format!("Failed to get device: {}", e)))?;
            
        let is_connected = device.is_connected().await
            .map_err(|e| Error::Bluetooth(format!("Failed to check connection: {}", e)))?;
        debug!("Device {} is_connected: {}", address, is_connected);
        
        if !is_connected {
            info!("Attempting to connect to {}", address);
            device.connect().await
                .map_err(|e| Error::Bluetooth(format!("Failed to connect: {}", e)))?;
            info!("Successfully connected to {}", address);
        } else {
            info!("Device {} already connected", address);
        }
        
        // Discover services
        info!("Discovering services for device {}", address);
        let services = device.services().await
            .map_err(|e| Error::Bluetooth(format!("Failed to get services: {}", e)))?;
        info!("Found {} services on device {}", services.len(), address);
            
        // Find our service and characteristic
        let mut found_characteristic = None;
        for service in services {
            let service_uuid = service.uuid().await
                .map_err(|e| Error::Bluetooth(format!("Failed to get service UUID: {}", e)))?;
            debug!("Service UUID: {}", service_uuid);
            
            if service_uuid == SERVICE_UUID {
                info!("Found BitChat service on device {}", address);
                
                let chars = service.characteristics().await
                    .map_err(|e| Error::Bluetooth(format!("Failed to get characteristics: {}", e)))?;
                info!("Found {} characteristics in BitChat service", chars.len());
                    
                for char in chars {
                    let char_uuid = char.uuid().await
                        .map_err(|e| Error::Bluetooth(format!("Failed to get char UUID: {}", e)))?;
                    debug!("Characteristic UUID: {}", char_uuid);
                    
                    if char_uuid == CHARACTERISTIC_UUID {
                        info!("Found BitChat characteristic on device {}", address);
                        
                        // Check characteristic properties
                        let flags = char.flags().await
                            .map_err(|e| Error::Bluetooth(format!("Failed to get char flags: {}", e)))?;
                        info!("Characteristic flags: {:?}", flags);
                        
                        found_characteristic = Some(char);
                        break;
                    }
                }
            }
        }
        
        let characteristic = found_characteristic
            .ok_or_else(|| Error::Bluetooth("Characteristic not found".to_string()))?;
            
        // Notifications are automatically started when we call notify()
            
        // Start notification handler
        let notify_stream = characteristic.notify()
            .await
            .map_err(|e| Error::Bluetooth(format!("Failed to get notify stream: {}", e)))?;
            
        let data_handler = self.data_handler.clone();
        let addr_str = address.to_string();
        let addr_str_clone = addr_str.clone();
        
        tokio::spawn(async move {
            pin_mut!(notify_stream);
            loop {
                match notify_stream.next().await {
                    Some(data) => {
                        debug!("Notification from {}: {} bytes", addr_str_clone, data.len());
                        if let Some(handler) = data_handler.lock().await.as_ref() {
                            handler(data, addr_str_clone.clone());
                        }
                    }
                    None => {
                        info!("Notification stream ended for {}", addr_str_clone);
                        break;
                    }
                }
            }
        });
        
        // Store connection and characteristic
        self.connections.write().await.insert(address, device);
        self.characteristics.write().await.insert(address, characteristic);
        
        info!("Successfully established connection to {} and stored in connection map", address);
        debug!("Connection count after adding {}: {}", address, self.connections.read().await.len());
        
        // Return success - the caller should send an announce to the newly connected peer
        Ok(addr_str)
    }
    
    pub async fn disconnect_from_device(&self, address: &Address) -> Result<()> {
        info!("Disconnecting from device: {}", address);
        
        // Remove characteristic
        if let Some(_char) = self.characteristics.write().await.remove(address) {
            // Notifications stop when the characteristic is dropped
        }
        
        // Remove and disconnect device
        if let Some(device) = self.connections.write().await.remove(address) {
            device.disconnect().await
                .map_err(|e| Error::Bluetooth(format!("Failed to disconnect: {}", e)))?;
        }
        
        Ok(())
    }
    
    pub async fn send_data(&self, address: &Address, data: &[u8]) -> Result<()> {
        // First check if we have a connection to this device
        let connections = self.connections.read().await;
        let device = connections.get(address)
            .ok_or_else(|| Error::Connection(format!("No connection to device {}", address)))?;
            
        // Check if device is still connected
        let is_connected = device.is_connected().await
            .map_err(|e| Error::Bluetooth(format!("Failed to check connection status: {}", e)))?;
            
        if !is_connected {
            return Err(Error::Connection(format!("Device {} is not connected", address)));
        }
        
        // Get the characteristic
        let characteristics = self.characteristics.read().await;
        let characteristic = characteristics.get(address)
            .ok_or_else(|| Error::Connection(format!("No characteristic for device {}", address)))?;
            
        debug!("Sending {} bytes to {}", data.len(), address);
        
        characteristic.write(data).await
            .map_err(|e| Error::Bluetooth(format!("Failed to write data to {}: {}", address, e)))?;
            
        Ok(())
    }
    
    pub async fn get_discovered_devices(&self) -> Result<Vec<Address>> {
        let addresses = self.adapter.device_addresses().await
            .map_err(|e| Error::Bluetooth(format!("Failed to get device addresses: {}", e)))?;
        debug!("Total discovered devices: {}", addresses.len());
            
        let mut filtered = Vec::new();
        
        for addr in addresses {
            if let Ok(device) = self.adapter.device(addr) {
                // Get device name for debugging
                let name = device.name().await.ok().flatten().unwrap_or_else(|| "Unknown".to_string());
                debug!("Checking device {} ({})", addr, name);
                
                // Check if device advertises our service
                if let Ok(uuids) = device.uuids().await {
                    if let Some(uuids) = uuids {
                        debug!("Device {} advertises {} UUIDs", addr, uuids.len());
                        if uuids.contains(&SERVICE_UUID) {
                            info!("Device {} ({}) advertises BitChat service", addr, name);
                            filtered.push(addr);
                        }
                    } else {
                        debug!("Device {} has no advertised UUIDs", addr);
                    }
                }
            }
        }
        
        Ok(filtered)
    }
    
    pub async fn get_connected_addresses(&self) -> Vec<Address> {
        self.connections.read().await.keys().cloned().collect()
    }
    
    pub async fn is_connected(&self, address: &Address) -> bool {
        self.connections.read().await.contains_key(address)
    }
    
    pub async fn start_device_discovery_monitor(&self) -> Result<()> {
        info!("Starting device discovery monitor");
        let device_events = self.adapter.discover_devices().await
            .map_err(|e| Error::Bluetooth(format!("Failed to start device discovery: {}", e)))?;
            
        let adapter = self.adapter.clone();
        let connection_manager = self.clone();
        
        tokio::spawn(async move {
            pin_mut!(device_events);
            info!("Device discovery monitor task started");
            
            while let Some(device_event) = device_events.next().await {
                debug!("Device event received: {:?}", device_event);
                match device_event {
                    bluer::AdapterEvent::DeviceAdded(addr) => {
//                        info!("Device discovered: {}", addr);
                        
                        // Check if it advertises our service
                        if let Ok(device) = adapter.device(addr) {
                            debug!("Got device object for {}", addr);
                            match device.uuids().await {
                                Ok(Some(uuids)) => {
                                    debug!("Device {} UUIDs: {:?}", addr, uuids);
                                    if uuids.contains(&SERVICE_UUID) {
                                        info!("Found BitChat device: {} - initiating connection", addr);
                                        
                                        // Auto-connect
                                        match connection_manager.connect_to_device(addr).await {
                                            Ok(connected_addr) => {
                                                info!("Successfully connected to BitChat device: {}", connected_addr);
                                                // Notify about new connection
                                                if let Some(handler) = connection_manager.data_handler.lock().await.as_ref() {
                                                    // Send special connection event
                                                    handler(vec![0xFF, 0xFF], format!("CONNECTED:{}", connected_addr));
                                                }
                                            }
                                            Err(e) => {
                                                warn!("Failed to connect to BitChat device {}: {}", addr, e);
                                            }
                                        }
                                    } else {
                                        debug!("Device {} does not advertise BitChat service", addr);
                                    }
                                }
                                Ok(None) => {
                                    debug!("Device {} has no UUIDs", addr);
                                }
                                Err(e) => {
                                    debug!("Failed to get UUIDs for device {}: {}", addr, e);
                                }
                            }
                        } else {
                            debug!("Failed to get device object for {}", addr);
                        }
                    }
                    bluer::AdapterEvent::DeviceRemoved(addr) => {
                        info!("Device removed: {}", addr);
                        let _ = connection_manager.disconnect_from_device(&addr).await;
                    }
                    _ => {
                        debug!("Other device event: {:?}", device_event);
                    }
                }
            }
            
            warn!("Device discovery monitor task ended");
        });
        
        Ok(())
    }
    
    pub fn get_adapter(&self) -> Arc<Adapter> {
        self.adapter.clone()
    }
    
    pub async fn send_notification(&self, data: &[u8]) -> Result<()> {
        let mut notifier_guard = self.notifier.lock().await;
        if let Some(notifier) = notifier_guard.as_mut() {
            debug!("Sending notification with {} bytes to subscribed centrals", data.len());
            
            // Send notification to all subscribed centrals
            notifier.notify(data.to_vec())
                .await
                .map_err(|e| Error::Bluetooth(format!("Failed to send notification: {}", e)))?;
                
            Ok(())
        } else {
            // No notifier means no subscribed centrals
            debug!("No subscribed centrals to notify");
            Ok(())
        }
    }
    
    pub async fn has_subscribed_centrals(&self) -> bool {
        // Check if we have any subscribed centrals (not just if notifier exists)
        !self.subscribed_centrals.read().await.is_empty()
    }
    
    pub async fn get_subscribed_centrals_count(&self) -> usize {
        self.subscribed_centrals.read().await.len()
    }
}
