use log::{Level, Log, Metadata, Record};
use tokio::sync::mpsc;
use std::sync::Mutex;
use std::fs::{File, OpenOptions};
use std::io::Write;

pub enum LogEvent {
    Log(String, Level),
}

pub struct TuiLogger {
    sender: Mutex<Option<mpsc::UnboundedSender<LogEvent>>>,
    info_file: Mutex<Option<File>>,
    error_file: Mutex<Option<File>>,
}

impl TuiLogger {
    pub fn new() -> Self {
        // Try to create log files
        let info_file = std::fs::create_dir_all("logs")
            .ok()
            .and_then(|_| OpenOptions::new()
                .create(true)
                .append(true)
                .open("logs/info.log")
                .ok());
                
        let error_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("logs/error.log")
            .ok();
            
        Self {
            sender: Mutex::new(None),
            info_file: Mutex::new(info_file),
            error_file: Mutex::new(error_file),
        }
    }

    pub fn set_sender(&self, sender: mpsc::UnboundedSender<LogEvent>) {
        *self.sender.lock().unwrap() = Some(sender);
    }
}

impl Log for TuiLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            let msg = format!("[{}] {}: {}", 
                record.level(), 
                record.target(), 
                record.args()
            );
            
            // Send to TUI
            if let Ok(sender_guard) = self.sender.lock() {
                if let Some(sender) = &*sender_guard {
                    let _ = sender.send(LogEvent::Log(msg.clone(), record.level()));
                }
            }
            
            // Write to files
            let file_msg = format!("[{}] {} - {}: {}\n", 
                timestamp, 
                record.level(), 
                record.target(), 
                record.args()
            );
            
            // Write to info.log for all messages
            if record.level() <= Level::Info {
                if let Ok(mut file_guard) = self.info_file.lock() {
                    if let Some(file) = &mut *file_guard {
                        let _ = file.write_all(file_msg.as_bytes());
                        let _ = file.flush();
                    }
                }
            }
            
            // Write to error.log only for errors
            if record.level() <= Level::Error {
                if let Ok(mut file_guard) = self.error_file.lock() {
                    if let Some(file) = &mut *file_guard {
                        let _ = file.write_all(file_msg.as_bytes());
                        let _ = file.flush();
                    }
                }
            }
        }
    }

    fn flush(&self) {}
}

pub fn init_tui_logger() -> &'static TuiLogger {
    use std::sync::Once;
    
    static mut LOGGER: Option<TuiLogger> = None;
    static INIT: Once = Once::new();
    
    unsafe {
        INIT.call_once(|| {
            LOGGER = Some(TuiLogger::new());
            
            if let Some(logger) = &LOGGER {
                log::set_logger(logger)
                    .map(|()| log::set_max_level(log::LevelFilter::Debug))
                    .expect("Failed to set logger");
            }
        });
        
        LOGGER.as_ref().unwrap()
    }
}