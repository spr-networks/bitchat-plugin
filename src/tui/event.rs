use crossterm::event::{self, Event as CrosstermEvent, KeyEvent, KeyEventKind};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub enum Event {
    Key(KeyEvent),
    Tick,
    Resize,
}

pub struct EventHandler {
    sender: mpsc::UnboundedSender<Event>,
    receiver: mpsc::UnboundedReceiver<Event>,
}

impl EventHandler {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        let sender_clone = sender.clone();
        
        // Spawn event listener
        tokio::spawn(async move {
            let mut last_tick = Instant::now();
            let tick_rate = Duration::from_millis(100);
            
            loop {
                let timeout = tick_rate
                    .checked_sub(last_tick.elapsed())
                    .unwrap_or_else(|| Duration::from_secs(0));
                
                if event::poll(timeout).unwrap_or(false) {
                    if let Ok(evt) = event::read() {
                        match evt {
                            CrosstermEvent::Key(key) => {
                                if key.kind == KeyEventKind::Press {
                                    let _ = sender_clone.send(Event::Key(key));
                                }
                            }
                            CrosstermEvent::Resize(_, _) => {
                                let _ = sender_clone.send(Event::Resize);
                            }
                            _ => {}
                        }
                    }
                }
                
                if last_tick.elapsed() >= tick_rate {
                    let _ = sender_clone.send(Event::Tick);
                    last_tick = Instant::now();
                }
            }
        });
        
        Self { sender, receiver }
    }
    
    pub async fn next(&mut self) -> Option<Event> {
        self.receiver.recv().await
    }
}