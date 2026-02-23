mod config;
mod core;

use crate::core::monitor::CybersecurityMonitor;

#[tokio::main]
async fn main() {
    let mut monitor = CybersecurityMonitor::new();
    
    // Simple signal handling
    tokio::spawn(async move {
        ctrlc::set_handler(move || {
            println!("\nStopping monitor...");
            std::process::exit(0);
        }).expect("Error setting Ctrl-C handler");
    });

    monitor.run().await;
}
