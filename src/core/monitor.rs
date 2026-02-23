use std::time::{Duration, Instant};
use std::sync::Arc;
use std::io::Write;
use tokio::time::sleep;
use chrono::Local;

use crate::core::app_tracker::AppTimeTracker;
use crate::core::browser_monitor::BrowserMonitor;
use crate::core::partial_access_manager::PartialAccessManager;
use crate::config::client::APIClient;
use crate::config::settings::CHECK_INTERVAL;

pub struct CybersecurityMonitor {
    pub app_tracker: AppTimeTracker,
    pub browser_monitor: BrowserMonitor,
    pub partial_access: PartialAccessManager,
    pub api_client: Arc<APIClient>,
}

impl CybersecurityMonitor {
    pub fn new() -> Self {
        CybersecurityMonitor {
            app_tracker: AppTimeTracker::new(),
            browser_monitor: BrowserMonitor::new(),
            partial_access: PartialAccessManager::new(),
            api_client: Arc::new(APIClient::new()),
        }
    }

    pub async fn run(&mut self) {
        println!("Starting Cybersecurity Monitor for Windows (Rust Version)...");
        
        let _ = std::fs::create_dir_all("logs");
        let _ = std::fs::create_dir_all("data");
        
        println!("  [1/3] Registering device...");
        self.api_client.register_device().await;
        
        println!("  [2/3] Sending initial heartbeat...");
        self.api_client.send_heartbeat().await;
        
        println!("  [3/3] Starting background threads...");
        self.partial_access.start_monitoring(self.api_client.clone());
        
        let mut last_sync = Instant::now();
        let mut last_config_update = Instant::now() - Duration::from_secs(300); // Trigger update soon
        println!("Monitoring loop active. Press Ctrl+C to stop.");
        
        loop {
            // Diagnostic print
            let now = Local::now().format("%H:%M:%S");
            print!("\r[{}] Monitor active | App: ", now);
            let _ = std::io::stdout().flush();

            // Check app usage
            if let Some(app) = self.app_tracker.track_app_usage() {
                print!("{} | ", app);
            } else {
                print!("None | ");
            }
            let _ = std::io::stdout().flush();
            
            // Check browser URL
            if let Some(url) = self.browser_monitor.get_active_browser_url_optimized() {
                self.browser_monitor.update_timing(Some(url.clone()));
                
                // Sync context for Partial Access
                {
                    let mut ctx = self.partial_access.context.lock().unwrap();
                    ctx.current_url = url.clone();
                    // Basic domain extraction
                    ctx.current_domain = if let Some(domain_part) = url.split("://").nth(1).and_then(|s| s.split('/').next()) {
                        domain_part.to_string()
                    } else {
                        url.clone()
                    };
                }

                print!("URL: {} ", if url.len() > 30 { format!("{}...", &url[..27]) } else { url });
            } else {
                self.browser_monitor.update_timing(None);
                
                // Do NOT clear context here! 
                // If a dialog is open, get_active_browser_url_optimized might return None
                // but we need the current_url to stay set to the browser's URL 
                // so the partial access check works.
                
                print!("URL: None (Preserving context) ");
            }
            let _ = std::io::stdout().flush();

            // Periodic configuration update (every 5 minutes)
            if last_config_update.elapsed() >= Duration::from_secs(60) {
                println!("[{}] Checking for configuration updates...", Local::now().format("%H:%M:%S"));
                
                // Update Partial Access Config
                self.partial_access.update_config(&self.api_client).await;
                
                // Update Blocked URLs
                let blocked_urls = self.api_client.get_blocked_urls().await;
                // Always update, even if empty, so changes (like removals) are reflected
                self.browser_monitor.update_blacklist(blocked_urls);
                println!("[{}] Updated blocked URL list (Blacklist size: {})", 
                    Local::now().format("%H:%M:%S"), 
                    self.browser_monitor.api_blacklist.len());
                
                last_config_update = Instant::now();
            }

            // Periodic Sync (every 60 seconds)
            if last_sync.elapsed() >= Duration::from_secs(60) {
                println!("[{}] Synchronizing with API...", Local::now().format("%H:%M:%S"));
                
                // Send heartbeat
                self.api_client.send_heartbeat().await;
                
                // Upload app usage
                let app_data = self.app_tracker.get_app_data_for_api();
                self.api_client.upload_app_usage(app_data).await;
                
                // Upload URL data
                let url_data = self.browser_monitor.get_url_data_for_api(true);
                self.api_client.upload_urls(url_data).await;
                
                // Upload logs (non-clearing for now, or use true if desired)
                self.api_client.upload_logs(std::path::Path::new("logs/app_timelog.log"), false).await;
                
                println!("[{}] API sync complete.", Local::now().format("%H:%M:%S"));
                last_sync = Instant::now();
            }

            sleep(Duration::from_secs(CHECK_INTERVAL)).await;
        }
    }
}
