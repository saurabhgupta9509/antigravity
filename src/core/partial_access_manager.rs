use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetClassNameW, GetWindowTextW, SendMessageW, WM_CLOSE};
use windows::Win32::Foundation::{LPARAM, WPARAM, HWND};
use serde::Deserialize;

pub struct PartialAccessManager {
    pub running: bool,
    pub stats: Arc<Mutex<PartialAccessStats>>,
    pub config: Arc<Mutex<PartialAccessConfig>>,
    pub context: Arc<Mutex<PartialAccessContext>>,
}

#[derive(Clone)]
pub struct PartialAccessContext {
    pub current_url: String,
    pub current_domain: String,
}

#[derive(PartialEq)]
pub enum DialogType {
    None,
    Upload,
    Download,
}

pub struct PartialAccessStats {
    pub dialogs_closed: u32,
}

#[derive(Clone, Deserialize)]
pub struct PartialAccessSite {
    #[serde(rename = "urlPattern")]
    pub url_pattern: String,
    #[serde(rename = "allowUpload")]
    pub allow_upload: bool,
    #[serde(rename = "allowDownload")]
    pub allow_download: bool,
    #[serde(rename = "monitorMode")]
    pub monitor_mode: String,
    pub active: bool,
}

#[derive(Clone)]
pub struct PartialAccessConfig {
    pub enabled: bool,
    pub sites: Vec<PartialAccessSite>,
}

impl PartialAccessManager {
    pub fn new() -> Self {
        PartialAccessManager {
            running: false,
            stats: Arc::new(Mutex::new(PartialAccessStats {
                dialogs_closed: 0,
            })),
            config: Arc::new(Mutex::new(PartialAccessConfig {
                enabled: true,
                sites: Vec::new(),
            })),
            context: Arc::new(Mutex::new(PartialAccessContext {
                current_url: String::new(),
                current_domain: String::new(),
            })),
        }
    }

    pub fn start_monitoring(&mut self, api_client: Arc<crate::config::client::APIClient>) {
        self.running = true;
        let stats = self.stats.clone();
        let config = self.config.clone();
        let context = self.context.clone();
        
        // Monitoring thread
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let mut last_blocked_hwnd: Option<HWND> = None;
            let mut last_blocked_time = Instant::now();

            loop {
                let current_config = {
                    let c = config.lock().unwrap();
                    c.clone()
                };

                if current_config.enabled {
                    // Check if current URL has specific config
                    let ctx = {
                        let c = context.lock().unwrap();
                        c.clone()
                    };

                    let site_config = current_config.sites.iter().find(|s| {
                        s.active && ctx.current_url.to_lowercase().contains(&s.url_pattern.to_lowercase())
                    });

                    if let Some(site) = site_config {
                        if let Some(hwnd) = unsafe { 
                            let h = GetForegroundWindow();
                            if h.0 != 0 { Some(h) } else { None }
                        } {
                            // Avoid repetitive blocking/logging for the same window within a short period
                            if Some(hwnd) == last_blocked_hwnd && last_blocked_time.elapsed() < Duration::from_secs(2) {
                                std::thread::sleep(Duration::from_millis(200));
                                continue;
                            }

                            let mut class_name = [0u16; 256];
                            let mut title = [0u16; 256];
                            
                            unsafe {
                                GetClassNameW(hwnd, &mut class_name);
                                let len = GetWindowTextW(hwnd, &mut title);
                                if len == 0 {
                                    std::thread::sleep(Duration::from_millis(150));
                                    continue;
                                }
                            }
                            
                            let class_name_str = String::from_utf16_lossy(&class_name).trim_matches('\0').to_string();
                            let title_str = String::from_utf16_lossy(&title).trim_matches('\0').to_string();
                            
                            let dialog_type = get_dialog_type(&class_name_str, &title_str, site);
                            if dialog_type != DialogType::None {
                                println!("[INFO] Blocking partial-access dialog: {} ({}) for site: {}", 
                                    title_str, class_name_str, site.url_pattern);
                                
                                // Use PostMessageW to be non-blocking and more likely to succeed for dialogs
                                unsafe { 
                                    windows::Win32::UI::WindowsAndMessaging::PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0)) 
                                };
                                
                                last_blocked_hwnd = Some(hwnd);
                                last_blocked_time = Instant::now();
                                
                                let mut s = stats.lock().unwrap();
                                s.dialogs_closed += 1;

                                // Report attempt
                                let attempt_data = crate::config::client::AccessAttemptData {
                                    url: ctx.current_url.clone(),
                                    domain: ctx.current_domain.clone(),
                                    file_type: "Unknown".to_string(),
                                    blocked: true,
                                    monitor_mode: site.monitor_mode.clone(),
                                };

                                let api = api_client.clone();
                                let is_upload = dialog_type == DialogType::Upload;
                                rt.block_on(async move {
                                    api.record_access_attempt(attempt_data, is_upload).await;
                                });
                            }
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        });
    }

    pub async fn update_config(&self, api_client: &crate::config::client::APIClient) {
        if let Some(new_config_val) = api_client.get_partial_access_config().await {
            let mut config = self.config.lock().unwrap();
            
            // The backend might send 'enabled' or 'success'
            if let Some(enabled) = new_config_val.get("enabled").and_then(|v| v.as_bool())
                .or_else(|| new_config_val.get("active").and_then(|v| v.as_bool())) {
                config.enabled = enabled;
            }

            if let Some(sites_array) = new_config_val.get("partialAccessSites").and_then(|v| v.as_array()) {
                let sites: Vec<PartialAccessSite> = sites_array.iter()
                    .filter_map(|s| serde_json::from_value(s.clone()).ok())
                    .collect();
                
                println!("Updated partial access config: {} sites received", sites.len());
                config.sites = sites;
            } else if let Some(sites_array) = new_config_val.get("sites").and_then(|v| v.as_array()) {
                // Try alternate key 'sites'
                let sites: Vec<PartialAccessSite> = sites_array.iter()
                    .filter_map(|s| serde_json::from_value(s.clone()).ok())
                    .collect();
                
                println!("Updated partial access config: {} sites received (via 'sites' key)", sites.len());
                config.sites = sites;
            }
        }
    }
}

fn get_dialog_type(class_name: &str, title: &str, site: &PartialAccessSite) -> DialogType {
    let dialog_classes = ["#32770", "FileChooserDialogClass", "NativeHWNDHost"];
    let title_lower = title.to_lowercase();

    let is_dialog_class = dialog_classes.iter().any(|&c| class_name.contains(c));
    if !is_dialog_class {
        return DialogType::None;
    }

    if !site.allow_upload && site.monitor_mode == "block" {
        let upload_keywords = ["open", "upload", "select file", "choose file"];
        if upload_keywords.iter().any(|&k| title_lower.contains(k)) {
            return DialogType::Upload;
        }
    }

    if !site.allow_download && site.monitor_mode == "block" {
        let download_keywords = ["save", "download"];
        if download_keywords.iter().any(|&k| title_lower.contains(k)) {
            return DialogType::Download;
        }
    }

    DialogType::None
}
