use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};
use uiautomation::{UIAutomation, UIElement, UITreeWalker};
use uiautomation::types::UIProperty;
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, SendMessageW, WM_CLOSE};
use windows::Win32::Foundation::{LPARAM, WPARAM};

pub struct BrowserMonitor {
    pub last_url: String,
    pub blocked_count: u32,
    pub suspicious_count: u32,
    pub url_timers: HashMap<String, f64>,
    pub total_times: HashMap<String, f64>,
    urls_for_upload: VecDeque<String>,
    api_blacklist: Vec<String>,
}

impl BrowserMonitor {
    pub fn new() -> Self {
        BrowserMonitor {
            last_url: String::new(),
            blocked_count: 0,
            suspicious_count: 0,
            url_timers: HashMap::new(),
            total_times: HashMap::new(),
            urls_for_upload: VecDeque::new(),
            api_blacklist: Vec::new(),
        }
    }

    pub fn get_active_browser_url_optimized(&mut self) -> Option<String> {
        let automation = UIAutomation::new().ok()?;
        let root = automation.get_root_element().ok()?;
        let walker = automation.get_control_view_walker().ok()?;
        
        let mut current = match walker.get_first_child(&root) {
            Ok(el) => el,
            _ => return None,
        };
        
        loop {
            if let Ok(name) = current.get_name() {
                let name_lower = name.to_lowercase();
                if name_lower.contains("chrome") || name_lower.contains("edge") || name_lower.contains("brave") {
                    if let Some(url) = self.find_address_bar_url(&automation, &walker, &current) {
                        return Some(url);
                    }
                }
            }
            
            if let Ok(next) = walker.get_next_sibling(&current) {
                current = next;
            } else {
                break;
            }
        }

        None
    }

    fn find_address_bar_url(&self, automation: &UIAutomation, walker: &UITreeWalker, browser_window: &UIElement) -> Option<String> {
        if let Some(address_bar) = self.find_address_bar_recursive(automation, walker, browser_window, 0) {
            if let Ok(val) = address_bar.get_property_value(UIProperty::ValueValue) {
                let url_str = val.to_string();
                if !url_str.is_empty() {
                    return Some(url_str);
                }
            }
        }
        None
    }

    fn find_address_bar_recursive(&self, automation: &UIAutomation, walker: &UITreeWalker, element: &UIElement, depth: u32) -> Option<UIElement> {
        if depth > 10 { return None; }

        let mut current = match walker.get_first_child(element) {
            Ok(el) => el,
            _ => return None,
        };
        
        loop {
            if let Ok(name) = current.get_name() {
                if name == "Address and search bar" || name == "Address bar" || name.contains("Address and search bar") {
                    return Some(current.clone());
                }
            }
            
            if let Some(found) = self.find_address_bar_recursive(automation, walker, &current, depth + 1) {
                return Some(found);
            }
            
            if let Ok(next) = walker.get_next_sibling(&current) {
                current = next;
            } else {
                break;
            }
        }
        None
    }

    pub fn update_timing(&mut self, current_url: Option<String>) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();

        if let Some(url) = current_url {
            if url != self.last_url {
                if !self.last_url.is_empty() {
                    let start_time = self.url_timers.remove(&self.last_url).unwrap_or(now);
                    let duration = now - start_time;
                    *self.total_times.entry(self.last_url.clone()).or_insert(0.0) += duration;
                }
                
                // Check if new URL is blocked
                if self.is_blocked(&url) {
                    println!("[ALERT] Accessing blocked URL: {}. Closing window...", url);
                    self.blocked_count += 1;
                    
                    // Actively block by closing the foreground window
                    unsafe {
                        let hwnd = GetForegroundWindow();
                        if hwnd.0 != 0 {
                            SendMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0));
                        }
                    }
                }

                self.last_url = url.clone();
                self.url_timers.insert(url.clone(), now);
                
                // Keep history for upload (limit to last 50)
                self.urls_for_upload.push_back(url);
                if self.urls_for_upload.len() > 50 {
                    self.urls_for_upload.pop_front();
                }
            }
        } else if !self.last_url.is_empty() {
            let start_time = self.url_timers.remove(&self.last_url).unwrap_or(now);
            let duration = now - start_time;
            *self.total_times.entry(self.last_url.clone()).or_insert(0.0) += duration;
            self.last_url = String::new();
        }
    }

    pub fn update_blacklist(&mut self, new_blacklist: Vec<String>) {
        self.api_blacklist = new_blacklist;
    }

    fn is_blocked(&self, url: &str) -> bool {
        self.api_blacklist.iter().any(|pattern| {
            if pattern.contains('*') {
                // Simple glob-like match (very basic)
                let regex_pattern = pattern.replace(".", "\\.").replace("*", ".*");
                if let Ok(re) = regex::Regex::new(&format!("(?i)^{}$", regex_pattern)) {
                    return re.is_match(url);
                }
            }
            url.to_lowercase().contains(&pattern.to_lowercase())
        })
    }


    pub fn get_url_data_for_api(&mut self, clear_after: bool) -> crate::config::client::UrlMonitoringData {
        let urls: Vec<String> = self.urls_for_upload.iter().cloned().collect();
        let total_visits = self.total_times.values().map(|&v| v as u32).sum::<u32>();

        let result = crate::config::client::UrlMonitoringData {
            device_id: crate::config::api_config::get_device_id(),
            timestamp: chrono::Local::now().to_rfc3339(),
            urls,
            blocked_count: self.blocked_count,
            suspicious_count: self.suspicious_count,
            total_visits,
        };
        
        if clear_after {
            self.urls_for_upload.clear();
        }
        
        result
    }
}
