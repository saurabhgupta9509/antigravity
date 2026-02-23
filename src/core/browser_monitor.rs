use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};
use uiautomation::{UIAutomation, UIElement, UITreeWalker};
use uiautomation::types::UIProperty;
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, SendMessageW, PostMessageW, WM_CLOSE};
use windows::Win32::Foundation::{LPARAM, WPARAM, HWND};

pub struct BrowserMonitor {
    pub last_url: String,
    pub blocked_count: u32,
    pub suspicious_count: u32,
    pub url_timers: HashMap<String, f64>,
    pub total_times: HashMap<String, f64>,
    urls_for_upload: VecDeque<String>,
    pub api_blacklist: Vec<String>,
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
                    println!("[DEBUG] Found potential browser window: {}", name);
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
                let mut url_str = val.to_string();
                // Clean up "STRING(url)" format from uiautomation Variant
                if url_str.starts_with("STRING(") && url_str.ends_with(')') {
                    url_str = url_str[7..url_str.len()-1].to_string();
                }
                
                if !url_str.is_empty() {
                    println!("[DEBUG] Extracted URL: {}", url_str);
                    return Some(url_str);
                }
            }
        }
        None
    }

    fn find_address_bar_recursive(&self, automation: &UIAutomation, walker: &UITreeWalker, element: &UIElement, depth: u32) -> Option<UIElement> {
        if depth > 12 { return None; }

        let mut current = match walker.get_first_child(element) {
            Ok(el) => el,
            _ => return None,
        };
        
        loop {
            if let Ok(name) = current.get_name() {
                let name_lower = name.to_lowercase();
                // Check common names
                if name_lower.contains("address and search bar") || name_lower.contains("address bar") {
                    return Some(current.clone());
                }
            }
            
            // Check for common AutomationIds as a robust fallback
            if let Ok(auto_id) = current.get_automation_id() {
                if auto_id == "addressEditBox" || auto_id.contains("url") || auto_id.contains("address") {
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
            // Active blocking: Check on every iteration if we have a URL
            if self.is_blocked(&url) {
                static mut LAST_ALERT_TIME: f64 = 0.0;
                let current_time = now;
                
                // Only log the alert every 2 seconds to avoid spamming the console
                unsafe {
                    if current_time - LAST_ALERT_TIME > 2.0 {
                        println!("[ALERT] Accessing blocked URL: {}. Closing window...", url);
                        LAST_ALERT_TIME = current_time;
                    }
                }
                
                self.blocked_count += 1;
                
                // Actively block using uiautomation if possible
                if let Some(automation) = UIAutomation::new().ok() {
                    if let Some(root) = automation.get_root_element().ok() {
                        if let Some(walker) = automation.get_control_view_walker().ok() {
                            let mut handle_found = false;
                            
                            if let Some(browser_el) = self.find_browser_window_with_url(&automation, &walker, &root, &url) {
                                if let Ok(val) = browser_el.get_property_value(UIProperty::NativeWindowHandle) {
                                    let mut handle_str = val.to_string();
                                    println!("[DEBUG] Raw HWND property: {}", handle_str);
                                    
                                    if let Some(start) = handle_str.find('(') {
                                        if let Some(end) = handle_str.rfind(')') {
                                            handle_str = handle_str[start+1..end].to_string();
                                        }
                                    }
                                    
                                    if let Ok(hwnd_val) = handle_str.parse::<isize>() {
                                        if hwnd_val != 0 {
                                            println!("[INFO] Found browser window HWND: {}. Sending close message...", hwnd_val);
                                            unsafe {
                                                PostMessageW(HWND(hwnd_val), WM_CLOSE, WPARAM(0), LPARAM(0));
                                            }
                                            handle_found = true;
                                        }
                                    }
                                }
                            }

                            if !handle_found {
                                // Fallback to foreground window
                                unsafe {
                                    let hwnd = GetForegroundWindow();
                                    if hwnd.0 != 0 {
                                        println!("[INFO] Falling back to closing foreground window (HWND: {:?})", hwnd);
                                        PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if url != self.last_url {
                if !self.last_url.is_empty() {
                    let start_time = self.url_timers.remove(&self.last_url).unwrap_or(now);
                    let duration = now - start_time;
                    *self.total_times.entry(self.last_url.clone()).or_insert(0.0) += duration;
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
        self.api_blacklist = new_blacklist.into_iter()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        println!("[DEBUG] Blacklist updated. {} patterns active.", self.api_blacklist.len());
        for p in &self.api_blacklist {
            println!("  - Block pattern: {}", p);
        }
    }

    fn is_blocked(&self, url: &str) -> bool {
        let url_lower = url.to_lowercase();
        
        // Prevent matching extremely short "URLs" that are usually just user typing
        if url_lower.len() < 4 {
            return false;
        }

        // Normalize URL for matching
        let mut normalized_url = url_lower.as_str();
        if normalized_url.starts_with("http://") { normalized_url = &normalized_url[7..]; }
        if normalized_url.starts_with("https://") { normalized_url = &normalized_url[8..]; }
        if normalized_url.starts_with("www.") { normalized_url = &normalized_url[4..]; }
        let normalized_url = normalized_url.trim_end_matches('/');

        self.api_blacklist.iter().any(|pattern| {
            // Normalize pattern as well
            let mut normalized_pattern = pattern.as_str();
            if normalized_pattern.starts_with("http://") { normalized_pattern = &normalized_pattern[7..]; }
            if normalized_pattern.starts_with("https://") { normalized_pattern = &normalized_pattern[8..]; }
            if normalized_pattern.starts_with("www.") { normalized_pattern = &normalized_pattern[4..]; }
            let normalized_pattern = normalized_pattern.trim_end_matches('/');

            let match_found = if pattern.contains('*') {
                let regex_pattern = pattern.replace(".", "\\.").replace("*", ".*");
                if let Ok(re) = regex::Regex::new(&format!("(?i)^{}$", regex_pattern)) {
                    re.is_match(url)
                } else {
                    false
                }
            } else {
                // Check if normalized URL contains normalized pattern (Domain Match)
                // e.g., "facebook.com/login" contains "facebook.com"
                normalized_url.contains(normalized_pattern)
            };

            if match_found {
                println!("[DEBUG] URL match found! Pattern: '{}' matches URL: '{}' (Normalized: '{}' vs '{}')", 
                    pattern, url, normalized_pattern, normalized_url);
            }
            match_found
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

    fn find_browser_window_with_url(&self, automation: &UIAutomation, walker: &UITreeWalker, root: &UIElement, target_url: &str) -> Option<UIElement> {
        let mut current = walker.get_first_child(root).ok()?;
        
        loop {
            if let Ok(name) = current.get_name() {
                let name_lower = name.to_lowercase();
                if name_lower.contains("chrome") || name_lower.contains("edge") || name_lower.contains("brave") {
                    if let Some(url) = self.find_address_bar_url(automation, walker, &current) {
                        if url.contains(target_url) || target_url.contains(&url) {
                            return Some(current);
                        }
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
}
