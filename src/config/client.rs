use reqwest::Client;
use serde::{Serialize, Deserialize};
use std::time::Duration;
use std::fs;
use std::path::Path;
use chrono::Local;
use std::collections::HashMap;
use crate::config::api_config::{get_api_endpoints, get_headers, get_device_id, get_user_id};

#[derive(Serialize)]
pub struct DeviceInfo {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "deviceName")]
    pub device_name: String,
    pub platform: String,
    #[serde(rename = "monitorVersion")]
    pub monitor_version: String,
    #[serde(rename = "firstSeen")]
    pub first_seen: String,
}

#[derive(Serialize)]
pub struct HeartbeatData {
    #[serde(rename = "deviceId")]
    pub device_id: String,
}

#[derive(Serialize)]
pub struct LogData {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "logType")]
    pub log_type: String,
    #[serde(rename = "logContent")]
    pub log_content: String,
    pub timestamp: String,
    #[serde(rename = "fileSize")]
    pub file_size: usize,
}

#[derive(Serialize)]
pub struct UrlMonitoringData {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    pub timestamp: String,
    pub urls: Vec<String>,
    #[serde(rename = "blockedCount")]
    pub blocked_count: u32,
    #[serde(rename = "suspiciousCount")]
    pub suspicious_count: u32,
    #[serde(rename = "totalVisits")]
    pub total_visits: u32,
}

#[derive(Serialize)]
pub struct AppUsageData {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    pub timestamp: String,
    #[serde(rename = "currentApp")]
    pub current_app: String,
    #[serde(rename = "currentSessionDuration")]
    pub current_session_duration: f64,
    #[serde(rename = "totalAppsTracked")]
    pub total_apps_tracked: u32,
    #[serde(rename = "totalTimeTracked")]
    pub total_time_tracked: f64,
    #[serde(rename = "activeUsageTime")]
    pub active_usage_time: f64,
    #[serde(rename = "topApps")]
    pub top_apps: Vec<serde_json::Value>,
    #[serde(rename = "categoryBreakdown")]
    pub category_breakdown: HashMap<String, f64>,
}

#[derive(Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[allow(dead_code)]
    pub message: String,
    pub data: T,
}

#[derive(Serialize)]
pub struct AccessAttemptData {
    pub url: String,
    pub domain: String,
    #[serde(rename = "fileType")]
    pub file_type: String,
    pub blocked: bool,
    #[serde(rename = "monitorMode")]
    pub monitor_mode: String,
}
pub struct APIClient {
    pub client: Client,
}

impl APIClient {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .default_headers(get_headers())
            .build()
            .unwrap();
        
        APIClient { client }
    }

    pub async fn register_device(&self) -> bool {
        let endpoints = get_api_endpoints();
        let url = endpoints.get("device_register").unwrap();
        
        let device_info = DeviceInfo {
            device_id: get_device_id(),
            user_id: get_user_id(),
            device_name: whoami::devicename(),
            platform: "Windows".to_string(),
            monitor_version: "2.1".to_string(),
            first_seen: Local::now().to_rfc3339(),
        };

        match self.client.post(url).json(&device_info).send().await {
            Ok(resp) if resp.status().is_success() => {
                println!("  [OK] Device registered successfully.");
                true
            }
            Ok(resp) => {
                println!("  [ERROR] Registration failed with status: {}", resp.status());
                false
            }
            Err(e) => {
                println!("  [ERROR] Registration failed: {}", e);
                false
            }
        }
    }

    pub async fn send_heartbeat(&self) -> bool {
        let endpoints = get_api_endpoints();
        let url = endpoints.get("heartbeat").unwrap();
        
        let heartbeat_data = HeartbeatData {
            device_id: get_device_id(),
        };

        match self.client.post(url).json(&heartbeat_data).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    pub async fn upload_logs(&self, log_path: &Path, clear_after: bool) -> bool {
        if !log_path.exists() {
            return false;
        }

        let content = match fs::read_to_string(log_path) {
            Ok(c) => c,
            Err(_) => return false,
        };

        if content.trim().is_empty() {
            return true;
        }

        let lines: Vec<&str> = content.lines().collect();
        let recent_lines = if lines.len() > 1000 {
            &lines[lines.len() - 1000..]
        } else {
            &lines[..]
        };

        let log_data = LogData {
            device_id: get_device_id(),
            log_type: log_path.file_stem().unwrap().to_str().unwrap().to_string(),
            log_content: recent_lines.join("\n"),
            timestamp: Local::now().to_rfc3339(),
            file_size: content.len(),
        };

        let endpoints = get_api_endpoints();
        let url = endpoints.get("log_upload").unwrap();

        match self.client.post(url).json(&log_data).send().await {
            Ok(resp) if resp.status().is_success() => {
                if clear_after {
                    let _ = fs::write(log_path, "");
                }
                true
            }
            _ => false,
        }
    }
    
    pub async fn upload_urls(&self, data: UrlMonitoringData) -> bool {
        let endpoints = get_api_endpoints();
        let url = endpoints.get("url_upload").unwrap();

        match self.client.post(url).json(&data).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    pub async fn upload_app_usage(&self, data: AppUsageData) -> bool {
        let endpoints = get_api_endpoints();
        let url = endpoints.get("app_usage_upload").unwrap();

        match self.client.post(url).json(&data).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    pub async fn get_partial_access_config(&self) -> Option<serde_json::Value> {
        let endpoints = get_api_endpoints();
        let url = endpoints.get("partial_access_config").unwrap();

        match self.client.get(url).send().await {
            Ok(resp) => {
                let status = resp.status();
                if !status.is_success() {
                    println!("[ERROR] Failed to fetch partial access config: status {}", status);
                    return None;
                }
                
                match resp.json::<ApiResponse<serde_json::Value>>().await {
                    Ok(api_resp) => {
                        if api_resp.success {
                            return Some(api_resp.data);
                        } else {
                            println!("[ERROR] API returned success=false for partial access config");
                        }
                    }
                    Err(e) => {
                        println!("[ERROR] Failed to parse partial access config JSON: {}", e);
                    }
                }
                None
            }
            Err(e) => {
                println!("[ERROR] Network error fetching partial access config: {}", e);
                None
            }
        }
    }

    pub async fn get_blocked_urls(&self) -> Vec<String> {
        let endpoints = get_api_endpoints();
        let url = endpoints.get("blocked_urls").unwrap();

        match self.client.get(url).send().await {
            Ok(resp) => {
                let status = resp.status();
                if !status.is_success() {
                    println!("[ERROR] Failed to fetch blocked URLs: status {}", status);
                    return Vec::new();
                }
                
                match resp.json::<ApiResponse<Vec<String>>>().await {
                    Ok(api_resp) => {
                        if api_resp.success {
                            return api_resp.data;
                        } else {
                            println!("[ERROR] API returned success=false for blocked URLs");
                        }
                    }
                    Err(e) => {
                        println!("[ERROR] Failed to parse blocked URLs JSON: {}", e);
                    }
                }
                Vec::new()
            }
            Err(e) => {
                println!("[ERROR] Network error fetching blocked URLs: {}", e);
                Vec::new()
            }
        }
    }

    pub async fn record_access_attempt(&self, data: AccessAttemptData, is_upload: bool) -> bool {
        let endpoints = get_api_endpoints();
        let key = if is_upload { "upload_attempt" } else { "download_attempt" };
        let url = endpoints.get(key).unwrap();

        match self.client.post(url).json(&data).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }
}
