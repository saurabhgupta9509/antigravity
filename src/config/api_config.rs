use sha2::{Sha256, Digest};
use mac_address::get_mac_address;
use whoami;
use std::collections::HashMap;
use std::sync::OnceLock;

pub const API_BASE_URL: &str = "http://192.168.1.111:9090";

pub fn get_device_id() -> String {
    static DEVICE_ID: OnceLock<String> = OnceLock::new();
    DEVICE_ID.get_or_init(|| {
        if let Ok(Some(mac)) = get_mac_address() {
            let mut hasher = Sha256::new();
            hasher.update(mac.to_string().as_bytes());
            format!("{:x}", hasher.finalize())[..32].to_string()
        } else {
            // Fallback to hostname
            let hostname = whoami::devicename();
            let mut hasher = Sha256::new();
            hasher.update(hostname.as_bytes());
            format!("{:x}", hasher.finalize())[..32].to_string()
        }
    }).clone()
}

pub fn get_user_id() -> String {
    static USER_ID: OnceLock<String> = OnceLock::new();
    USER_ID.get_or_init(|| {
        let username = whoami::username();
        let mut hasher = Sha256::new();
        hasher.update(username.as_bytes());
        format!("{:x}", hasher.finalize())[..32].to_string()
    }).clone()
}

pub fn get_api_endpoints() -> &'static HashMap<&'static str, String> {
    static ENDPOINTS: OnceLock<HashMap<&'static str, String>> = OnceLock::new();
    ENDPOINTS.get_or_init(|| {
        let mut m = HashMap::new();
        let device_id = get_device_id();
        let api_prefix = "/api/python-client";
        m.insert("device_register", format!("{}{}/devices/register", API_BASE_URL, api_prefix));
        m.insert("heartbeat", format!("{}{}/devices/{}/heartbeat", API_BASE_URL, api_prefix, device_id));
        m.insert("log_upload", format!("{}{}/devices/{}/logs", API_BASE_URL, api_prefix, device_id));
        m.insert("url_upload", format!("{}{}/devices/{}/urls", API_BASE_URL, api_prefix, device_id));
        m.insert("app_usage_upload", format!("{}{}/devices/{}/app-usage", API_BASE_URL, api_prefix, device_id));
        m.insert("shutdown", format!("{}{}/devices/{}/shutdown", API_BASE_URL, api_prefix, device_id));
        m.insert("blocked_urls", format!("{}{}/devices/{}/blocked-urls", API_BASE_URL, api_prefix, device_id));
        m.insert("partial_access_config", format!("{}{}/devices/{}/partial-access", API_BASE_URL, api_prefix, device_id));
        m.insert("partial_access_check", format!("{}{}/partial-access/check", API_BASE_URL, api_prefix));
        m.insert("upload_attempt", format!("{}{}/devices/{}/partial-access/upload-attempt", API_BASE_URL, api_prefix, device_id));
        m.insert("download_attempt", format!("{}{}/devices/{}/partial-access/download-attempt", API_BASE_URL, api_prefix, device_id));
        m
    })
}

pub fn get_headers() -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::CONTENT_TYPE, "application/json".parse().unwrap());
    headers.insert(reqwest::header::USER_AGENT, "Cybersecurity-Monitor-Windows/2.1".parse().unwrap());
    headers.insert("X-Device-ID", get_device_id().parse().unwrap());
    headers.insert("X-User-ID", get_user_id().parse().unwrap());
    headers
}
