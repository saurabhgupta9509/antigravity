use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::sync::{Arc, Mutex};
use std::fs::OpenOptions;
use std::io::Write;
use chrono::{DateTime, Local};
use serde::{Serialize, Deserialize};
use sysinfo::{System};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};
use windows::Win32::UI::Input::KeyboardAndMouse::GetLastInputInfo;
use windows::Win32::UI::Input::KeyboardAndMouse::LASTINPUTINFO;

use crate::config::settings::{get_ignore_apps, get_app_categories, MINIMUM_APP_TIME, TRACK_APP_USAGE};

#[derive(Serialize, Deserialize, Clone)]
pub struct AppData {
    pub app_total_time: HashMap<String, f64>,
    pub app_sessions: HashMap<String, u32>,
    pub app_category_time: HashMap<String, f64>,
}

pub struct AppTimeTracker {
    pub current_app: Option<String>,
    pub app_start_time: Option<f64>,
    pub data: Arc<Mutex<AppData>>,
    sys: System,
}

impl AppTimeTracker {
    pub fn new() -> Self {
        let data = AppData {
            app_total_time: HashMap::new(),
            app_sessions: HashMap::new(),
            app_category_time: HashMap::new(),
        };

        AppTimeTracker {
            current_app: None,
            app_start_time: None,
            data: Arc::new(Mutex::new(data)),
            sys: System::new_all(),
        }
    }

    pub fn track_app_usage(&mut self) -> Option<String> {
        if !TRACK_APP_USAGE {
            return None;
        }

        let now = current_time_secs();
        let device_active = self.check_device_active();

        if !device_active {
            if let (Some(app), Some(start)) = (self.current_app.take(), self.app_start_time.take()) {
                let duration = now - start;
                if duration >= MINIMUM_APP_TIME as f64 {
                    self.record_app_session(&app, start, now, duration);
                }
            }
            return None;
        }

        let active_app = self.get_active_app();

        if let Some(app) = active_app {
            if Some(&app) != self.current_app.as_ref() {
                if let (Some(old_app), Some(start)) = (self.current_app.take(), self.app_start_time.take()) {
                    let duration = now - start;
                    if duration >= MINIMUM_APP_TIME as f64 {
                        self.record_app_session(&old_app, start, now, duration);
                    }
                }
                self.current_app = Some(app);
                self.app_start_time = Some(now);
            } else if let Some(start) = self.app_start_time {
                if now - start >= 300.0 {
                    let duration = now - start;
                    self.record_app_session(self.current_app.as_ref().unwrap(), start, now, duration);
                    self.app_start_time = Some(now);
                }
            }
        } else {
            if let (Some(app), Some(start)) = (self.current_app.take(), self.app_start_time.take()) {
                let duration = now - start;
                if duration >= MINIMUM_APP_TIME as f64 {
                    self.record_app_session(&app, start, now, duration);
                }
            }
        }

        self.current_app.clone()
    }

    fn check_device_active(&self) -> bool {
        let mut lii = LASTINPUTINFO {
            cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        unsafe {
            if GetLastInputInfo(&mut lii).as_bool() {
                let current_tick = windows::Win32::System::SystemInformation::GetTickCount64();
                let _last_input_tick = lii.dwTime as u64;
                
                // Handle the 32-bit wrap around of lii.dwTime
                let current_tick_32 = (current_tick & 0xFFFFFFFF) as u32;
                let idle_ticks = if current_tick_32 >= lii.dwTime {
                    current_tick_32 - lii.dwTime
                } else {
                    (u32::MAX - lii.dwTime) + current_tick_32
                };
                
                let idle_secs = idle_ticks as f64 / 1000.0;
                idle_secs < 120.0 // 2 minutes idle threshold
            } else {
                true
            }
        }
    }

    fn get_active_app(&mut self) -> Option<String> {
        let hwnd = unsafe { GetForegroundWindow() };
        if hwnd.0 == 0 {
            return None;
        }

        let mut pid: u32 = 0;
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };

        self.sys.refresh_processes();

        if let Some(process) = self.sys.process(sysinfo::Pid::from(pid as usize)) {
            let name = process.name().to_lowercase().replace(".exe", "");
            if self.should_ignore_app(&name) {
                None
            } else {
                Some(name)
            }
        } else {
            None
        }
    }

    fn should_ignore_app(&self, app_name: &str) -> bool {
        let ignores = get_ignore_apps();
        ignores.iter().any(|&i| app_name.contains(&i.to_lowercase()))
    }

    fn record_app_session(&self, app_name: &str, start_time: f64, _end_time: f64, duration: f64) {
        let timestamp = DateTime::<Local>::from(UNIX_EPOCH + Duration::from_secs_f64(start_time))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        
        let log_line = format!("[{}] {}: {:.1}s\n", timestamp, app_name, duration);
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("logs/app_timelog.log") {
            let _ = file.write_all(log_line.as_bytes());
        }

        let mut data = self.data.lock().unwrap();
        *data.app_total_time.entry(app_name.to_string()).or_insert(0.0) += duration;
        *data.app_sessions.entry(app_name.to_string()).or_insert(0) += 1;

        let category = self.get_app_category(app_name);
        *data.app_category_time.entry(category).or_insert(0.0) += duration;
    }

    fn get_app_category(&self, app_name: &str) -> String {
        let categories = get_app_categories();
        for (cat, apps) in categories {
            if apps.iter().any(|&a| app_name.contains(&a.to_lowercase())) {
                return cat.to_string();
            }
        }
        "Other".to_string()
    }

    pub fn get_app_data_for_api(&self) -> crate::config::client::AppUsageData {
        let (data, current_app, start_time) = {
            let data = self.data.lock().unwrap();
            (data.clone(), self.current_app.clone(), self.app_start_time)
        };

        let now = current_time_secs();
        let current_session_duration = if let Some(start) = start_time {
            now - start
        } else {
            0.0
        };

        let mut top_apps = Vec::new();
        let mut sorted_apps: Vec<_> = data.app_total_time.iter().collect();
        sorted_apps.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));

        for (name, time) in sorted_apps.iter().take(5) {
            let category = self.get_app_category(name);
            top_apps.push(serde_json::json!({
                "app": *name,
                "active_time": **time,
                "category": category,
                "sessions": data.app_sessions.get(*name).unwrap_or(&0)
            }));
        }

        let active_usage_time: f64 = data.app_total_time.values().sum();

        crate::config::client::AppUsageData {
            device_id: crate::config::api_config::get_device_id(),
            timestamp: Local::now().to_rfc3339(),
            current_app: current_app.unwrap_or_else(|| "Idle".to_string()),
            current_session_duration,
            total_apps_tracked: data.app_total_time.len() as u32,
            total_time_tracked: active_usage_time, // Or use a separate system uptime if needed
            active_usage_time,
            top_apps,
            category_breakdown: data.app_category_time.clone(),
        }
    }
}

fn current_time_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
}
