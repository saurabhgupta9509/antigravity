use std::collections::HashMap;
use std::sync::OnceLock;

pub const CHECK_INTERVAL: u64 = 3;
pub const TRACK_APP_USAGE: bool = true;
pub const MINIMUM_APP_TIME: u64 = 5;

pub fn get_ignore_apps() -> &'static [&'static str] {
    static IGNORE_APPS: OnceLock<Vec<&'static str>> = OnceLock::new();
    IGNORE_APPS.get_or_init(|| vec![
        "explorer", "svchost", "System", "Idle", "Registry", "smss", "csrss",
        "wininit", "winlogon", "services", "lsass", "taskhost", "dwm", "conhost",
        "cmd", "powershell", "pwsh", "python", "pythonw", "javaw", "java",
        "WmiPrvSE", "sihost", "ctfmon", "RuntimeBroker", "SearchUI",
        "StartMenuExperienceHost", "Widgets", "Calculator", "notepad", "wordpad",
        "mspaint", "SystemSettings", "Taskmgr", "SecurityHealthSystray",
        "SecurityHealthService", "CybersecurityMonitor",
    ])
}

pub fn get_app_categories() -> &'static HashMap<&'static str, Vec<&'static str>> {
    static APP_CATEGORIES: OnceLock<HashMap<&'static str, Vec<&'static str>>> = OnceLock::new();
    APP_CATEGORIES.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert("Browsers", vec!["chrome", "firefox", "msedge", "opera", "brave", "vivaldi", "safari", "tor"]);
        m.insert("Communication", vec!["teams", "zoom", "discord", "slack", "whatsapp", "signal", "telegram", "skype"]);
        m.insert("Social Media", vec!["facebook", "instagram", "twitter", "tiktok", "reddit", "linkedin", "pinterest"]);
        m.insert("Productivity", vec!["winword", "excel", "powerpnt", "outlook", "onenote", "notepad++", "vscode", "code"]);
        m.insert("Entertainment", vec!["spotify", "vlc", "netflix", "disney+", "primevideo", "steam", "epicgameslauncher"]);
        m.insert("Development", vec!["vscode", "code", "pycharm", "intellij", "androidstudio", "visualstudio", "git", "docker"]);
        m.insert("Creative", vec!["photoshop", "illustrator", "premiere", "aftereffects", "blender", "audacity", "obs"]);
        m.insert("Utilities", vec!["explorer", "taskmgr", "control", "settings", "calculator", "mspaint", "cmd", "powershell"]);
        m
    })
}
