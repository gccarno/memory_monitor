use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe: Option<String>,
    pub cmdline: Option<Vec<String>>,
    pub create_time: f64,
    pub private_bytes: i64,
    pub working_set: i64,
    pub cpu_s: Option<f64>,
    pub io_bytes: Option<i64>,
    pub cwd: Option<String>,
    pub limited: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub description: String,
    /// "automatic" | "manual" | "disabled"
    pub start_type: String,
    pub pid: Option<u32>,
    pub binpath: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub ts: i64,
    pub ram_total: i64,
    pub ram_avail: i64,
    pub commit_used: i64,
    pub commit_limit: i64,
    pub compression_ws: Option<i64>,
    pub pool_paged: i64,
    pub pool_nonpaged: i64,
    pub boot_time: i64,
    pub logger_ws: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppGroup {
    pub app_key: String,
    pub label: String,
    /// "suite" | "instance" | "windows" | "protected"
    pub kind: String,
    pub pids: Vec<(u32, f64)>,
    pub private_bytes: i64,
    pub working_set: i64,
    pub services: Vec<String>,
    pub limited: bool,
    pub microsoft: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageFlags {
    pub foreground: bool,
    pub active: bool,
    pub has_windows: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleRow {
    pub ts: i64,
    pub private_bytes: i64,
    pub working_set: i64,
    pub foreground: bool,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppRecord {
    pub app_key: String,
    pub label: String,
    pub kind: String,
    pub microsoft: bool,
    pub first_seen: i64,
    pub last_seen: i64,
    pub last_used: Option<i64>,
    pub last_active: Option<i64>,
    pub has_windows_ever: bool,
    pub limited: bool,
    pub services: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StartupEntry {
    /// "run" | "startup_folder" | "packaged" | "task" | "service"
    pub source: String,
    pub name: String,
    pub location: String,
    pub command: String,
    pub enabled: bool,
    pub needs_admin: bool,
    pub can_disable: bool,
    pub note: Option<String>,
    pub app_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionRecord {
    pub id: Option<i64>,
    pub ts: i64,
    pub app_key: String,
    pub action: String,
    pub entry: serde_json::Value,
    pub before: serde_json::Value,
    pub undone: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionResult {
    /// 'done'|'still_open'|'already_stopped'|'declined'|'failed'|'partial'
    pub status: String,
    pub message: String,
    #[serde(default)]
    pub remaining_pids: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Suggestion {
    pub app_key: String,
    pub label: String,
    pub kind: String,
    pub private_bytes: i64,
    pub working_set: i64,
    pub typical_private: i64,
    pub last_used: Option<i64>,
    pub idle_observed_s: i64,
    pub reasons: Vec<String>,
    pub reason_codes: Vec<String>,
    pub has_windows: bool,
    pub caution: Option<String>,
    pub limited: bool,
    pub startup: Vec<StartupEntry>,
    pub service_modes: Vec<String>,
    pub services: Vec<String>,
    pub n_procs: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppSummary {
    pub app_key: String,
    pub label: String,
    pub private_bytes: i64,
    pub last_used: Option<i64>,
    pub autostart: bool,
    pub spark: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub now: i64,
    pub system: Option<SystemSnapshot>,
    pub observed_hours: f64,
    pub partial_note: Option<String>,
    pub reclaimable: i64,
    pub suggestions: Vec<Suggestion>,
    pub apps: Vec<AppSummary>,
    pub kernel_note: Option<String>,
    pub uptime_s: i64,
    pub logger_ws: Option<i64>,
    pub logger_over_cap: bool,
    pub undo: Vec<ActionRecord>,
    pub data_ts: Option<i64>,
    pub stale: bool,
}
