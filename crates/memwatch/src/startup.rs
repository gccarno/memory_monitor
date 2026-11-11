//! Startup inventory (what starts with Windows) and the switches that turn it off.
//!
//! Run-key and Startup-folder entries use Windows' own `StartupApproved` switches (as
//! Task Manager does); packaged apps use their startup-task `State`; logon tasks use
//! `schtasks`; services use the SCM through the elevated runner.

use std::fmt;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};
use winreg::enums::*;
use winreg::{RegKey, RegValue};

use crate::config::Config;
use crate::grouping::suite_from_path;
use crate::models::StartupEntry;
use crate::probe;

const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";
const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN32: &str = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
const PKG: &str = r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData";
const PKG_NOTE: &str = "Windows blocks changes to this packaged service; uninstall the app to remove it";
pub const WINDOWS_TASK_NOTE: &str = "Windows system task";
const FILETIME_EPOCH: u64 = 11_644_473_600;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The three StartupApproved subkeys, by kind.
pub fn approved_path(kind: &str) -> Option<String> {
    match kind {
        "run" => Some(format!(r"{APPROVED}\Run")),
        "run32" => Some(format!(r"{APPROVED}\Run32")),
        "startup_folder" => Some(format!(r"{APPROVED}\StartupFolder")),
        _ => None,
    }
}

/// All StartupApproved subkeys (what the elevated runner may write under HKLM).
pub fn approved_paths() -> Vec<String> {
    ["run", "run32", "startup_folder"].iter().filter_map(|k| approved_path(k)).collect()
}

#[derive(Debug)]
pub enum StartupError {
    /// The entry needs elevation or has no supported switch.
    Permission(String),
    /// Bad input: unsupported source or mode.
    Value(String),
    /// The registry refused or failed.
    Os(String),
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupError::Permission(s) | StartupError::Value(s) | StartupError::Os(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for StartupError {}

impl From<std::io::Error> for StartupError {
    fn from(e: std::io::Error) -> Self {
        StartupError::Os(e.to_string())
    }
}

pub fn approved_bytes(enabled: bool, filetime: u64) -> Vec<u8> {
    if enabled {
        let mut v = vec![2u8];
        v.extend([0u8; 11]);
        v
    } else {
        let mut v = 3u32.to_le_bytes().to_vec();
        v.extend(filetime.to_le_bytes());
        v
    }
}

pub fn approved_is_enabled(data: Option<&[u8]>) -> bool {
    match data {
        None => true,
        Some(d) => d.is_empty() || d[0] & 1 == 0,
    }
}

fn now_filetime() -> u64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    ((secs + FILETIME_EPOCH as f64) * 10_000_000.0) as u64
}

fn p(root: &str, path: &str) -> String {
    if root.is_empty() {
        path.to_string()
    } else {
        format!(r"{root}\{path}")
    }
}

fn hive(name: &str) -> RegKey {
    RegKey::predef(if name == "HKLM" { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER })
}

fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

// ---- command parsing ------------------------------------------------------

fn expand_vars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after.find('%') {
            Some(j) if j > 0 => match std::env::var(&after[..j]) {
                Ok(v) => {
                    out.push_str(&v);
                    rest = &after[j + 1..];
                }
                Err(_) => {
                    out.push('%');
                    rest = after;
                }
            },
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

static CMD_SWITCH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)/[ck]\s+(.*)").unwrap());

/// First `prefix.exe|com|bat|cmd` (no quotes in the prefix) followed by whitespace, a quote or the end.
fn unquoted_exe_prefix(cmd: &str) -> Option<usize> {
    let lower = cmd.to_ascii_lowercase();
    let mut i = 0;
    while i < lower.len() {
        let dot = lower[i..].find('.').map(|d| d + i)?;
        i = dot + 1;
        let tail = &lower[dot..];
        let Some(ext) = [".exe", ".com", ".bat", ".cmd"].iter().find(|e| tail.starts_with(**e)) else { continue };
        let end = dot + ext.len();
        if cmd[..end].contains('"') {
            return None;
        }
        if dot == 0 {
            continue;
        }
        match cmd[end..].chars().next() {
            None => return Some(end),
            Some(c) if c.is_whitespace() || c == '"' => return Some(end),
            _ => {}
        }
    }
    None
}

/// Best-effort extraction of the executable (or wrapped target) from a command line.
pub fn parse_command(command: &str) -> String {
    let cmd = expand_vars(command.trim());
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return String::new();
    }
    let (exe, rest): (String, String) = if let Some(stripped) = cmd.strip_prefix('"') {
        match stripped.find('"') {
            Some(end) => (stripped[..end].to_string(), stripped[end + 1..].to_string()),
            None => (stripped.to_string(), String::new()),
        }
    } else if let Some(end) = unquoted_exe_prefix(cmd) {
        (cmd[..end].to_string(), cmd[end..].to_string())
    } else {
        match cmd.split_once(' ') {
            Some((a, b)) => (a.to_string(), b.to_string()),
            None => (cmd.to_string(), String::new()),
        }
    };
    let base = basename(&exe).to_lowercase();
    if base == "rundll32" || base == "rundll32.exe" {
        let r = rest.trim_start();
        let r = r.strip_prefix('"').unwrap_or(r);
        let stop = r.find(['"', ',']).unwrap_or(r.len());
        let cand = r[..stop].trim();
        let after = r[stop..].trim_start_matches('"').trim_start();
        let ok = after.is_empty() || after.starts_with(',');
        if ok && !cand.is_empty() && (cand.contains('\\') || cand.to_lowercase().ends_with(".dll")) {
            return cand.to_string();
        }
    } else if base == "cmd" || base == "cmd.exe" {
        if let Some(m) = CMD_SWITCH.captures(&rest) {
            return parse_command(&m[1]);
        }
    }
    exe
}

fn is_binary_like(exe: &str) -> bool {
    let l = exe.to_lowercase();
    exe.contains('\\') || [".exe", ".com", ".bat", ".cmd", ".dll"].iter().any(|e| l.ends_with(e))
}

fn key_for(exe: &str, name: &str, cfg: &Config) -> Option<String> {
    if exe.is_empty() || !is_binary_like(exe) {
        return None; // e.g. "COM handler"
    }
    let base = basename(exe);
    Some(suite_from_path(Some(exe), if base.is_empty() { name } else { base }, cfg).0)
}

// ---- registry helpers -----------------------------------------------------

fn reg_string(v: &RegValue) -> Option<String> {
    if v.vtype != REG_SZ && v.vtype != REG_EXPAND_SZ {
        return None;
    }
    let wide: Vec<u16> = v.bytes.chunks(2).filter(|c| c.len() == 2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Some(String::from_utf16_lossy(&wide).trim_end_matches('\0').to_string())
}

/// Every REG_SZ / REG_EXPAND_SZ value under `path`, in registry order.
fn string_values(h: &RegKey, path: &str) -> Vec<(String, String)> {
    let Ok(k) = h.open_subkey_with_flags(path, KEY_READ) else { return Vec::new() };
    k.enum_values()
        .filter_map(Result::ok)
        .filter_map(|(n, v)| reg_string(&v).map(|s| (n, s)))
        .collect()
}

fn subkeys(h: &RegKey, path: &str) -> Vec<String> {
    let Ok(k) = h.open_subkey_with_flags(path, KEY_READ) else { return Vec::new() };
    k.enum_keys().filter_map(Result::ok).collect()
}

fn read_approved(hive_name: &str, kind: &str, name: &str, root: &str) -> Option<Vec<u8>> {
    let base = approved_path(kind)?;
    let path = if hive_name == "HKCU" { p(root, &base) } else { base };
    let k = hive(hive_name).open_subkey_with_flags(path, KEY_READ).ok()?;
    let v = k.get_raw_value(name).ok()?;
    (v.vtype == REG_BINARY).then_some(v.bytes)
}

fn write_approved(name: &str, kind: &str, data: Option<&[u8]>, root: &str) -> Result<(), StartupError> {
    let base = approved_path(kind).ok_or_else(|| StartupError::Value(format!("unknown kind {kind}")))?;
    let (k, _) = hive("HKCU").create_subkey_with_flags(p(root, &base), KEY_SET_VALUE)?;
    match data {
        None => match k.delete_value(name) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        },
        Some(d) => {
            k.set_raw_value(name, &RegValue { bytes: d.to_vec(), vtype: REG_BINARY })?;
            Ok(())
        }
    }
}

// ---- inventory sources ----------------------------------------------------

fn run_entries(cfg: &Config, root: &str) -> Vec<StartupEntry> {
    let mut specs: Vec<(&str, String, &str, bool)> = vec![("HKCU", p(root, RUN), "run", false)];
    if root.is_empty() {
        specs.push(("HKLM", RUN.to_string(), "run", true));
        specs.push(("HKLM32", RUN32.to_string(), "run32", true));
    }
    let mut out = Vec::new();
    for (hive_name, path, kind, admin) in specs {
        let h = hive(if admin { "HKLM" } else { "HKCU" });
        for (name, cmd) in string_values(&h, &path) {
            let approved = read_approved(if admin { "HKLM" } else { "HKCU" }, kind, &name, root);
            let enabled = approved_is_enabled(approved.as_deref());
            let exe = parse_command(&cmd);
            out.push(StartupEntry {
                source: "run".into(),
                location: format!(r"{hive_name}\{name}"),
                app_key: key_for(&exe, &name, cfg),
                name,
                command: cmd,
                enabled,
                needs_admin: admin,
                can_disable: true,
                note: None,
            });
        }
    }
    out
}

fn lnk_target(path: &str) -> String {
    use windows::core::{Interface, PCWSTR};
    use windows::Win32::Storage::FileSystem::WIN32_FIND_DATAW;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, IPersistFile, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, STGM_READ,
    };
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let Ok(link) = CoCreateInstance::<_, IShellLinkW>(&ShellLink, None, CLSCTX_INPROC_SERVER) else {
            return String::new();
        };
        let Ok(file) = link.cast::<IPersistFile>() else { return String::new() };
        let w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        if file.Load(PCWSTR(w.as_ptr()), STGM_READ).is_err() {
            return String::new();
        }
        let mut buf = [0u16; 1024];
        let mut fd = WIN32_FIND_DATAW::default();
        if link.GetPath(&mut buf, &mut fd, 0).is_err() {
            return String::new();
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }
}

fn folder_entries(cfg: &Config) -> Vec<StartupEntry> {
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let progdata = std::env::var("PROGRAMDATA").unwrap_or_default();
    let folders = [
        (format!(r"{appdata}\Microsoft\Windows\Start Menu\Programs\Startup"), false),
        (format!(r"{progdata}\Microsoft\Windows\Start Menu\Programs\StartUp"), true),
    ];
    let mut out = Vec::new();
    for (folder, admin) in folders {
        let Ok(rd) = std::fs::read_dir(&folder) else { continue };
        for ent in rd.flatten() {
            let fn_ = ent.file_name().to_string_lossy().to_string();
            if fn_.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let full = format!(r"{folder}\{fn_}");
            let target = if fn_.to_lowercase().ends_with(".lnk") { lnk_target(&full) } else { full.clone() };
            let approved = read_approved(if admin { "HKLM" } else { "HKCU" }, "startup_folder", &fn_, "");
            out.push(StartupEntry {
                source: "startup_folder".into(),
                app_key: key_for(&target, &fn_, cfg),
                name: fn_,
                location: full,
                command: target,
                enabled: approved_is_enabled(approved.as_deref()),
                needs_admin: admin,
                can_disable: true,
                note: None,
            });
        }
    }
    out
}

fn packaged_entries(cfg: &Config) -> Vec<StartupEntry> {
    let h = hive("HKCU");
    let mut out = Vec::new();
    for pkg in subkeys(&h, PKG) {
        for task in subkeys(&h, &format!(r"{PKG}\{pkg}")) {
            let path = format!(r"{PKG}\{pkg}\{task}");
            let Ok(k) = h.open_subkey_with_flags(&path, KEY_READ) else { continue };
            let Ok(state) = k.get_value::<u32, _>("State") else { continue };
            let short = pkg.split('_').next().unwrap_or(&pkg).to_string();
            let key = suite_from_path(
                Some(&format!(r"C:\Program Files\WindowsApps\{pkg}\app.exe")),
                &short,
                cfg,
            )
            .0;
            out.push(StartupEntry {
                source: "packaged".into(),
                name: format!("{short} ({task})"),
                location: format!(r"{pkg}\{task}"),
                command: String::new(),
                enabled: state == 2 || state == 4,
                needs_admin: false,
                can_disable: true,
                note: None,
                app_key: Some(key),
            });
        }
    }
    out
}

/// Tasks under \Microsoft\Windows\ belong to Windows: shown read-only, never changed.
pub fn is_windows_task(location: &str) -> bool {
    location.to_lowercase().starts_with(r"\microsoft\windows\")
}

fn user_names() -> Vec<String> {
    let u = std::env::var("USERNAME").unwrap_or_default().to_lowercase();
    if u.is_empty() {
        return Vec::new();
    }
    let d = std::env::var("USERDOMAIN").unwrap_or_default().to_lowercase();
    vec![u.clone(), format!(r"{d}\{u}")]
}

fn schtasks(args: &[&str]) -> Option<(bool, String)> {
    let out = Command::new("schtasks").args(args).creation_flags(CREATE_NO_WINDOW).output().ok()?;
    Some((out.status.success(), String::from_utf8_lossy(&out.stdout).to_string()))
}

/// Logon tasks from the CSV that `schtasks /query /fo csv /v` prints.
pub fn task_entries_from_csv(text: &str, cfg: &Config) -> Vec<StartupEntry> {
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(text.as_bytes());
    let Ok(headers) = rdr.headers().cloned() else { return Vec::new() };
    let col = |n: &str| headers.iter().position(|h| h == n);
    let (c_name, c_sched, c_cmd, c_auth, c_run, c_state) = (
        col("TaskName"),
        col("Schedule Type"),
        col("Task To Run"),
        col("Author"),
        col("Run As User"),
        col("Scheduled Task State"),
    );
    let me = user_names();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for rec in rdr.records().flatten() {
        let get = |c: Option<usize>| c.and_then(|i| rec.get(i)).unwrap_or("");
        let name = get(c_name);
        if name.is_empty() || name == "TaskName" || seen.contains(name) {
            continue;
        }
        if !get(c_sched).to_lowercase().contains("logon") {
            continue;
        }
        seen.insert(name.to_string());
        let cmd = get(c_cmd).trim().to_string();
        let author = get(c_auth).to_lowercase();
        let runas = get(c_run).to_lowercase();
        let mine = me.contains(&author) || ((author.is_empty() || author == "n/a") && me.contains(&runas));
        let admin = !(name.starts_with('\\') && mine);
        let exe = if !cmd.is_empty() && !cmd.eq_ignore_ascii_case("n/a") { parse_command(&cmd) } else { String::new() };
        let system = is_windows_task(name);
        out.push(StartupEntry {
            source: "task".into(),
            name: basename(name).to_string(),
            location: name.to_string(),
            command: cmd,
            enabled: get(c_state).to_lowercase() == "enabled",
            needs_admin: admin,
            can_disable: !system,
            note: system.then(|| WINDOWS_TASK_NOTE.to_string()),
            app_key: key_for(&exe, name, cfg),
        });
    }
    out
}

fn task_entries(cfg: &Config) -> Vec<StartupEntry> {
    match schtasks(&["/query", "/fo", "csv", "/v"]) {
        Some((_, text)) => task_entries_from_csv(&text, cfg),
        None => {
            log::warn!("schtasks query failed");
            Vec::new()
        }
    }
}

/// Live state of one scheduled task; None when it cannot be read.
pub fn task_enabled(name: &str) -> Option<bool> {
    let (ok, text) = schtasks(&["/query", "/tn", name, "/fo", "csv", "/nh"])?;
    if !ok {
        return None;
    }
    let mut rdr = csv::ReaderBuilder::new().has_headers(false).flexible(true).from_reader(text.as_bytes());
    rdr.records().flatten().find_map(|r| (r.len() >= 3).then(|| r[2].trim().to_lowercase() != "disabled"))
}

/// Current state of a non-service entry read from Windows, or None when unreadable.
pub fn live_enabled(entry: &StartupEntry, root: &str) -> Option<bool> {
    match entry.source.as_str() {
        "run" | "startup_folder" => {
            let (h, kind, name) = approved_target(entry);
            let r = if h == "HKCU" { root } else { "" };
            Some(approved_is_enabled(read_approved(h, kind, &name, r).as_deref()))
        }
        "packaged" => {
            let k = hive("HKCU").open_subkey_with_flags(pkg_key(entry, root), KEY_READ).ok()?;
            let s: u32 = k.get_value("State").ok()?;
            Some(s == 2 || s == 4)
        }
        "task" => task_enabled(&entry.location),
        _ => None,
    }
}

fn service_entries(cfg: &Config) -> Vec<StartupEntry> {
    let mut out = Vec::new();
    for s in probe::all_services() {
        if s.start_type != "automatic" {
            continue;
        }
        let low = s.binpath.to_lowercase();
        let key = if low.contains("svchost.exe") {
            Some(format!("service:{}", s.name.to_lowercase()))
        } else {
            key_for(&parse_command(&s.binpath), &s.name, cfg)
        };
        let packaged = low.contains(r"\windowsapps\");
        out.push(StartupEntry {
            source: "service".into(),
            name: if s.display_name.is_empty() { s.name.clone() } else { s.display_name.clone() },
            location: s.name.clone(),
            command: s.binpath.clone(),
            enabled: true,
            needs_admin: true,
            can_disable: !packaged,
            note: packaged.then(|| PKG_NOTE.to_string()),
            app_key: key,
        });
    }
    out
}

/// Every startup source. A non-empty `root` (tests only) reads just the HKCU Run key under it.
pub fn inventory(cfg: &Config, root: &str) -> Vec<StartupEntry> {
    let mut out = run_entries(cfg, root);
    if root.is_empty() {
        out.extend(folder_entries(cfg));
        out.extend(packaged_entries(cfg));
        out.extend(task_entries(cfg));
        out.extend(service_entries(cfg));
    }
    out
}

// ---- toggles --------------------------------------------------------------

/// (hive, kind, value name) for a StartupApproved-backed entry.
pub fn approved_target(entry: &StartupEntry) -> (&'static str, &'static str, String) {
    if entry.source == "startup_folder" {
        return (
            if entry.needs_admin { "HKLM" } else { "HKCU" },
            "startup_folder",
            basename(&entry.location).to_string(),
        );
    }
    let (h, name) = entry.location.split_once('\\').unwrap_or((&entry.location, ""));
    (
        if h.starts_with("HKLM") { "HKLM" } else { "HKCU" },
        if h == "HKLM32" { "run32" } else { "run" },
        name.to_string(),
    )
}

fn pkg_key(entry: &StartupEntry, root: &str) -> String {
    p(root, &format!(r"{PKG}\{}", entry.location))
}

/// Switch a non-admin entry; returns the `before` state for Undo.
pub fn apply_toggle(entry: &StartupEntry, enabled: bool, _mode: Option<&str>, root: &str) -> Result<Value, StartupError> {
    if entry.needs_admin || !entry.can_disable {
        return Err(StartupError::Permission(format!("{} cannot be changed without elevation", entry.name)));
    }
    match entry.source.as_str() {
        "packaged" => {
            let k = hive("HKCU").open_subkey_with_flags(pkg_key(entry, root), KEY_READ | KEY_SET_VALUE)?;
            let old: u32 = k.get_value("State")?;
            k.set_value("State", &(if enabled { 2u32 } else { 1u32 }))?;
            Ok(json!({"state": old}))
        }
        "run" | "startup_folder" => {
            let (_, kind, name) = approved_target(entry);
            let old = read_approved("HKCU", kind, &name, root);
            let data = approved_bytes(enabled, if enabled { 0 } else { now_filetime() });
            write_approved(&name, kind, Some(&data), root)?;
            Ok(json!({"approved": old.map(hex_encode)}))
        }
        other => Err(StartupError::Value(format!("unsupported source {other}"))),
    }
}

pub fn restore(entry: &StartupEntry, before: &Value, root: &str) -> Result<(), StartupError> {
    if !["run", "startup_folder", "packaged"].contains(&entry.source.as_str()) || entry.needs_admin {
        return Err(StartupError::Value(format!(
            "restore does not support {} entry {:?}",
            entry.source, entry.name
        )));
    }
    if entry.source == "packaged" {
        let state = before["state"]
            .as_u64()
            .ok_or_else(|| StartupError::Value("missing state".into()))? as u32;
        let k = hive("HKCU").open_subkey_with_flags(pkg_key(entry, root), KEY_SET_VALUE)?;
        k.set_value("State", &state)?;
        return Ok(());
    }
    let (_, kind, name) = approved_target(entry);
    let raw = match &before["approved"] {
        Value::Null => None,
        Value::String(s) => Some(hex_decode(s).ok_or_else(|| StartupError::Value("bad hex".into()))?),
        _ => return Err(StartupError::Value("bad approved value".into())),
    };
    write_approved(&name, kind, raw.as_deref(), root)
}

pub fn hex_encode(b: impl AsRef<[u8]>) -> String {
    b.as_ref().iter().map(|x| format!("{x:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Ops for the UAC runner (admin-only changes). Fails closed on anything unsupported.
pub fn elevated_ops_for(entry: &StartupEntry, enabled: bool, mode: Option<&str>) -> Result<Vec<Value>, StartupError> {
    if !entry.can_disable {
        return Err(StartupError::Value(format!(
            "{:?} cannot be changed: {}",
            entry.name,
            entry.note.as_deref().unwrap_or("no supported switch")
        )));
    }
    if entry.source == "task" && is_windows_task(&entry.location) {
        return Err(StartupError::Value(format!("{:?} cannot be changed: {WINDOWS_TASK_NOTE}", entry.name)));
    }
    match entry.source.as_str() {
        "run" | "startup_folder" => {
            let (h, kind, name) = approved_target(entry);
            let data = approved_bytes(enabled, if enabled { 0 } else { now_filetime() });
            Ok(vec![json!({"op": "set_approved", "hive": h, "subkey": approved_path(kind),
                           "value": name, "data_hex": hex_encode(data)})])
        }
        "task" => Ok(vec![json!({"op": "set_task", "name": entry.location, "enabled": enabled})]),
        "service" => {
            let start = if enabled {
                match mode {
                    None | Some("auto") => "auto",
                    Some("demand") | Some("manual") => "demand",
                    _ => return Err(StartupError::Value(format!("invalid service mode {mode:?}"))),
                }
            } else {
                match mode {
                    Some("manual") => "demand",
                    Some("disabled") => "disabled",
                    _ => return Err(StartupError::Value(format!("invalid service mode {mode:?}"))),
                }
            };
            Ok(vec![json!({"op": "set_service_start", "name": entry.location, "start": start})])
        }
        other => Err(StartupError::Value(format!("{other} entries are changed with apply_toggle, not elevated ops"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ent(source: &str, location: &str, admin: bool) -> StartupEntry {
        StartupEntry {
            source: source.into(), name: "n".into(), location: location.into(), command: String::new(),
            enabled: true, needs_admin: admin, can_disable: true, note: None, app_key: None,
        }
    }

    /// A throwaway HKCU subtree, deleted before and after the test.
    struct TestRoot(String);
    impl TestRoot {
        fn new(name: &str) -> Self {
            let r = format!(r"Software\memwatch-test-rs-{name}");
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&r);
            TestRoot(r)
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.0);
        }
    }

    fn set_hkcu(path: &str, name: &str, value: &str) {
        let (k, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey_with_flags(path, KEY_SET_VALUE).unwrap();
        k.set_value(name, &value).unwrap();
    }

    fn raw_approved(path: &str, name: &str) -> Option<Vec<u8>> {
        let k = RegKey::predef(HKEY_CURRENT_USER).open_subkey(path).ok()?;
        k.get_raw_value(name).ok().map(|v| v.bytes)
    }

    fn find(cfg: &Config, root: &str, name: &str) -> StartupEntry {
        inventory(cfg, root).into_iter().find(|x| x.name == name).unwrap()
    }

    #[test]
    fn approved_bytes_roundtrip() {
        assert!(approved_is_enabled(None));
        assert!(approved_is_enabled(Some(&approved_bytes(true, 0))));
        let d = approved_bytes(false, 133_000_000_000_000_000);
        assert!(d.len() == 12 && !approved_is_enabled(Some(&d)));
    }

    #[test]
    fn inventory_and_toggle_run_entry() {
        let t = TestRoot::new("run");
        let cfg = Config::default();
        set_hkcu(&format!(r"{}\{RUN}", t.0), "DummyApp", r#""C:\Program Files\Dummy\dummy.exe" --min"#);
        let e = find(&cfg, &t.0, "DummyApp");
        assert!(e.source == "run" && e.enabled && !e.needs_admin);
        assert_eq!(e.app_key.as_deref(), Some("suite:dummy"));
        assert_eq!(e.location, r"HKCU\DummyApp");
        let before = apply_toggle(&e, false, None, &t.0).unwrap();
        assert_eq!(before, json!({"approved": null}));
        let apath = format!(r"{}\{}", t.0, approved_path("run").unwrap());
        assert!(!approved_is_enabled(raw_approved(&apath, "DummyApp").as_deref()));
        assert!(!find(&cfg, &t.0, "DummyApp").enabled);
        restore(&e, &before, &t.0).unwrap();
        assert!(raw_approved(&apath, "DummyApp").is_none()); // deleted, not rewritten
        assert!(find(&cfg, &t.0, "DummyApp").enabled);
    }

    #[test]
    fn restore_previous_bytes() {
        let t = TestRoot::new("prev");
        let cfg = Config::default();
        set_hkcu(&format!(r"{}\{RUN}", t.0), "DummyApp", r"C:\x\y.exe -a");
        let e = find(&cfg, &t.0, "DummyApp");
        let b1 = apply_toggle(&e, false, None, &t.0).unwrap();
        let b2 = apply_toggle(&e, true, None, &t.0).unwrap();
        let prev = hex_decode(b2["approved"].as_str().unwrap()).unwrap();
        assert!(!approved_is_enabled(Some(&prev)));
        restore(&e, &b2, &t.0).unwrap();
        assert!(!find(&cfg, &t.0, "DummyApp").enabled);
        restore(&e, &b1, &t.0).unwrap();
        let apath = format!(r"{}\{}", t.0, approved_path("run").unwrap());
        assert!(raw_approved(&apath, "DummyApp").is_none());
    }

    #[test]
    fn restore_exact_prior_bytes() {
        let t = TestRoot::new("exact");
        let cfg = Config::default();
        set_hkcu(&format!(r"{}\{RUN}", t.0), "DummyApp", r"C:\x\y.exe");
        let apath = format!(r"{}\{}", t.0, approved_path("run").unwrap());
        let mut prior = vec![3u8, 0, 0, 0];
        prior.extend([0x11u8; 8]);
        let (k, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey_with_flags(&apath, KEY_SET_VALUE).unwrap();
        k.set_raw_value("DummyApp", &RegValue { bytes: prior.clone(), vtype: REG_BINARY }).unwrap();
        let e = find(&cfg, &t.0, "DummyApp");
        assert!(!e.enabled);
        let before = apply_toggle(&e, true, None, &t.0).unwrap();
        assert_eq!(raw_approved(&apath, "DummyApp").unwrap(), approved_bytes(true, 0));
        restore(&e, &before, &t.0).unwrap();
        assert_eq!(raw_approved(&apath, "DummyApp").unwrap(), prior);
    }

    #[test]
    fn packaged_toggle_roundtrip() {
        let t = TestRoot::new("pkg");
        let loc = r"Pkg_1.0_x64__abc\Task1";
        let path = format!(r"{}\{PKG}\{loc}", t.0);
        let (k, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey_with_flags(&path, KEY_SET_VALUE).unwrap();
        k.set_value("State", &2u32).unwrap();
        let e = StartupEntry {
            source: "packaged".into(), name: "Pkg (Task1)".into(), location: loc.into(), command: String::new(),
            enabled: true, needs_admin: false, can_disable: true, note: None, app_key: Some("suite:pkg".into()),
        };
        let state = || -> u32 { RegKey::predef(HKEY_CURRENT_USER).open_subkey(&path).unwrap().get_value("State").unwrap() };
        let before = apply_toggle(&e, false, None, &t.0).unwrap();
        assert_eq!(before, json!({"state": 2}));
        assert_eq!(state(), 1);
        restore(&e, &before, &t.0).unwrap();
        assert_eq!(state(), 2);
    }

    #[test]
    fn hive_and_subkey_selection() {
        let cases = [
            (ent("run", r"HKLM\n", true), "HKLM", "run", "n"),
            (ent("run", r"HKLM32\n", true), "HKLM", "run32", "n"),
            (ent("startup_folder", r"C:\ProgramData\Startup\n.lnk", true), "HKLM", "startup_folder", "n.lnk"),
        ];
        for (e, h, kind, value) in cases {
            let ops = elevated_ops_for(&e, false, None).unwrap();
            let op = &ops[0];
            assert_eq!(op["hive"], h);
            assert_eq!(op["subkey"], approved_path(kind).unwrap());
            assert_eq!(op["value"], value);
        }
        // non-admin entries resolve to HKCU
        assert_eq!(approved_target(&ent("run", r"HKCU\n", false)), ("HKCU", "run", "n".to_string()));
        assert_eq!(
            approved_target(&ent("startup_folder", r"C:\Users\u\Startup\n.lnk", false)),
            ("HKCU", "startup_folder", "n.lnk".to_string())
        );
    }

    #[test]
    fn fail_closed() {
        let mut blocked = ent("service", "G", true);
        blocked.can_disable = false;
        blocked.note = Some("no".into());
        assert!(elevated_ops_for(&blocked, false, Some("manual")).is_err());
        let svc_e = ent("service", "S", true);
        for bad in [None, Some("bogus"), Some("auto")] {
            assert!(elevated_ops_for(&svc_e, false, bad).is_err(), "{bad:?}");
        }
        assert!(elevated_ops_for(&ent("packaged", r"p\t", false), false, None).is_err());
        for src in ["task", "service"] {
            assert!(restore(&ent(src, "S", true), &json!({}), "").is_err());
        }
    }

    #[test]
    fn service_ops_respect_mode() {
        let e = ent("service", "Tobii Service", true);
        assert_eq!(
            elevated_ops_for(&e, false, Some("manual")).unwrap(),
            vec![json!({"op": "set_service_start", "name": "Tobii Service", "start": "demand"})]
        );
        assert_eq!(elevated_ops_for(&e, false, Some("disabled")).unwrap()[0]["start"], "disabled");
        assert_eq!(elevated_ops_for(&e, true, None).unwrap()[0]["start"], "auto");
        assert_eq!(elevated_ops_for(&e, true, Some("manual")).unwrap()[0]["start"], "demand");
    }

    #[test]
    fn elevated_ops_task_and_hklm_run() {
        let t = ent("task", r"\Foo", true);
        assert_eq!(
            elevated_ops_for(&t, false, None).unwrap(),
            vec![json!({"op": "set_task", "name": r"\Foo", "enabled": false})]
        );
        let r = ent("run", r"HKLM\Foo", true);
        let ops = elevated_ops_for(&r, false, None).unwrap();
        assert!(ops[0]["op"] == "set_approved" && ops[0]["hive"] == "HKLM" && ops[0]["value"] == "Foo");
        let data = hex_decode(ops[0]["data_hex"].as_str().unwrap()).unwrap();
        assert!(!approved_is_enabled(Some(&data)));
    }

    #[test]
    fn parse_command_cases() {
        let cases = [
            (r#""C:\Program Files\Dummy\dummy.exe" --min"#, r"C:\Program Files\Dummy\dummy.exe"),
            (r"C:\x\y.exe -a", r"C:\x\y.exe"),
            (r"C:\Program Files\Some App\app.exe /s", r"C:\Program Files\Some App\app.exe"),
            (r#"rundll32.exe "C:\Foo\bar.dll",Start"#, r"C:\Foo\bar.dll"),
            (r#"cmd /c "C:\Foo\run.exe" x"#, r"C:\Foo\run.exe"),
        ];
        for (cmd, exe) in cases {
            assert_eq!(parse_command(cmd), exe, "{cmd}");
        }
    }

    #[test]
    fn parse_command_expands_env() {
        std::env::set_var("MWTEST_RS", r"C:\Zed");
        assert_eq!(parse_command(r"%MWTEST_RS%\z.exe"), r"C:\Zed\z.exe");
    }

    const CSV_HEAD: &str = "\"TaskName\",\"Schedule Type\",\"Task To Run\",\"Author\",\"Run As User\",\"Scheduled Task State\"\n";

    #[test]
    fn windows_system_logon_tasks_are_read_only() {
        let cfg = Config::default();
        let rows = format!(
            "{CSV_HEAD}{}\n{}\n",
            r#""\Microsoft\Windows\Shell\FamilySafety","At logon time","C:\Windows\x.exe","Microsoft","SYSTEM","Enabled""#,
            r#""\Tobii\Logon","At logon time","C:\Program Files\Tobii\t.exe","Tobii","SYSTEM","Enabled""#,
        );
        let tasks = task_entries_from_csv(&rows, &cfg);
        let (ms, tobii) = (&tasks[0], &tasks[1]);
        assert!(!ms.can_disable && ms.note.as_deref() == Some("Windows system task"));
        assert!(tobii.can_disable && tobii.note.is_none());
        assert!(elevated_ops_for(ms, false, None).is_err());
        // even a stale row that still says can_disable never reaches the runner
        let stale = ent("task", r"\Microsoft\Windows\X", true);
        assert!(elevated_ops_for(&stale, false, None).is_err());
    }

    #[test]
    fn live_inventory_smoke() {
        let inv = inventory(&Config::default(), "");
        assert!(inv.iter().any(|e| e.source == "service"));
        assert!(inv.iter().any(|e| e.source == "run"));
    }
}
