use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn default_data_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_default();
    base.join("memwatch")
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn protected_names() -> BTreeSet<String> {
    set(&[
        "system", "idle", "registry", "smss.exe", "csrss.exe", "wininit.exe",
        "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "dwm.exe",
        "explorer.exe", "fontdrvhost.exe", "memory compression", "secure system",
        "sihost.exe", "ctfmon.exe", "audiodg.exe", "msmpeng.exe", "nissrv.exe",
        "mpdefendercoreservice.exe", "securityhealthservice.exe",
        "securityhealthsystray.exe", "taskhostw.exe", "runtimebroker.exe",
        "startmenuexperiencehost.exe", "shellexperiencehost.exe", "searchhost.exe",
        "textinputhost.exe", "lockapp.exe", "wudfhost.exe",
    ])
}

fn protected_services() -> BTreeSet<String> {
    set(&[
        "rpcss", "dcomlaunch", "rpceptmapper", "lsm", "brokerinfrastructure",
        "power", "plugplay", "eventlog", "schedule", "profsvc", "usermanager",
        "coremessagingregistrar", "systemeventsbroker", "dhcp", "dnscache", "nsi",
        "nlasvc", "netprofm", "winmgmt", "cryptsvc", "audiosrv",
        "audioendpointbuilder", "themes", "gpsvc", "windefend", "mdcoresvc",
        "wdnissvc", "securityhealthservice", "mpssvc", "bfe", "wscsvc",
        "staterepository", "timebrokersvc", "camsvc", "dispbrokerdesktopsvc",
        "appinfo", "tokenbroker", "samss", "keyiso", "vaultsvc", "wlansvc",
        "wcmsvc", "lanmanworkstation", "sens", "fontcache", "shellhwdetection",
        "cdpusersvc", "wpnservice", "wpnusersvc", "tabletinputservice",
        "textinputmanagementservice", "appxsvc", "clipsvc", "msiserver",
        "trustedinstaller",
    ])
}

fn terminal_names() -> BTreeSet<String> {
    set(&[
        "windowsterminal.exe", "mintty.exe", "openconsole.exe", "conhost.exe",
        "wezterm-gui.exe", "alacritty.exe",
    ])
}

/// Children of these do not inherit their parent's group.
fn shell_parent_names() -> BTreeSet<String> {
    set(&[
        "explorer.exe", "services.exe", "svchost.exe", "wininit.exe",
        "userinit.exe", "windowsterminal.exe", "mintty.exe", "openconsole.exe",
        "conhost.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe",
        "taskhostw.exe", "sihost.exe",
    ])
}

/// Order matters: the first matching fragment wins.
fn suite_overrides() -> Vec<(String, String)> {
    pairs(&[
        ("\\google\\chrome\\", "Google Chrome"),
        ("\\mozilla firefox\\", "Firefox"),
        ("\\citrix\\", "Citrix"),
        ("\\zoom\\", "Zoom"),
        ("\\steam\\", "Steam"),
        ("\\discord\\", "Discord"),
        ("\\nvidia corporation\\", "NVIDIA"),
        ("\\lenovo\\", "Lenovo Vantage"),
        ("\\samsung\\", "Samsung"),
        ("\\tobii\\", "Tobii"),
        ("\\reasonlabs\\", "Reason Security"),
        ("\\android\\sdk\\", "Android SDK"),
        ("\\adobe\\", "Adobe"),
        ("\\displaylink\\", "DisplayLink"),
        ("\\tobiiab.", "Tobii"),
        ("\\google\\drive", "Google Drive"),
        ("\\driverstore\\filerepository\\lenovo", "Lenovo Vantage"),
        ("\\driverstore\\filerepository\\nv_", "NVIDIA"),
        ("\\driverstore\\filerepository\\nvlt.", "NVIDIA"),
        ("\\elevocinstalldriver\\", "Elevoc"),
        ("\\common files\\microsoft shared\\", "Microsoft Office"),
    ])
}

fn categories() -> Vec<(String, Vec<String>)> {
    let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    vec![
        ("antivirus".to_string(), v(&["Reason Security", "Windows Defender"])),
        ("browser".to_string(), v(&["Google Chrome", "Firefox", "Microsoft Edge"])),
    ]
}

fn notes() -> BTreeMap<String, String> {
    pairs(&[
        ("service:wsearch", "Windows Search indexing: Start-menu and File Explorer search get slower without it."),
        ("service:sysmain", "SysMain preloads apps you use often; turning it off frees memory but apps may open a bit slower."),
        ("service:diagtrack", "Telemetry sent to Microsoft; safe to turn off."),
        ("suite:microsoft.yourphone", "Phone Link: you lose phone notifications and texts on the PC."),
        ("suite:microsoftwindows.client.webexperience", "Widgets board: the taskbar widgets stop working."),
        ("service:wslservice", "WSL: Linux distros and Docker Desktop need this."),
        ("service:edgeupdate", "Edge updater: Edge will update less promptly."),
        ("suite:microsoft onedrive", "OneDrive: files stop syncing until it is started again."),
    ])
    .into_iter()
    .collect()
}

/// Products that are protected (no app row of their own) but still count for the
/// duplicate-category reason: lower-case process name -> product label.
fn process_markers() -> BTreeMap<String, String> {
    pairs(&[("msmpeng.exe", "Windows Defender")]).into_iter().collect()
}

#[derive(Debug, Clone)]
pub struct Config {
    pub sample_interval_s: i64,
    pub retention_days: i64,
    pub idle_days: f64,
    pub large_mb: i64,
    pub long_running_days: f64,
    pub rare_max_days_used: i64,
    pub rare_min_observed_days: i64,
    /// CPU seconds per tick.
    pub cpu_active_s: f64,
    /// I/O bytes per tick.
    pub io_active_bytes: i64,
    pub user_away_s: i64,
    pub close_timeout_s: i64,
    pub logger_cap_mb: i64,
    pub nonpaged_warn_mb: i64,
    pub partial_hours: i64,
    pub heartbeat_timeout_s: i64,
    pub server_idle_timeout_s: i64,
    pub data_dir: PathBuf,
    pub protected_names: BTreeSet<String>,
    pub protected_services: BTreeSet<String>,
    pub terminal_names: BTreeSet<String>,
    pub shell_parent_names: BTreeSet<String>,
    pub suite_overrides: Vec<(String, String)>,
    pub categories: Vec<(String, Vec<String>)>,
    pub notes: BTreeMap<String, String>,
    pub process_markers: BTreeMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            sample_interval_s: 60,
            retention_days: 30,
            idle_days: 2.0,
            large_mb: 500,
            long_running_days: 2.0,
            rare_max_days_used: 2,
            rare_min_observed_days: 3,
            cpu_active_s: 0.5,
            io_active_bytes: 1_048_576,
            user_away_s: 300,
            close_timeout_s: 10,
            logger_cap_mb: 50,
            nonpaged_warn_mb: 500,
            partial_hours: 72,
            heartbeat_timeout_s: 180,
            server_idle_timeout_s: 1800,
            data_dir: default_data_dir(),
            protected_names: protected_names(),
            protected_services: protected_services(),
            terminal_names: terminal_names(),
            shell_parent_names: shell_parent_names(),
            suite_overrides: suite_overrides(),
            categories: categories(),
            notes: notes(),
            process_markers: process_markers(),
        }
    }
}

fn as_f64(v: &toml::Value) -> Option<f64> {
    match v {
        toml::Value::Float(f) => Some(*f),
        toml::Value::Integer(i) => Some(*i as f64),
        _ => None,
    }
}

fn as_i64(v: &toml::Value) -> Option<i64> {
    match v {
        toml::Value::Integer(i) => Some(*i),
        toml::Value::Float(f) if f.fract() == 0.0 => Some(*f as i64),
        _ => None,
    }
}

fn str_list(v: &toml::Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

fn extend_set(target: &mut BTreeSet<String>, v: &toml::Value) {
    target.extend(str_list(v).into_iter().map(|s| s.to_lowercase()));
}

fn extend_string_map(v: &toml::Value) -> Vec<(String, String)> {
    v.as_table()
        .map(|t| {
            t.iter()
                .filter_map(|(k, x)| x.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// Insert or replace by key, keeping first-seen order.
fn upsert(list: &mut Vec<(String, String)>, k: String, v: String) {
    match list.iter_mut().find(|(ek, _)| *ek == k) {
        Some(e) => e.1 = v,
        None => list.push((k, v)),
    }
}

/// Load config; scalars override defaults, sets/lists/dicts extend them.
/// A missing or unparsable file yields the defaults.
pub fn load_config(path: Option<&Path>) -> Config {
    let mut cfg = Config::default();
    let default_path = cfg.data_dir.join("config.toml");
    let path = path.unwrap_or(&default_path);
    let Ok(text) = std::fs::read_to_string(path) else {
        return cfg;
    };
    let Ok(table) = text.parse::<toml::Table>() else {
        return cfg;
    };
    for (key, val) in &table {
        match key.as_str() {
            "sample_interval_s" => set_i(&mut cfg.sample_interval_s, val),
            "retention_days" => set_i(&mut cfg.retention_days, val),
            "idle_days" => set_f(&mut cfg.idle_days, val),
            "large_mb" => set_i(&mut cfg.large_mb, val),
            "long_running_days" => set_f(&mut cfg.long_running_days, val),
            "rare_max_days_used" => set_i(&mut cfg.rare_max_days_used, val),
            "rare_min_observed_days" => set_i(&mut cfg.rare_min_observed_days, val),
            "cpu_active_s" => set_f(&mut cfg.cpu_active_s, val),
            "io_active_bytes" => set_i(&mut cfg.io_active_bytes, val),
            "user_away_s" => set_i(&mut cfg.user_away_s, val),
            "close_timeout_s" => set_i(&mut cfg.close_timeout_s, val),
            "logger_cap_mb" => set_i(&mut cfg.logger_cap_mb, val),
            "nonpaged_warn_mb" => set_i(&mut cfg.nonpaged_warn_mb, val),
            "partial_hours" => set_i(&mut cfg.partial_hours, val),
            "heartbeat_timeout_s" => set_i(&mut cfg.heartbeat_timeout_s, val),
            "server_idle_timeout_s" => set_i(&mut cfg.server_idle_timeout_s, val),
            "data_dir" => {
                if let Some(s) = val.as_str() {
                    cfg.data_dir = PathBuf::from(s);
                }
            }
            "protected_names" => extend_set(&mut cfg.protected_names, val),
            "protected_services" => extend_set(&mut cfg.protected_services, val),
            "terminal_names" => extend_set(&mut cfg.terminal_names, val),
            "shell_parent_names" => extend_set(&mut cfg.shell_parent_names, val),
            "suite_overrides" => {
                for (k, v) in extend_string_map(val) {
                    upsert(&mut cfg.suite_overrides, k, v);
                }
            }
            "notes" => cfg.notes.extend(extend_string_map(val)),
            "process_markers" => cfg.process_markers.extend(extend_string_map(val)),
            "categories" => {
                if let Some(t) = val.as_table() {
                    for (k, v) in t {
                        let add = str_list(v);
                        match cfg.categories.iter_mut().find(|(ek, _)| ek == k) {
                            Some((_, list)) => {
                                for item in add {
                                    if !list.contains(&item) {
                                        list.push(item);
                                    }
                                }
                            }
                            None => {
                                let mut dedup: Vec<String> = Vec::new();
                                for item in add {
                                    if !dedup.contains(&item) {
                                        dedup.push(item);
                                    }
                                }
                                cfg.categories.push((k.clone(), dedup));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    cfg
}

fn set_i(slot: &mut i64, v: &toml::Value) {
    if let Some(x) = as_i64(v) {
        *slot = x;
    }
}

fn set_f(slot: &mut f64, v: &toml::Value) {
    if let Some(x) = as_f64(v) {
        *slot = x;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn defaults() {
        let c = load_config(Some(Path::new("nonexistent.toml")));
        assert!(c.sample_interval_s == 60 && c.retention_days == 30 && c.logger_cap_mb == 50);
        assert!(c.protected_names.contains("csrss.exe") && c.protected_names.contains("msmpeng.exe"));
        assert!(!c.protected_names.contains("spoolsv.exe"));
        let la = std::env::var("LOCALAPPDATA").unwrap();
        assert_eq!(c.data_dir, Path::new(&la).join("memwatch"));
    }

    #[test]
    fn toml_overrides_scalars_and_extends_sets() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.toml");
        std::fs::write(
            &p,
            "idle_days = 5\nprotected_names = [\"MyAgent.exe\"]\n[notes]\n\"suite:foo\" = \"Foo note\"\n",
        )
        .unwrap();
        let c = load_config(Some(&p));
        assert_eq!(c.idle_days, 5.0);
        assert!(c.protected_names.contains("myagent.exe") && c.protected_names.contains("csrss.exe"));
        assert_eq!(c.notes["suite:foo"], "Foo note");
        assert!(c.notes.contains_key("service:wsearch"));
    }

    #[test]
    fn categories_and_suites_extend_in_order() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.toml");
        std::fs::write(
            &p,
            "[categories]\nbrowser = [\"Brave\", \"Firefox\"]\nvpn = [\"A\"]\n[suite_overrides]\n\"\\\\brave\\\\\" = \"Brave\"\n\"\\\\steam\\\\\" = \"Steam2\"\n",
        )
        .unwrap();
        let c = load_config(Some(&p));
        let browser = &c.categories.iter().find(|(k, _)| k == "browser").unwrap().1;
        assert_eq!(browser, &["Google Chrome", "Firefox", "Microsoft Edge", "Brave"]);
        assert!(c.categories.iter().any(|(k, _)| k == "vpn"));
        let steam = c.suite_overrides.iter().find(|(k, _)| k == "\\steam\\").unwrap();
        assert_eq!(steam.1, "Steam2");
        assert_eq!(c.suite_overrides.last().unwrap().0, "\\brave\\");
    }
}
