//! Raw processes -> apps the owner recognises.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{LazyLock, Mutex};

use regex::Regex;

use crate::config::Config;
use crate::models::{AppGroup, ProcInfo, ServiceInfo};

pub const PROTECTED_KEY: &str = "protected:windows";

fn re(p: &str) -> Regex {
    Regex::new(&format!("(?i){p}")).unwrap()
}

/// Most specific first: `\appdata\local\programs\<v>\` before `\appdata\local\<v>\`.
static PATH_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        re(r"\\program files \(x86\)\\([^\\]+)\\"),
        re(r"\\program files\\([^\\]+)\\"),
        re(r"\\appdata\\local\\programs\\([^\\]+)\\"),
        re(r"\\appdata\\local\\([^\\]+)\\"),
        re(r"\\appdata\\roaming\\([^\\]+)\\"),
    ]
});
static WINDOWSAPPS: LazyLock<Regex> = LazyLock::new(|| re(r"\\windowsapps\\([^\\_]+)_"));
static MS_NEXT: LazyLock<Regex> = LazyLock::new(|| re(r"\\microsoft\\([^\\]+)\\"));
static CORP_SUFFIX: LazyLock<Regex> = LazyLock::new(|| {
    re(r"[,\s]+(inc\.?|corporation|corp\.?|co\.,? ?ltd\.?|ltd\.?)$")
});

static COMPANY_CACHE: LazyLock<Mutex<HashMap<String, Option<String>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// CompanyName from the exe's version info (memoized), or None when unreadable.
pub fn company(path: &str) -> Option<String> {
    if let Some(v) = COMPANY_CACHE.lock().unwrap().get(path) {
        return v.clone();
    }
    let v = crate::probe::file_company(path);
    let mut cache = COMPANY_CACHE.lock().unwrap();
    if cache.len() >= 512 {
        cache.clear();
    }
    cache.insert(path.to_string(), v.clone());
    v
}

/// Map an exe path to (app_key, label, microsoft).
pub fn suite_from_path(path: Option<&str>, name: &str, cfg: &Config) -> (String, String, bool) {
    suite_from_path_with(path, name, cfg, &company)
}

pub fn suite_from_path_with(
    path: Option<&str>,
    name: &str,
    cfg: &Config,
    company: &dyn Fn(&str) -> Option<String>,
) -> (String, String, bool) {
    let stem = if name.to_lowercase().ends_with(".exe") { &name[..name.len() - 4] } else { name };
    let Some(path) = path.filter(|p| !p.is_empty()) else {
        return (format!("suite:{}", stem.to_lowercase()), stem.to_string(), false);
    };
    let low = path.to_lowercase();
    for (sub, label) in &cfg.suite_overrides {
        if low.contains(&sub.to_lowercase()) {
            let l = label.to_lowercase();
            return (format!("suite:{l}"), label.clone(), l.starts_with("microsoft"));
        }
    }
    if let Some(m) = WINDOWSAPPS.captures(path) {
        let label = m[1].to_string();
        let l = label.to_lowercase();
        return (format!("suite:{l}"), label, l.starts_with("microsoft"));
    }
    for pat in PATH_PATTERNS.iter() {
        let Some(c) = pat.captures(path) else { continue };
        let mut label = c[1].to_string();
        if label.to_lowercase() == "microsoft" {
            let start = c.get(0).unwrap().start();
            if let Some(n) = MS_NEXT.captures(&path[start..]) {
                let nxt = n[1].to_string();
                label = if nxt.to_lowercase().starts_with("microsoft") {
                    nxt
                } else {
                    format!("Microsoft {nxt}")
                };
            }
            return (format!("suite:{}", label.to_lowercase()), label, true);
        }
        let l = label.to_lowercase();
        let ms = l.starts_with("microsoft");
        return (format!("suite:{l}"), label, ms);
    }
    if low.contains("\\windows\\") {
        if let Some(co) = company(path) {
            if !co.to_lowercase().starts_with("microsoft") {
                let trimmed = co.trim();
                let stripped = CORP_SUFFIX.replace(trimmed, "").to_string();
                let label = if stripped.is_empty() { trimmed.to_string() } else { stripped };
                return (format!("suite:{}", label.to_lowercase()), label, false);
            }
        }
        return (format!("windows:{}", name.to_lowercase()), name.to_string(), true);
    }
    (format!("suite:{}", stem.to_lowercase()), stem.to_string(), false)
}

fn is_protected(p: &ProcInfo, services: &HashMap<u32, Vec<ServiceInfo>>, cfg: &Config) -> bool {
    let low = p.name.to_lowercase();
    if p.pid == 0 || p.pid == 4 || cfg.protected_names.contains(&low) {
        return true;
    }
    if low == "svchost.exe" {
        return services.get(&p.pid).is_some_and(|v| {
            v.iter().any(|s| cfg.protected_services.contains(&s.name.to_lowercase()))
        });
    }
    false
}

fn python_label(cmdline: &Option<Vec<String>>) -> String {
    let args: &[String] = cmdline.as_deref().map(|c| c.get(1..).unwrap_or(&[])).unwrap_or(&[]);
    for (i, a) in args.iter().enumerate() {
        if a == "-m" && i + 1 < args.len() {
            return format!("Python: -m {}", args[i + 1]);
        }
        if a.to_lowercase().ends_with(".py") {
            let norm = a.replace('/', "\\");
            return format!("Python: {}", norm.rsplit('\\').next().unwrap_or(&norm));
        }
    }
    "Python: interpreter".to_string()
}

/// (type, label) when this process is its own instance group.
fn instance(p: &ProcInfo) -> Option<(&'static str, String)> {
    let low = p.name.to_lowercase();
    if low == "claude.exe"
        && p.exe.as_deref().unwrap_or("").to_lowercase().contains("\\.local\\bin\\")
    {
        let started = format_local(p.create_time, "%b %d %H:%M");
        let mut label = format!("Claude Code session (started {started})");
        if let Some(cwd) = p.cwd.as_deref().filter(|c| !c.is_empty()) {
            label.push_str(&format!(" \u{2014} {cwd}"));
        }
        return Some(("claude-cli", label));
    }
    if low == "python.exe" || low == "pythonw.exe" {
        return Some(("python", python_label(&p.cmdline)));
    }
    if low.starts_with("qemu-system-") {
        let args = p.cmdline.as_deref().unwrap_or(&[]);
        if let Some(i) = args.iter().position(|a| a == "-avd") {
            if i + 1 < args.len() {
                return Some(("emulator", format!("Android emulator ({})", args[i + 1])));
            }
        }
        return Some(("emulator", "Android emulator".to_string()));
    }
    None
}

pub fn format_local(ts: f64, fmt: &str) -> String {
    use chrono::{Local, TimeZone};
    Local
        .timestamp_opt(ts as i64, 0)
        .single()
        .map(|d| d.format(fmt).to_string())
        .unwrap_or_default()
}

struct Grouper<'a> {
    by_pid: HashMap<u32, &'a ProcInfo>,
    shell: HashSet<String>,
    services: &'a HashMap<u32, Vec<ServiceInfo>>,
    cfg: &'a Config,
    groups: BTreeMap<String, AppGroup>,
    key_of: HashMap<u32, String>,
}

impl Grouper<'_> {
    fn ensure(&mut self, key: &str, label: &str, kind: &str, microsoft: bool, svc_names: &[String]) {
        let g = self.groups.entry(key.to_string()).or_insert_with(|| AppGroup {
            app_key: key.to_string(),
            label: label.to_string(),
            kind: kind.to_string(),
            pids: vec![],
            private_bytes: 0,
            working_set: 0,
            services: vec![],
            limited: false,
            microsoft,
        });
        for s in svc_names {
            if !g.services.contains(s) {
                g.services.push(s.clone());
            }
        }
    }

    fn resolve(&mut self, p: &ProcInfo, seen: &HashSet<u32>) -> String {
        if let Some(k) = self.key_of.get(&p.pid) {
            return k.clone();
        }
        let key;
        if is_protected(p, self.services, self.cfg) {
            self.ensure(PROTECTED_KEY, "Windows core", "protected", false, &[]);
            key = PROTECTED_KEY.to_string();
        } else if let Some((ty, label)) = instance(p) {
            key = format!("{ty}:{}:{}", p.pid, p.create_time as i64);
            self.ensure(&key, &label, "instance", false, &[]);
        } else if p.name.to_lowercase() == "svchost.exe"
            && self.services.get(&p.pid).is_some_and(|v| !v.is_empty())
        {
            let mut svcs: Vec<&ServiceInfo> = self.services[&p.pid].iter().collect();
            svcs.sort_by_key(|s| s.name.to_lowercase());
            key = format!(
                "service:{}",
                svcs.iter().map(|s| s.name.to_lowercase()).collect::<Vec<_>>().join("+")
            );
            let label = svcs.iter().map(|s| s.display_name.as_str()).collect::<Vec<_>>().join(", ");
            let names: Vec<String> = svcs.iter().map(|s| s.name.clone()).collect();
            self.ensure(&key, &label, "windows", true, &names);
        } else {
            let parent = self.by_pid.get(&p.ppid).copied().filter(|par| {
                par.pid != p.pid
                    && !seen.contains(&par.pid)
                    && par.create_time <= p.create_time
                    && !self.shell.contains(&par.name.to_lowercase())
                    && !is_protected(par, self.services, self.cfg)
            });
            if let Some(par) = parent {
                let mut s2 = seen.clone();
                s2.insert(p.pid);
                key = self.resolve(par, &s2);
            } else {
                let (k, label, ms) = suite_from_path(p.exe.as_deref(), &p.name, self.cfg);
                let kind = if k.starts_with("windows:") { "windows" } else { "suite" };
                let names: Vec<String> = self
                    .services
                    .get(&p.pid)
                    .map(|v| v.iter().map(|s| s.name.clone()).collect())
                    .unwrap_or_default();
                self.ensure(&k, &label, kind, ms, &names);
                key = k;
            }
        }
        self.key_of.insert(p.pid, key.clone());
        key
    }
}

pub fn group_processes(
    procs: &[ProcInfo],
    services: &HashMap<u32, Vec<ServiceInfo>>,
    cfg: &Config,
) -> BTreeMap<String, AppGroup> {
    let mut g = Grouper {
        by_pid: procs.iter().map(|p| (p.pid, p)).collect(),
        shell: cfg.shell_parent_names.iter().map(|s| s.to_lowercase()).collect(),
        services,
        cfg,
        groups: BTreeMap::new(),
        key_of: HashMap::new(),
    };
    for p in procs {
        let key = g.resolve(p, &HashSet::new());
        let grp = g.groups.get_mut(&key).unwrap();
        grp.pids.push((p.pid, p.create_time));
        grp.private_bytes += p.private_bytes;
        grp.working_set += p.working_set;
        grp.limited = grp.limited || p.limited;
    }
    g.groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{mkproc, svc};

    fn grp(procs: &[ProcInfo], services: HashMap<u32, Vec<ServiceInfo>>) -> BTreeMap<String, AppGroup> {
        group_processes(procs, &services, &Config::default())
    }

    const CHROME: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
    const CLAUDE: &str = r"C:\Users\u\.local\bin\claude.exe";

    #[test]
    fn chrome_children_one_suite() {
        let procs = [
            mkproc(1, 999, "explorer.exe", Some(r"C:\Windows\explorer.exe")),
            mkproc(10, 1, "chrome.exe", Some(CHROME)),
            mkproc(11, 10, "chrome.exe", Some(CHROME)),
        ];
        let g = grp(&procs, HashMap::new());
        assert_eq!(g["suite:google chrome"].pids, [(10, 1.0), (11, 1.0)]);
        assert_eq!(g["protected:windows"].kind, "protected");
    }

    #[test]
    fn each_claude_session_separate() {
        let procs = [
            mkproc(20, 5, "claude.exe", Some(CLAUDE)),
            mkproc(21, 5, "claude.exe", Some(CLAUDE)),
            mkproc(22, 20, "node.exe", None),
        ];
        let g = grp(&procs, HashMap::new());
        let keys: Vec<_> = g.keys().filter(|k| k.starts_with("claude-cli:")).cloned().collect();
        assert_eq!(keys, ["claude-cli:20:1", "claude-cli:21:1"]);
        assert!(g["claude-cli:20:1"].pids.contains(&(22, 1.0)));
    }

    #[test]
    fn claude_label_with_cwd() {
        let mut p = mkproc(20, 5, "claude.exe", Some(CLAUDE));
        p.cwd = Some(r"C:\proj".into());
        let g = grp(&[p], HashMap::new());
        let label = &g["claude-cli:20:1"].label;
        assert!(label.starts_with("Claude Code session (started ") && label.ends_with(") \u{2014} C:\\proj"));
    }

    #[test]
    fn python_and_emulator_labels() {
        let mut a = mkproc(30, 5, "python.exe", Some(r"C:\Py\python.exe"));
        a.cmdline = Some(vec!["python".into(), "train_lgbm.py".into()]);
        let mut b = mkproc(31, 5, "qemu-system-x86_64.exe", Some(r"C:\x\qemu-system-x86_64.exe"));
        b.cmdline = Some(vec!["q".into(), "-avd".into(), "Medium_Phone_API_36.1".into()]);
        let mut c = mkproc(32, 5, "python.exe", Some(r"C:\Py\python.exe"));
        c.cmdline = Some(vec!["python".into(), "-m".into(), "http.server".into()]);
        let mut d = mkproc(33, 5, "pythonw.exe", Some(r"C:\Py\pythonw.exe"));
        d.cmdline = Some(vec!["pythonw".into()]);
        let g = grp(&[a, b, c, d], HashMap::new());
        assert_eq!(g["python:30:1"].label, "Python: train_lgbm.py");
        assert_eq!(g["emulator:31:1"].label, "Android emulator (Medium_Phone_API_36.1)");
        assert_eq!(g["python:32:1"].label, "Python: -m http.server");
        assert_eq!(g["python:33:1"].label, "Python: interpreter");
    }

    #[test]
    fn vendor_service_joins_vendor_suite() {
        let procs = [
            mkproc(40, 3, "ss_conn_service.exe", Some(r"C:\Program Files (x86)\Samsung\USB Drivers\ss_conn_service.exe")),
            mkproc(41, 1, "SamsungApp.exe", Some(r"C:\Program Files\Samsung\App\SamsungApp.exe")),
        ];
        let g = grp(&procs, HashMap::from([(40, vec![svc("ss_conn_service")])]));
        let s = &g["suite:samsung"];
        let mut pids: Vec<_> = s.pids.iter().map(|p| p.0).collect();
        pids.sort();
        assert_eq!(pids, [40, 41]);
        assert_eq!(s.services, ["ss_conn_service"]);
    }

    #[test]
    fn svchost_core_protected_optional_not() {
        let sv = r"C:\Windows\System32\svchost.exe";
        let procs = [mkproc(50, 3, "svchost.exe", Some(sv)), mkproc(51, 3, "svchost.exe", Some(sv))];
        let g = grp(&procs, HashMap::from([(50, vec![svc("RpcSs")]), (51, vec![svc("WSearch")])]));
        assert!(g["protected:windows"].pids.contains(&(50, 1.0)));
        assert!(g["service:wsearch"].microsoft && g["service:wsearch"].kind == "windows");
    }

    #[test]
    fn svchost_multiple_services_sorted_key() {
        let procs = [mkproc(50, 3, "svchost.exe", Some(r"C:\Windows\System32\svchost.exe"))];
        let mut ws = svc("WSearch");
        ws.display_name = "Windows Search".into();
        let mut fax = svc("Fax");
        fax.display_name = "Fax".into();
        let g = grp(&procs, HashMap::from([(50, vec![ws, fax])]));
        assert_eq!(g["service:fax+wsearch"].services, ["Fax", "WSearch"]);
    }

    #[test]
    fn shell_children_do_not_inherit() {
        let procs = [
            mkproc(60, 1, "WindowsTerminal.exe", Some(r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.2_x64__8w\WindowsTerminal.exe")),
            mkproc(61, 60, "steam.exe", Some(r"C:\Program Files (x86)\Steam\steam.exe")),
        ];
        assert!(grp(&procs, HashMap::new()).contains_key("suite:steam"));
    }

    fn sfp(path: Option<&str>, name: &str) -> (String, String, bool) {
        suite_from_path_with(path, name, &Config::default(), &|_| None)
    }

    fn t(a: (String, String, bool)) -> (String, String, bool) {
        a
    }

    #[test]
    fn suite_from_path_rules() {
        let e = |k: &str, l: &str, m: bool| (k.to_string(), l.to_string(), m);
        assert_eq!(sfp(Some(r"C:\Users\u\AppData\Local\Programs\Foo\foo.exe"), "foo.exe"), e("suite:foo", "Foo", false));
        assert_eq!(sfp(Some(r"C:\Users\u\AppData\Local\Bar\bar.exe"), "bar.exe"), e("suite:bar", "Bar", false));
        assert_eq!(sfp(Some(r"C:\Users\u\AppData\Roaming\Baz\baz.exe"), "baz.exe"), e("suite:baz", "Baz", false));
        assert_eq!(sfp(Some(r"C:\Program Files\Microsoft OneDrive\OneDrive.exe"), "OneDrive.exe"), e("suite:microsoft onedrive", "Microsoft OneDrive", true));
        assert_eq!(sfp(Some(r"C:\Users\u\AppData\Local\Microsoft\OneDrive\OneDrive.exe"), "OneDrive.exe"), e("suite:microsoft onedrive", "Microsoft OneDrive", true));
        assert_eq!(sfp(Some(r"C:\Windows\System32\foo.exe"), "Foo.exe"), e("windows:foo.exe", "Foo.exe", true));
        assert_eq!(sfp(None, "Mystery.exe"), e("suite:mystery", "Mystery", false));
        assert_eq!(sfp(Some(r"C:\Program Files\WindowsApps\Microsoft.YourPhone_1.0_x64__8w\a.exe"), "a.exe"), e("suite:microsoft.yourphone", "Microsoft.YourPhone", true));
        let _ = t(sfp(None, "x"));
    }

    #[test]
    fn totals_and_limited() {
        let mut a = mkproc(10, 1, "chrome.exe", Some(CHROME));
        a.private_bytes = 100;
        a.working_set = 50;
        let mut b = mkproc(11, 10, "chrome.exe", None);
        b.private_bytes = 200;
        b.working_set = 70;
        b.limited = true;
        let g = grp(&[a, b], HashMap::new());
        let s = &g["suite:google chrome"];
        assert_eq!((s.private_bytes, s.working_set, s.limited), (300, 120, true));
    }

    #[test]
    fn protected_parent_is_inheritance_boundary() {
        let procs = [
            mkproc(70, 1, "SearchHost.exe", Some(r"C:\Windows\SystemApps\x\SearchHost.exe")),
            mkproc(71, 70, "foo.exe", Some(r"C:\Program Files\Foo\foo.exe")),
        ];
        let g = grp(&procs, HashMap::new());
        assert_eq!(g["suite:foo"].pids, [(71, 1.0)]);
        assert_eq!(g["protected:windows"].pids, [(70, 1.0)]);
    }

    #[test]
    fn windows_path_uses_company() {
        let exe = Some(r"C:\Windows\System32\DriverStore\x\svc.exe");
        let cfg = Config::default();
        let ms = suite_from_path_with(exe, "svc.exe", &cfg, &|_| Some("Microsoft Corporation".into()));
        assert_eq!(ms, ("windows:svc.exe".into(), "svc.exe".into(), true));
        let rt = suite_from_path_with(exe, "svc.exe", &cfg, &|_| Some("Realtek Semiconductor Corp.".into()));
        assert_eq!(rt, ("suite:realtek semiconductor".into(), "Realtek Semiconductor".into(), false));
        let none = suite_from_path_with(exe, "svc.exe", &cfg, &|_| None);
        assert!(none.2);
    }

    #[test]
    fn microsoft_override_flagged() {
        let mut cfg = Config::default();
        cfg.suite_overrides.push(("\\foo\\".into(), "Microsoft Foo".into()));
        let r = suite_from_path_with(Some(r"C:\x\foo\a.exe"), "a.exe", &cfg, &|_| None);
        assert!(r.2);
    }
}
