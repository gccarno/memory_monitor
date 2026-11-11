//! `install`, `uninstall` and `status`.
//!
//! Everything that touches the system goes through [`Sys`], so tests can swap the
//! process-killing, process-starting and shortcut-making parts for fakes.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};
use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
use winreg::RegKey;

use crate::config::Config;
use crate::db;
use crate::models::ProcInfo;

pub const RUN_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
pub const RUN_NAME: &str = "memwatch";
pub const SHORTCUT_NAME: &str = "Memory Report.lnk";
const EXES: [&str; 2] = ["memwatch.exe", "memwatchw.exe"];

/// How to get a startup change back by hand, per startup source.
fn undo_how(source: &str) -> &'static str {
    match source {
        "run" | "startup_folder" | "packaged" => "Task Manager > Startup apps",
        "task" => "Task Scheduler (enable the task)",
        "service" => "services.msc (set the startup type back to Automatic)",
        _ => "Task Manager or services.msc",
    }
}

type FindFn = dyn Fn() -> Vec<(u32, f64)>;
type StopFn = dyn Fn(&[(u32, f64)]);
type StartFn = dyn Fn(&Path) -> Result<(), String>;
type LinkFn = dyn Fn(&Path, &Path, &str, &Path) -> Result<(), String>;

pub struct Sys {
    /// (pid, create_time) of every running memwatch logger, either build.
    pub find_loggers: Box<FindFn>,
    /// End those processes and wait for them.
    pub stop: Box<StopFn>,
    /// Start `memwatchw.exe log` detached from this console.
    pub start_logger: Box<StartFn>,
    /// `(lnk, target, arguments, working_dir)`.
    pub make_shortcut: Box<LinkFn>,
}

impl Sys {
    pub fn real() -> Self {
        Sys {
            find_loggers: Box::new(|| {
                let me = std::process::id();
                loggers_in(&crate::probe::snapshot_processes(), me)
            }),
            stop: Box::new(stop_processes),
            start_logger: Box::new(start_logger_detached),
            make_shortcut: Box::new(make_shortcut),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Opts {
    /// HKCU subkey that stands in for the root (tests only).
    pub root: Option<String>,
    /// Folder for the shortcut instead of the real Desktop (tests only).
    pub desktop: Option<PathBuf>,
    /// Where the exes are installed instead of `%LOCALAPPDATA%\Programs\memwatch`.
    pub install_dir: Option<PathBuf>,
    /// The folder holding the exes to install (this exe's folder).
    pub src_dir: PathBuf,
    pub purge: bool,
    pub force: bool,
}

// ---------------------------------------------------------------- finding loggers

/// A `memwatch(w).exe log` or (during the migration) `python -m memwatch log` command line.
pub fn is_logger_cmdline(cmdline: &[String]) -> bool {
    let args: Vec<String> = cmdline.iter().map(|a| a.to_lowercase()).collect();
    if let Some(first) = args.first() {
        let file = first.rsplit(['\\', '/']).next().unwrap_or("");
        if matches!(file, "memwatch.exe" | "memwatchw.exe" | "memwatch" | "memwatchw") {
            return args.get(1).map(String::as_str) == Some("log");
        }
    }
    if !crate::selfid::is_memwatch_cmdline(cmdline) {
        return false;
    }
    for (i, a) in args.iter().enumerate() {
        if a == "-m" && args.get(i + 1).map(String::as_str) == Some("memwatch") {
            return args.get(i + 2).map(String::as_str) == Some("log");
        }
        if a == "-mmemwatch" {
            return args.get(i + 1).map(String::as_str) == Some("log");
        }
    }
    false
}

pub fn loggers_in(procs: &[ProcInfo], me: u32) -> Vec<(u32, f64)> {
    procs
        .iter()
        .filter(|p| p.pid != me && p.cmdline.as_deref().is_some_and(is_logger_cmdline))
        .map(|p| (p.pid, p.create_time))
        .collect()
}

fn stop_processes(items: &[(u32, f64)]) {
    for &(pid, ct) in items {
        if crate::winctl::find_live(pid, ct).is_some() {
            let _ = crate::winctl::terminate(pid);
        }
    }
    let _ = crate::winctl::wait_gone(items, Duration::from_secs(5));
}

#[allow(clippy::zombie_processes)] // detached on purpose: the logger outlives this command
fn start_logger_detached(exe: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    Command::new(exe)
        .arg("log")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW)
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- shell helpers

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn make_shortcut(lnk: &Path, target: &Path, args: &str, workdir: &Path) -> Result<(), String> {
    use windows::core::{Interface, PCWSTR};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, IPersistFile, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
    let e = |e: windows::core::Error| e.message();
    if let Some(parent) = lnk.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).map_err(e)?;
        let target_w = wide(&target.to_string_lossy());
        let args_w = wide(args);
        let wd_w = wide(&workdir.to_string_lossy());
        let desc_w = wide("memwatch memory report");
        link.SetPath(PCWSTR(target_w.as_ptr())).map_err(e)?;
        link.SetArguments(PCWSTR(args_w.as_ptr())).map_err(e)?;
        link.SetWorkingDirectory(PCWSTR(wd_w.as_ptr())).map_err(e)?;
        link.SetDescription(PCWSTR(desc_w.as_ptr())).map_err(e)?;
        let file: IPersistFile = link.cast().map_err(e)?;
        let lnk_w = wide(&lnk.to_string_lossy());
        file.Save(PCWSTR(lnk_w.as_ptr()), true).map_err(e)
    }
}

pub fn desktop_dir() -> Option<PathBuf> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_Desktop, SHGetKnownFolderPath, KF_FLAG_DEFAULT};
    unsafe {
        let p = SHGetKnownFolderPath(&FOLDERID_Desktop, KF_FLAG_DEFAULT, None).ok()?;
        let s = p.to_string().ok();
        CoTaskMemFree(Some(p.as_ptr() as *const _));
        s.map(PathBuf::from)
    }
}

fn run_key(root: &Option<String>) -> String {
    match root {
        Some(r) => format!(r"{r}\{RUN_SUBKEY}"),
        None => RUN_SUBKEY.to_string(),
    }
}

/// Where the exes live once installed: `%LOCALAPPDATA%\Programs\memwatch`.
pub fn default_install_dir(cfg: &Config) -> PathBuf {
    cfg.data_dir.parent().unwrap_or(Path::new(".")).join("Programs").join("memwatch")
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

// ---------------------------------------------------------------- install

pub fn install(cfg: &Config, o: &Opts, sys: &Sys, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if o.root.is_some() && o.desktop.is_none() {
        let _ = writeln!(err, "--root requires --desktop");
        return 2;
    }
    if o.root.is_some() && o.install_dir.is_none() {
        let _ = writeln!(err, "--root requires --install-dir");
        return 2;
    }
    let dir = o.install_dir.clone().unwrap_or_else(|| default_install_dir(cfg));
    for n in EXES {
        if !o.src_dir.join(n).is_file() {
            let _ = writeln!(err, "memwatch: cannot find {n} next to this program ({})", o.src_dir.display());
            return 1;
        }
    }
    // A running logger holds its exe open and would keep running the old build.
    let running = (sys.find_loggers)();
    if !running.is_empty() {
        (sys.stop)(&running);
    }
    if !same_dir(&o.src_dir, &dir) {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            let _ = writeln!(err, "memwatch: cannot create {}: {e}", dir.display());
            return 1;
        }
        for n in EXES {
            if let Err(e) = std::fs::copy(o.src_dir.join(n), dir.join(n)) {
                let _ = writeln!(err, "memwatch: cannot copy {n} to {}: {e}", dir.display());
                return 1;
            }
        }
    }
    let w = dir.join("memwatchw.exe");
    let set = RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey(run_key(&o.root))
        .and_then(|(k, _)| k.set_value(RUN_NAME, &format!("\"{}\" log", w.display())));
    if let Err(e) = set {
        let _ = writeln!(err, "memwatch: cannot write the startup entry: {e}");
        return 1;
    }
    let desktop = o.desktop.clone().or_else(desktop_dir);
    let made = match desktop {
        Some(d) => (sys.make_shortcut)(&d.join(SHORTCUT_NAME), &w, "report", &dir),
        None => Err("cannot find the Desktop folder".to_string()),
    };
    if let Err(e) = made {
        let _ = writeln!(err, "memwatch: startup entry was written but the desktop shortcut failed: {e}");
        let _ = writeln!(err, "Run `memwatch uninstall` to undo, or create the shortcut by hand.");
        return 1;
    }
    if let Err(e) = (sys.start_logger)(&w) {
        let _ = writeln!(err, "memwatch: installed, but the logger did not start ({e}); it will start at next login.");
        return 1;
    }
    let _ = writeln!(out, "memwatch installed: logger starts at login; shortcut 'Memory Report' created.");
    0
}

// ---------------------------------------------------------------- uninstall

/// memwatch startup changes that were never undone (a purge would lose their record).
fn outstanding_changes(data_dir: &Path) -> Vec<crate::models::ActionRecord> {
    let path = data_dir.join("memwatch.db");
    if !path.is_file() {
        return vec![];
    }
    let Ok(conn) = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY) else {
        return vec![];
    };
    db::list_actions(&conn, false).unwrap_or_default()
}

pub fn uninstall(cfg: &Config, o: &Opts, sys: &Sys, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if o.root.is_some() && o.desktop.is_none() {
        let _ = writeln!(err, "--root requires --desktop");
        return 2;
    }
    if o.purge && !o.force {
        let pending = outstanding_changes(&cfg.data_dir);
        if !pending.is_empty() {
            let _ = writeln!(
                err,
                "memwatch: {} startup change(s) made by memwatch are still in effect, and purging \
                 deletes the record needed to undo them:",
                pending.len()
            );
            for rec in &pending {
                let src = rec.entry.get("source").and_then(|v| v.as_str()).unwrap_or("");
                let name = rec.entry.get("name").and_then(|v| v.as_str()).unwrap_or(&rec.app_key);
                let _ = writeln!(err, "  - {name} ({src}): re-enable in {}", undo_how(src));
            }
            let _ = writeln!(
                err,
                "Undo them in the report's Undo section (or by hand as above), then run this again; \
                 or pass --force to purge anyway. Nothing was removed."
            );
            return 1;
        }
    }
    if let Ok(k) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(run_key(&o.root), KEY_SET_VALUE) {
        let _ = k.delete_value(RUN_NAME); // absent is fine
    }
    if let Some(d) = o.desktop.clone().or_else(desktop_dir) {
        let _ = std::fs::remove_file(d.join(SHORTCUT_NAME));
    }
    let running = (sys.find_loggers)();
    if !running.is_empty() {
        (sys.stop)(&running);
    }
    if o.purge {
        let _ = std::fs::remove_dir_all(&cfg.data_dir);
        let left = files_under(&cfg.data_dir);
        if !left.is_empty() {
            let _ = writeln!(err, "memwatch: could not delete these files: {}", left.join(" | "));
            return 1;
        }
        // The installed exes too, best effort (the one running this command stays).
        let dir = o.install_dir.clone().or_else(|| o.root.is_none().then(|| default_install_dir(cfg)));
        if let Some(d) = dir {
            let _ = std::fs::remove_dir_all(d);
        }
    }
    let _ = writeln!(out, "memwatch uninstalled.");
    0
}

fn files_under(dir: &Path) -> Vec<String> {
    let mut out = vec![];
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p.display().to_string());
            }
        }
    }
    out
}

// ---------------------------------------------------------------- status

pub fn status(cfg: &Config, sys: &Sys, out: &mut dyn Write) -> i32 {
    let path = cfg.data_dir.join("memwatch.db");
    let running = !(sys.find_loggers)().is_empty();
    let _ = writeln!(out, "logger running: {}", if running { "yes" } else { "no" });
    if !path.is_file() {
        let _ = writeln!(out, "db size: 0.0 MB");
        let _ = writeln!(out, "observed: 0.0 hours");
        let _ = writeln!(out, "logger memory: unknown");
        return 0;
    }
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let _ = writeln!(out, "db size: {:.1} MB", size as f64 / 1_048_576.0);
    let (mut hours, mut ws) = (0.0, None);
    if let Ok(conn) = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        if let Ok(ticks) = db::system_ticks_since(&conn, 0) {
            hours = ticks.len() as f64 * cfg.sample_interval_s as f64 / 3600.0;
        }
        ws = db::latest_system(&conn).ok().flatten().and_then(|s| s.logger_ws);
    }
    let _ = writeln!(out, "observed: {hours:.1} hours");
    match ws {
        None => {
            let _ = writeln!(out, "logger memory: unknown");
        }
        Some(w) => {
            let _ = writeln!(out, "logger memory: {:.0} MB (cap {} MB)", w as f64 / 1_048_576.0, cfg.logger_cap_mb);
        }
    }
    0
}

#[cfg(test)]
#[path = "install_tests.rs"]
mod tests;
