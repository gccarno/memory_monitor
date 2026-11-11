//! Stop, force-kill, disable-at-startup and undo. Every action re-verifies what it is about
//! to touch; admin-only work goes through one elevator call.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::config::Config;
use crate::db::{get_action, mark_undone, record_action, set_startup_enabled};
use crate::elevate::{run_elevated, Elevation, Elevator, OpResult};
use crate::models::{ActionRecord, ActionResult, AppGroup, ProcInfo, ServiceInfo, StartupEntry};
use crate::selfid::{is_memwatch_proc, own_pids_in};
use crate::server::Actions;
use crate::winctl::{self, Term};
use crate::{probe, startup};

const CT_TOLERANCE: f64 = 1e-3;
pub const STILL_OPEN: &str = "Still open; it may be waiting for you (unsaved work?)";
pub const PROTECTED_MSG: &str = "Windows core processes are never stopped";
pub const SELF_MSG: &str = "memwatch will not stop itself";
pub const DECLINED: &str = "Administrator approval was declined; nothing that needs it was changed";
const FORCE_GRACE: Duration = Duration::from_secs(3);
const EXIT_WAIT: Duration = Duration::from_secs(5);
const LOCAL_SOURCES: [&str; 3] = ["run", "startup_folder", "packaged"];

type Pid = (u32, f64);

type ByName<R> = Box<dyn Fn(&str) -> R + Send + Sync>;
type ByEntry = Box<dyn Fn(&StartupEntry) -> Option<String> + Send + Sync>;
type ByPid = Box<dyn Fn() -> HashMap<u32, Vec<ServiceInfo>> + Send + Sync>;

/// The system lookups the actions make. Tests replace them; `Default` is the real thing.
pub struct Hooks {
    pub service_running: ByName<bool>,
    pub dependents: ByName<Vec<String>>,
    pub service_start: ByName<Option<String>>,
    pub hklm_approved: ByEntry,
    pub services_by_pid: ByPid,
    pub terminate: Box<dyn Fn(u32) -> Term + Send + Sync>,
}

impl Default for Hooks {
    fn default() -> Self {
        Hooks {
            // cannot tell (None): try to stop it
            service_running: Box::new(|n| probe::service_is_running(n).unwrap_or(true)),
            dependents: Box::new(crate::suggest::default_dependents),
            service_start: Box::new(probe::service_start_mode),
            hklm_approved: Box::new(|e| {
                let (hive, kind, name) = startup::approved_target(e);
                startup::read_approved(hive, kind, &name, "").map(startup::hex_encode)
            }),
            services_by_pid: Box::new(probe::services_by_pid),
            terminate: Box::new(winctl::terminate),
        }
    }
}

pub struct RealActions {
    /// None: ask Windows for administrator rights through the elevated runner.
    pub elevator: Option<Elevator>,
    pub hooks: Hooks,
    /// Registry root prefix for tests ("" in production).
    pub root: String,
    /// Startup changes and undos run one at a time, so a double click sees the first click's
    /// result (live state) instead of recording a second, already-off "before".
    startup_lock: Mutex<()>,
}

impl RealActions {
    pub fn new() -> Self {
        RealActions { elevator: None, hooks: Hooks::default(), root: String::new(), startup_lock: Mutex::new(()) }
    }

    pub fn with_elevator(elevator: Elevator) -> Self {
        RealActions { elevator: Some(elevator), ..Self::new() }
    }
}

impl Default for RealActions {
    fn default() -> Self {
        Self::new()
    }
}

fn result(status: &str, message: impl Into<String>, remaining: Vec<u32>) -> ActionResult {
    ActionResult { status: status.into(), message: message.into(), remaining_pids: remaining }
}

/// Space-joined notes without repeats, in first-seen order.
fn join(notes: &[String]) -> String {
    let mut seen = HashSet::new();
    notes.iter().filter(|n| seen.insert(n.as_str())).cloned().collect::<Vec<_>>().join(" ")
}

enum Called {
    Declined,
    Results(Vec<OpResult>),
}

fn same_proc(p: &ProcInfo, k: Pid) -> bool {
    p.pid == k.0 && (p.create_time - k.1).abs() <= CT_TOLERANCE
}

fn key(p: &ProcInfo) -> Pid {
    (p.pid, p.create_time)
}

/// Pids (sorted, unique) among the given groups that are still running.
fn remaining(groups: &[&[ProcInfo]]) -> Vec<u32> {
    let snap = probe::snapshot_processes();
    let set: BTreeSet<u32> = groups
        .iter()
        .flat_map(|g| g.iter())
        .filter(|p| snap.iter().any(|s| same_proc(s, key(p))))
        .map(|p| p.pid)
        .collect();
    set.into_iter().collect()
}

fn alive(p: &ProcInfo) -> bool {
    winctl::find_live(p.pid, p.create_time).is_some()
}

fn wait(procs: &[&ProcInfo], timeout: Duration) {
    let keys: Vec<Pid> = procs.iter().map(|p| key(p)).collect();
    winctl::wait_gone(&keys, timeout);
}

fn kill_op(p: &ProcInfo) -> Value {
    json!({"op": "kill", "pid": p.pid, "create_time": p.create_time})
}

struct Guard {
    live: Vec<ProcInfo>,
    usable: Vec<ProcInfo>,
    left: Vec<ProcInfo>,
    notes: Vec<String>,
}

impl RealActions {
    fn call(&self, ops: &[Value], cfg: &Config) -> Called {
        let res = match &self.elevator {
            Some(e) => e(ops),
            None => run_elevated(ops, cfg),
        };
        match res {
            Elevation::Declined => Called::Declined,
            Elevation::Results(r) if r.len() == ops.len() => Called::Results(
                r.into_iter()
                    .map(|x| {
                        if x.ok {
                            OpResult { ok: true, error: None }
                        } else {
                            OpResult { ok: false, error: Some(x.error.filter(|e| !e.is_empty()).unwrap_or_else(|| "failed".into())) }
                        }
                    })
                    .collect(),
            ),
            Elevation::Results(_) => Called::Results(
                ops.iter().map(|_| OpResult { ok: false, error: Some("no result".into()) }).collect(),
            ),
        }
    }

    /// Why this process must never be stopped directly, or None. `svchost_ok` lets stop_now
    /// see service hosts; it stops their services and never terminates them.
    fn untouchable(&self, p: &ProcInfo, cfg: &Config, guarded: &HashSet<u32>, svchost_ok: bool) -> Option<String> {
        if guarded.contains(&p.pid) || is_memwatch_proc(p) {
            return Some(SELF_MSG.into());
        }
        if p.pid == 0 || p.pid == 4 {
            return Some(PROTECTED_MSG.into());
        }
        let low = p.name.to_lowercase();
        if cfg.protected_names.contains(&low) {
            return Some(format!("{} is a Windows core process and is never stopped.", p.name));
        }
        if low == "svchost.exe" && !svchost_ok {
            return Some(format!("{} (pid {}) hosts Windows services and is not terminated directly.", p.name, p.pid));
        }
        None
    }

    fn guard_group(&self, group: &AppGroup, cfg: &Config, svchost_ok: bool) -> Result<Guard, ActionResult> {
        if group.kind == "protected" {
            return Err(result("failed", PROTECTED_MSG, vec![]));
        }
        let snap = probe::snapshot_processes();
        let live: Vec<ProcInfo> =
            group.pids.iter().filter_map(|&k| snap.iter().find(|p| same_proc(p, k)).cloned()).collect();
        let guarded = own_pids_in(&snap, std::process::id());
        let (mut usable, mut left, mut notes) = (vec![], vec![], vec![]);
        for p in &live {
            match self.untouchable(p, cfg, &guarded, svchost_ok) {
                Some(why) => {
                    left.push(p.clone());
                    notes.push(why);
                }
                None => usable.push(p.clone()),
            }
        }
        if !live.is_empty() && usable.is_empty() && notes.iter().all(|n| n == SELF_MSG) {
            return Err(result("failed", SELF_MSG, remaining(&[&left])));
        }
        Ok(Guard { live, usable, left, notes })
    }

    /// `targets` were acted on; `left` are group processes deliberately left alone.
    fn finish(
        label: &str,
        targets: &[ProcInfo],
        left: &[ProcInfo],
        notes: &[String],
        any_change: bool,
        incomplete: bool,
    ) -> ActionResult {
        let rem = remaining(&[targets, left]);
        let extra = if notes.is_empty() { String::new() } else { format!(" {}", join(notes)) };
        if rem.is_empty() && !incomplete {
            return result("done", format!("Stopped {label}.{extra}"), vec![]);
        }
        if any_change || targets.iter().any(|p| !alive(p)) {
            return result("partial", format!("Stopped part of {label}.{extra}"), rem);
        }
        result("failed", format!("Could not stop {label}.{extra}"), rem)
    }

    /// Elevation was declined: 'partial' when unelevated work already took effect.
    fn declined(label: &str, changed: bool, notes: &[String], groups: &[&[ProcInfo]]) -> ActionResult {
        let rem = remaining(groups);
        if changed {
            let msg = format!("Stopped part of {label}. {DECLINED}. {}", join(notes));
            return result("partial", msg.trim().to_string(), rem);
        }
        result("declined", DECLINED, rem)
    }

    fn terminate_all(&self, procs: &[ProcInfo]) -> Vec<ProcInfo> {
        let mut denied = vec![];
        for p in procs {
            match (self.hooks.terminate)(p.pid) {
                Term::Done | Term::Gone => {}
                Term::Denied | Term::Failed(_) => denied.push(p.clone()),
            }
        }
        denied
    }

    pub fn do_stop_now(&self, group: &AppGroup, cfg: &Config) -> ActionResult {
        let Guard { live, usable: mut procs, mut left, mut notes } = match self.guard_group(group, cfg, true) {
            Ok(g) => g,
            Err(r) => return r,
        };
        let hosts = (self.hooks.services_by_pid)();
        let group_svcs: HashSet<String> = group.services.iter().map(|s| s.to_lowercase()).collect();
        let mut svc_hosts: Vec<ProcInfo> = vec![]; // exit once their services stop
        for p in procs.clone() {
            let hosted: HashSet<String> =
                hosts.get(&p.pid).into_iter().flatten().map(|s| s.name.to_lowercase()).collect();
            if !hosted.is_empty() {
                procs.retain(|x| x.pid != p.pid);
                if hosted.is_subset(&group_svcs) {
                    svc_hosts.push(p);
                } else {
                    notes.push(format!("pid {} also runs other services and was left alone.", p.pid));
                    left.push(p);
                }
            } else if p.name.to_lowercase() == "svchost.exe" {
                procs.retain(|x| x.pid != p.pid);
                notes.push(format!("svchost.exe (pid {}) runs no service of this app and was left alone.", p.pid));
                left.push(p);
            }
        }
        let running: Vec<&String> = group.services.iter().filter(|s| (self.hooks.service_running)(s)).collect();
        if live.is_empty() && running.is_empty() {
            return result("already_stopped", format!("{} is not running.", group.label), vec![]);
        }
        if procs.is_empty() && svc_hosts.is_empty() && running.is_empty() {
            return result("failed", join(&notes), remaining(&[&left]));
        }

        // Windowed processes: WM_CLOSE only, then wait. Nothing else is touched until every
        // window has gone.
        let windows = winctl::windows_by_pid();
        let (windowed, mut windowless): (Vec<ProcInfo>, Vec<ProcInfo>) =
            procs.iter().cloned().partition(|p| windows.get(&p.pid).is_some_and(|w| !w.is_empty()));
        if !windowed.is_empty() {
            for p in &windowed {
                winctl::post_close(&windows[&p.pid]);
            }
            let keys: Vec<Pid> = windowed.iter().map(key).collect();
            if !winctl::wait_gone(&keys, Duration::from_secs(cfg.close_timeout_s.max(0) as u64)).is_empty() {
                let all: Vec<ProcInfo> = procs.iter().chain(&svc_hosts).cloned().collect();
                return result("still_open", STILL_OPEN, remaining(&[&all]));
            }
            // helpers often exit with their window
            wait(&windowless.iter().collect::<Vec<_>>(), Duration::from_secs(1));
            windowless.retain(alive);
        }

        // Windowless processes: terminate; access-denied ones go to the elevator.
        let mut ops: Vec<Value> = self.terminate_all(&windowless).iter().map(kill_op).collect();

        // Services: only those without running dependents.
        let mut skipped = false;
        for name in &running {
            if cfg.protected_services.contains(&name.to_lowercase()) {
                notes.push(format!("{name} is a Windows core service and was not stopped."));
                skipped = true;
                continue;
            }
            let deps = (self.hooks.dependents)(name);
            if !deps.is_empty() {
                notes.push(format!(
                    "{name} was not stopped: other running services depend on it ({}).",
                    deps.join(", ")
                ));
                skipped = true;
                continue;
            }
            ops.push(json!({"op": "stop_service", "name": name}));
        }

        let (mut failed_ops, mut stopped_svc) = (false, false);
        if !ops.is_empty() {
            match self.call(&ops, cfg) {
                Called::Declined => {
                    let changed = !windowed.is_empty() || windowless.iter().any(|p| !alive(p));
                    return Self::declined(&group.label, changed, &notes, &[&procs, &svc_hosts, &left]);
                }
                Called::Results(res) => {
                    for (op, r) in ops.iter().zip(res) {
                        if r.ok {
                            stopped_svc |= op["op"] == "stop_service";
                            continue;
                        }
                        failed_ops = true;
                        let what = if op["op"] == "stop_service" {
                            op["name"].as_str().unwrap_or("").to_string()
                        } else {
                            format!("pid {}", op["pid"])
                        };
                        notes.push(format!("Could not stop {what}: {}.", r.error.unwrap_or_default()));
                    }
                }
            }
        }
        let waiting: Vec<&ProcInfo> = windowless.iter().chain(&svc_hosts).collect();
        wait(&waiting, EXIT_WAIT);
        let targets: Vec<ProcInfo> = windowed.iter().chain(&windowless).chain(&svc_hosts).cloned().collect();
        Self::finish(&group.label, &targets, &left, &notes, !windowed.is_empty() || stopped_svc, skipped || failed_ops)
    }

    pub fn do_force_kill(&self, group: &AppGroup, cfg: &Config) -> ActionResult {
        let Guard { live, usable: procs, left, mut notes } = match self.guard_group(group, cfg, false) {
            Ok(g) => g,
            Err(r) => return r,
        };
        if live.is_empty() {
            return result("already_stopped", format!("{} is not running.", group.label), vec![]);
        }
        let snap = probe::snapshot_processes();
        let guarded = own_pids_in(&snap, std::process::id());
        let mut targets: Vec<ProcInfo> = procs.clone();
        let mut stack: Vec<ProcInfo> = procs;
        // children by hand, so untouchable subtrees are pruned
        while let Some(parent) = stack.pop() {
            for c in snap.iter().filter(|c| c.ppid == parent.pid && c.create_time >= parent.create_time - CT_TOLERANCE) {
                if targets.iter().any(|t| t.pid == c.pid) {
                    continue;
                }
                if let Some(why) = self.untouchable(c, cfg, &guarded, false) {
                    notes.push(why);
                    continue;
                }
                targets.push(c.clone());
                stack.push(c.clone());
            }
        }
        if targets.is_empty() {
            return result("failed", join(&notes), remaining(&[&left]));
        }
        let mut denied = self.terminate_all(&targets);
        let denied_pids = |d: &[ProcInfo]| d.iter().map(|p| p.pid).collect::<HashSet<_>>();
        let first: HashSet<u32> = denied_pids(&denied);
        let rest: Vec<Pid> = targets.iter().filter(|p| !first.contains(&p.pid)).map(key).collect();
        let survivors = winctl::wait_gone(&rest, FORCE_GRACE);
        let again: Vec<ProcInfo> = targets.iter().filter(|p| survivors.contains(&key(p))).cloned().collect();
        denied.extend(self.terminate_all(&again)); // kill() after terminate(): same call on Windows
        let mut failed_ops = false;
        if !denied.is_empty() {
            let ops: Vec<Value> = denied.iter().map(kill_op).collect();
            match self.call(&ops, cfg) {
                Called::Declined => {
                    let d = denied_pids(&denied);
                    let changed = targets.iter().any(|p| !d.contains(&p.pid) && !alive(p));
                    return Self::declined(&group.label, changed, &notes, &[&targets, &left]);
                }
                Called::Results(res) => {
                    for (op, r) in ops.iter().zip(res) {
                        if !r.ok {
                            failed_ops = true;
                            notes.push(format!("Could not stop pid {}: {}.", op["pid"], r.error.unwrap_or_default()));
                        }
                    }
                }
            }
        }
        wait(&targets.iter().collect::<Vec<_>>(), EXIT_WAIT);
        Self::finish(&group.label, &targets, &left, &notes, false, failed_ops)
    }

    // ---- startup ---------------------------------------------------------

    fn is_local(e: &StartupEntry) -> bool {
        LOCAL_SOURCES.contains(&e.source.as_str()) && !e.needs_admin
    }

    /// What undo needs to put an elevated entry back exactly.
    fn capture_before(&self, e: &StartupEntry) -> Result<Value, String> {
        match e.source.as_str() {
            "service" => match (self.hooks.service_start)(&e.location) {
                Some(start) => Ok(json!({"start": start})),
                None => Err("its current start type could not be read exactly, so it was left unchanged".into()),
            },
            "task" => Ok(json!({"enabled": e.enabled})),
            "run" | "startup_folder" => {
                if !e.needs_admin {
                    return Err(format!("'{}' is changed without elevation", e.name));
                }
                Ok(json!({"approved": (self.hooks.hklm_approved)(e)}))
            }
            other => Err(format!("{other} entries cannot be changed with elevation")),
        }
    }

    fn undo_ops(e: &StartupEntry, before: &Value) -> Result<Vec<Value>, String> {
        match e.source.as_str() {
            "service" => {
                let start = before["start"].as_str().ok_or("missing start")?;
                Ok(vec![json!({"op": "set_service_start", "name": e.location, "start": start})])
            }
            "task" => Ok(vec![json!({"op": "set_task", "name": e.location, "enabled": truthy(&before["enabled"])})]),
            "run" | "startup_folder" if e.needs_admin => {
                let (hive, kind, name) = startup::approved_target(e);
                let data = match &before["approved"] {
                    Value::Null => Value::Null,
                    v @ Value::String(_) => v.clone(),
                    _ => return Err("bad approved value".into()),
                };
                Ok(vec![json!({"op": "set_approved", "hive": hive, "subkey": startup::approved_path(kind),
                               "value": name, "data_hex": data})])
            }
            _ => Err(format!("no elevated undo for {} entry '{}'", e.source, e.name)),
        }
    }

    fn record(conn: &Connection, app_key: &str, e: &StartupEntry, before: Value) -> Result<(), String> {
        let rec = ActionRecord {
            id: None,
            ts: probe::now_unix(),
            app_key: app_key.into(),
            action: "disable_startup".into(),
            entry: serde_json::to_value(e).map_err(|x| x.to_string())?,
            before,
            undone: false,
        };
        record_action(conn, &rec).map_err(|x| x.to_string())?;
        set_startup_enabled(conn, &e.source, &e.location, false).map_err(|x| x.to_string())
    }

    /// Whether the entry is switched on right now, or None when that cannot be read.
    fn live_enabled(&self, e: &StartupEntry) -> Option<bool> {
        if e.source == "service" {
            return (self.hooks.service_start)(&e.location).map(|s| s == "auto" || s == "delayed-auto");
        }
        startup::live_enabled(e, &self.root)
    }

    fn enabled_after_undo(e: &StartupEntry, before: &Value) -> bool {
        match e.source.as_str() {
            "service" => matches!(before["start"].as_str(), Some("auto" | "delayed-auto")),
            "task" => truthy(&before["enabled"]),
            "packaged" => matches!(before["state"].as_u64(), Some(2 | 4)),
            _ => {
                let raw = before["approved"].as_str().and_then(startup::hex_decode);
                startup::approved_is_enabled(raw.as_deref())
            }
        }
    }

    pub fn do_disable_startup(
        &self,
        conn: &Connection,
        app_key: &str,
        entries: &[StartupEntry],
        mode: Option<&str>,
        cfg: &Config,
    ) -> ActionResult {
        let _guard = self.startup_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut notes: Vec<String> = vec![];
        let (mut ok, mut attempted) = (0usize, 0usize);
        let mut pending: Vec<(&StartupEntry, Value, Vec<Value>)> = vec![];
        for e in entries {
            let windows_task = e.source == "task" && startup::is_windows_task(&e.location);
            if !e.can_disable || windows_task {
                let note = if windows_task { Some(startup::WINDOWS_TASK_NOTE) } else { e.note.as_deref() };
                notes.push(format!("{}: {}.", e.name, note.unwrap_or("cannot be turned off here")));
                attempted += 1;
                continue;
            }
            let live = self.live_enabled(e); // the table may be up to 30 ticks old
            if let Some(l) = live {
                if l != e.enabled {
                    let _ = set_startup_enabled(conn, &e.source, &e.location, l);
                }
            }
            if !live.unwrap_or(e.enabled) {
                notes.push(format!("{} is already off.", e.name));
                continue;
            }
            attempted += 1;
            if Self::is_local(e) {
                match startup::apply_toggle(e, false, mode, &self.root) {
                    Ok(before) => match Self::record(conn, app_key, e, before) {
                        Ok(()) => ok += 1,
                        Err(x) => notes.push(format!("{}: could not be turned off ({x}).", e.name)),
                    },
                    Err(x) => notes.push(format!("{}: could not be turned off ({x}).", e.name)),
                }
            } else {
                let prepared = self
                    .capture_before(e)
                    .and_then(|b| startup::elevated_ops_for(e, false, mode).map(|o| (b, o)).map_err(|x| x.to_string()));
                match prepared {
                    Ok((before, ops)) => pending.push((e, before, ops)),
                    Err(x) => notes.push(format!("{}: could not be turned off ({x}).", e.name)),
                }
            }
        }

        let mut declined = false;
        if !pending.is_empty() {
            let ops: Vec<Value> = pending.iter().flat_map(|(_, _, o)| o.iter().cloned()).collect();
            match self.call(&ops, cfg) {
                Called::Declined => {
                    declined = true;
                    notes.push(format!("{DECLINED}."));
                }
                Called::Results(res) => {
                    let mut i = 0;
                    for (e, before, eops) in pending {
                        let rs = &res[i..i + eops.len()];
                        i += eops.len();
                        if rs.iter().all(|r| r.ok) {
                            match Self::record(conn, app_key, e, before) {
                                Ok(()) => ok += 1,
                                Err(x) => notes.push(format!("{}: changed, but not recorded ({x}).", e.name)),
                            }
                        } else {
                            let err: Vec<String> = rs
                                .iter()
                                .filter(|r| !r.ok)
                                .map(|r| r.error.clone().unwrap_or_else(|| "failed".into()))
                                .collect();
                            notes.push(format!("{}: could not be turned off ({}).", e.name, err.join("; ")));
                        }
                    }
                }
            }
        }

        let msg = notes.join(" ");
        if attempted == 0 {
            return result("done", if msg.is_empty() { "Nothing to turn off.".to_string() } else { msg }, vec![]);
        }
        if ok == attempted {
            return result("done", format!("Turned off at startup. {msg}").trim().to_string(), vec![]);
        }
        if ok == 0 {
            return result(if declined { "declined" } else { "failed" }, msg, vec![]);
        }
        result("partial", format!("Some entries turned off. {msg}").trim().to_string(), vec![])
    }

    pub fn do_undo(&self, conn: &Connection, action_id: i64, cfg: &Config) -> ActionResult {
        let _guard = self.startup_lock.lock().unwrap_or_else(|e| e.into_inner());
        let fail = |m: String| result("failed", m, vec![]);
        let rec = match get_action(conn, action_id) {
            Ok(Some(r)) => r,
            Ok(None) => return fail("That change is not on record.".into()),
            Err(e) => return fail(format!("Could not read the record: {e}.")),
        };
        if rec.undone {
            return fail("That change was already undone.".into());
        }
        if rec.action != "disable_startup" {
            return fail(format!("{} cannot be undone.", rec.action));
        }
        let e: StartupEntry = match serde_json::from_value(rec.entry.clone()) {
            Ok(e) => e,
            Err(x) => return fail(format!("Could not undo: {x}.")),
        };
        if Self::is_local(&e) {
            if let Err(x) = startup::restore(&e, &rec.before, &self.root) {
                return fail(format!("Could not undo: {x}."));
            }
        } else {
            let ops = match Self::undo_ops(&e, &rec.before) {
                Ok(o) => o,
                Err(x) => return fail(format!("Could not undo: {x}.")),
            };
            match self.call(&ops, cfg) {
                Called::Declined => return result("declined", DECLINED, vec![]),
                Called::Results(res) => {
                    let bad: Vec<String> = res
                        .iter()
                        .filter(|r| !r.ok)
                        .map(|r| r.error.clone().unwrap_or_else(|| "failed".into()))
                        .collect();
                    if !bad.is_empty() {
                        return fail(format!("Could not undo: {}.", bad.join("; ")));
                    }
                }
            }
        }
        if let Err(x) = mark_undone(conn, action_id) {
            return fail(format!("Restored, but could not update the record: {x}."));
        }
        let _ = set_startup_enabled(conn, &e.source, &e.location, Self::enabled_after_undo(&e, &rec.before));
        result("done", format!("Restored {} at startup.", e.name), vec![])
    }
}

/// Python truthiness of a JSON value, for `before` fields written by the Python build.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::Null => false,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

impl Actions for RealActions {
    fn stop_now(&self, group: &AppGroup, cfg: &Config) -> ActionResult {
        self.do_stop_now(group, cfg)
    }
    fn force_kill(&self, group: &AppGroup, cfg: &Config) -> ActionResult {
        self.do_force_kill(group, cfg)
    }
    fn disable_startup(
        &self,
        conn: &Connection,
        app_key: &str,
        entries: &[StartupEntry],
        mode: Option<&str>,
        cfg: &Config,
    ) -> ActionResult {
        self.do_disable_startup(conn, app_key, entries, mode, cfg)
    }
    fn undo(&self, conn: &Connection, action_id: i64, cfg: &Config) -> ActionResult {
        self.do_undo(conn, action_id, cfg)
    }
}

#[cfg(test)]
#[path = "actions_tests.rs"]
mod tests;
