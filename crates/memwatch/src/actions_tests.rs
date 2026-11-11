//! Actions against processes these tests spawn and registry values under
//! HKCU\Software\memwatch-test-rs-* only. Elevation is always a fake injected here.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use winreg::enums::*;
use winreg::RegKey;

use super::*;
use crate::db::list_actions;
use crate::elevate::{Elevation, OpResult};
use crate::testutil::{mem_conn, mk_cfg};

// ---- fixtures ------------------------------------------------------------------

fn fixture(name: &str) -> PathBuf {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let ok = Command::new(cargo).args(["build", "-p", "test-fixtures"]).status().map(|s| s.success());
        assert_eq!(ok.ok(), Some(true), "could not build the test fixtures");
    });
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().join(format!("{name}.exe"))
}

/// Run launch.exe and read the pid it prints. Its output goes to a file, not a pipe: the
/// started process would inherit the pipe and keep it open until it exits.
fn launch_pid(exe: &std::path::Path, args: &[&str]) -> u32 {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("pid.txt");
    let status = Command::new(fixture("launch"))
        .arg(exe)
        .args(args)
        .stdout(std::fs::File::create(&out).unwrap())
        .status()
        .unwrap();
    assert!(status.success());
    std::fs::read_to_string(&out).unwrap().trim().parse().expect("launch printed a pid")
}

/// A fixture process; ended when dropped (only ever a process spawned here).
struct Sp {
    pid: u32,
    ct: f64,
    child: Option<Child>,
}

impl Sp {
    fn from_pid(pid: u32, child: Option<Child>) -> Sp {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(p) = probe::snapshot_processes().into_iter().find(|p| p.pid == pid) {
                return Sp { pid, ct: p.create_time, child };
            }
            assert!(Instant::now() < end, "fixture {pid} never appeared");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Started through launch.exe, so it is NOT a descendant of the test process.
    fn spawn(name: &str, args: &[&str]) -> Sp {
        Sp::from_pid(launch_pid(&fixture(name), args), None)
    }

    /// A real child of the test process.
    fn spawn_direct(name: &str) -> Sp {
        let child = Command::new(fixture(name)).spawn().unwrap();
        let pid = child.id();
        Sp::from_pid(pid, Some(child))
    }

    fn running(&self) -> bool {
        winctl::find_live(self.pid, self.ct).is_some()
    }

    fn wait_exit(&self) -> bool {
        winctl::wait_gone(&[(self.pid, self.ct)], Duration::from_secs(10)).is_empty()
    }
}

impl Drop for Sp {
    fn drop(&mut self) {
        if self.running() {
            winctl::terminate(self.pid);
        }
        if let Some(c) = self.child.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn group_of(ps: &[&Sp], kind: &str, services: &[&str]) -> AppGroup {
    AppGroup {
        app_key: "suite:test".into(),
        label: "Test app".into(),
        kind: kind.into(),
        pids: ps.iter().map(|p| (p.pid, p.ct)).collect(),
        private_bytes: 0,
        working_set: 0,
        services: services.iter().map(|s| s.to_string()).collect(),
        limited: false,
        microsoft: false,
    }
}

fn suite(ps: &[&Sp]) -> AppGroup {
    group_of(ps, "suite", &[])
}

fn wait_for_window(pid: u32) {
    let end = Instant::now() + Duration::from_secs(20);
    while Instant::now() < end {
        if probe::window_pids().contains(&pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("fixture window never appeared");
}

// ---- fake elevators --------------------------------------------------------------

fn no_elev() -> Elevator {
    Box::new(|ops| panic!("unexpected elevation: {ops:?}"))
}

#[derive(Clone, Default)]
struct Fake {
    calls: Arc<Mutex<Vec<Vec<Value>>>>,
}

impl Fake {
    fn elevator(&self, ok: bool, declined: bool) -> Elevator {
        let calls = self.calls.clone();
        Box::new(move |ops| {
            calls.lock().unwrap().push(ops.to_vec());
            if declined {
                return Elevation::Declined;
            }
            Elevation::Results(
                ops.iter()
                    .map(|_| OpResult { ok, error: if ok { None } else { Some("boom".into()) } })
                    .collect(),
            )
        })
    }
    fn calls(&self) -> Vec<Vec<Value>> {
        self.calls.lock().unwrap().clone()
    }
}

/// Actions with no real service lookups.
fn acts(elev: Elevator) -> RealActions {
    let mut a = RealActions::with_elevator(elev);
    a.hooks.services_by_pid = Box::new(HashMap::new);
    a.hooks.service_running = Box::new(|_| false);
    a.hooks.dependents = Box::new(|_| vec![]);
    a.hooks.service_start = Box::new(|_| Some("auto".into()));
    a.hooks.hklm_approved = Box::new(|_| None);
    a
}

/// Make terminate report access-denied for one pid.
fn deny(a: &mut RealActions, pid: u32) {
    let denied = Arc::new(AtomicU32::new(pid));
    a.hooks.terminate = Box::new(move |p| {
        if p == denied.load(Ordering::SeqCst) {
            Term::Denied
        } else {
            winctl::terminate(p)
        }
    });
}

fn cfg2() -> Config {
    let mut c = mk_cfg();
    c.close_timeout_s = 2;
    c
}

// ---- stop / force ------------------------------------------------------------------

#[test]
fn stop_closes_window_app() {
    let p = Sp::spawn("window_app", &[]);
    wait_for_window(p.pid);
    let r = acts(no_elev()).do_stop_now(&suite(&[&p]), &cfg2());
    assert_eq!(r.status, "done", "{r:?}");
    assert!(!p.running());
}

#[test]
fn stubborn_window_needs_force() {
    let p = Sp::spawn("window_app", &["--stubborn"]);
    wait_for_window(p.pid);
    let a = acts(no_elev());
    let r = a.do_stop_now(&suite(&[&p]), &cfg2());
    assert_eq!(r.status, "still_open");
    assert_eq!(r.remaining_pids, vec![p.pid]);
    assert_eq!(r.message, STILL_OPEN);
    assert_eq!(a.do_force_kill(&suite(&[&p]), &cfg2()).status, "done");
    assert!(p.wait_exit());
}

#[test]
fn stop_on_vanished_app() {
    let p = Sp::spawn("sleeper", &[]);
    let g = suite(&[&p]);
    winctl::terminate(p.pid);
    assert!(p.wait_exit());
    assert_eq!(acts(no_elev()).do_stop_now(&g, &cfg2()).status, "already_stopped");
}

#[test]
fn reused_pid_is_not_touched() {
    let p = Sp::spawn("sleeper", &[]);
    let mut g = suite(&[&p]);
    g.pids = vec![(p.pid, p.ct - 100.0)]; // simulate reuse
    let a = acts(no_elev());
    assert_eq!(a.do_stop_now(&g, &cfg2()).status, "already_stopped");
    assert_eq!(a.do_force_kill(&g, &cfg2()).status, "already_stopped");
    assert!(p.running());
}

#[test]
fn stop_terminates_windowless() {
    let p = Sp::spawn("sleeper", &[]);
    assert_eq!(acts(no_elev()).do_stop_now(&suite(&[&p]), &cfg2()).status, "done");
    assert!(p.wait_exit());
}

#[test]
fn protected_group_is_never_touched() {
    let p = Sp::spawn("sleeper", &[]);
    let a = acts(no_elev());
    let g = group_of(&[&p], "protected", &[]);
    for r in [a.do_stop_now(&g, &cfg2()), a.do_force_kill(&g, &cfg2())] {
        assert_eq!((r.status.as_str(), r.message.as_str()), ("failed", PROTECTED_MSG));
    }
    assert!(p.running());
}

#[test]
fn own_process_is_never_touched() {
    let me = std::process::id();
    let ct = probe::snapshot_processes().into_iter().find(|p| p.pid == me).unwrap().create_time;
    let g = AppGroup { pids: vec![(me, ct)], ..group_of(&[], "instance", &[]) };
    let a = acts(no_elev());
    for r in [a.do_stop_now(&g, &cfg2()), a.do_force_kill(&g, &cfg2())] {
        assert_eq!((r.status.as_str(), r.message.as_str()), ("failed", SELF_MSG));
    }
}

#[test]
fn own_descendant_is_never_touched() {
    let p = Sp::spawn_direct("sleeper"); // a child of this (memwatch) process
    let a = acts(no_elev());
    for r in [a.do_stop_now(&suite(&[&p]), &cfg2()), a.do_force_kill(&suite(&[&p]), &cfg2())] {
        assert_eq!((r.status.as_str(), r.message.as_str()), ("failed", SELF_MSG));
    }
    assert!(p.running());
}

#[test]
fn memwatch_image_name_is_never_touched() {
    // a copy of the sleeper named like memwatch's own exe
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("memwatchw.exe");
    std::fs::copy(fixture("sleeper"), &copy).unwrap();
    let p = Sp::from_pid(launch_pid(&copy, &[]), None);
    let a = acts(no_elev());
    for r in [a.do_stop_now(&suite(&[&p]), &cfg2()), a.do_force_kill(&suite(&[&p]), &cfg2())] {
        assert_eq!((r.status.as_str(), r.message.as_str()), ("failed", SELF_MSG));
        assert_eq!(r.remaining_pids, vec![p.pid]);
    }
    assert!(p.running());
    winctl::terminate(p.pid);
    p.wait_exit();
}

#[test]
fn memwatch_cmdline_process_is_never_touched() {
    let p = Sp::spawn("sleeper", &["-m", "memwatch"]); // looks like `python -m memwatch ...`
    let a = acts(no_elev());
    for r in [a.do_stop_now(&suite(&[&p]), &cfg2()), a.do_force_kill(&suite(&[&p]), &cfg2())] {
        assert_eq!((r.status.as_str(), r.message.as_str()), ("failed", SELF_MSG));
        assert_eq!(r.remaining_pids, vec![p.pid]);
    }
    assert!(p.running());
}

#[test]
fn force_kill_reports_untouchable_survivor_as_partial() {
    let plain = Sp::spawn("sleeper", &[]);
    let mw = Sp::spawn("sleeper", &["-m", "memwatch", "log"]);
    let r = acts(no_elev()).do_force_kill(&suite(&[&plain, &mw]), &cfg2());
    assert_eq!(r.status, "partial", "{r:?}");
    assert_eq!(r.remaining_pids, vec![mw.pid]);
    assert!(plain.wait_exit());
    assert!(mw.running());
}

#[test]
fn stop_reports_untouchable_survivor_as_partial() {
    let plain = Sp::spawn("sleeper", &[]);
    let mw = Sp::spawn("sleeper", &["-m", "memwatch.report"]);
    let r = acts(no_elev()).do_stop_now(&suite(&[&plain, &mw]), &cfg2());
    assert_eq!(r.status, "partial", "{r:?}");
    assert_eq!(r.remaining_pids, vec![mw.pid]);
    assert!(plain.wait_exit());
    assert!(mw.running());
}

#[test]
fn still_open_window_leaves_the_rest_untouched() {
    let win = Sp::spawn("window_app", &["--stubborn"]);
    wait_for_window(win.pid);
    let helper = Sp::spawn("sleeper", &[]);
    let mut a = acts(no_elev());
    a.hooks.service_running = Box::new(|_| true);
    let r = a.do_stop_now(&group_of(&[&win, &helper], "suite", &["FakeSvc"]), &cfg2());
    assert_eq!(r.status, "still_open");
    let mut want = vec![win.pid, helper.pid];
    want.sort();
    assert_eq!(r.remaining_pids, want);
    assert!(helper.running() && win.running());
}

#[test]
fn force_kill_takes_children() {
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("child.pid");
    let p = Sp::spawn("sleeper", &["--child", pidfile.to_str().unwrap()]);
    let end = Instant::now() + Duration::from_secs(20);
    while std::fs::read_to_string(&pidfile).map(|s| s.is_empty()).unwrap_or(true) && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(100));
    }
    let child = Sp::from_pid(std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap(), None);
    assert_eq!(acts(no_elev()).do_force_kill(&suite(&[&p]), &cfg2()).status, "done");
    assert!(p.wait_exit());
    assert!(child.wait_exit(), "the child must go with its parent");
}

#[test]
fn access_denied_goes_to_elevator() {
    let p = Sp::spawn("sleeper", &[]);
    let g = suite(&[&p]);
    let seen: Arc<Mutex<Vec<Vec<Value>>>> = Arc::default();
    let (s2, pid) = (seen.clone(), p.pid);
    // stands in for the runner: kills only our own sleeper
    let elev: Elevator = Box::new(move |ops| {
        s2.lock().unwrap().push(ops.to_vec());
        winctl::terminate(pid);
        Elevation::Results(vec![OpResult { ok: true, error: None }])
    });
    let mut a = acts(elev);
    deny(&mut a, p.pid);
    let r = a.do_stop_now(&g, &cfg2());
    assert_eq!(*seen.lock().unwrap(), vec![vec![json!({"op": "kill", "pid": p.pid, "create_time": p.ct})]]);
    assert_eq!(r.status, "done", "{r:?}");
}

#[test]
fn declined_elevation() {
    let p = Sp::spawn("sleeper", &[]);
    let g = suite(&[&p]);
    let f = Fake::default();
    let mut a = acts(f.elevator(true, true));
    deny(&mut a, p.pid);
    assert_eq!(a.do_stop_now(&g, &cfg2()).status, "declined");
    assert_eq!(a.do_force_kill(&g, &cfg2()).status, "declined");
    assert!(p.running());
}

#[test]
fn declined_after_partial_work_is_partial() {
    for force in [false, true] {
        let easy = Sp::spawn("sleeper", &[]);
        let hard = Sp::spawn("sleeper", &[]);
        let f = Fake::default();
        let mut a = acts(f.elevator(true, true));
        deny(&mut a, hard.pid);
        let g = suite(&[&easy, &hard]);
        let r = if force { a.do_force_kill(&g, &cfg2()) } else { a.do_stop_now(&g, &cfg2()) };
        assert_eq!(r.status, "partial", "{r:?}");
        assert!(r.message.contains("declined"));
        assert_eq!(r.remaining_pids, vec![hard.pid]);
        assert!(easy.wait_exit());
        assert!(hard.running());
    }
}

#[test]
fn services_with_dependents_are_skipped() {
    let running: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec!["SvcA".into(), "SvcB".into()]));
    let (r1, r2) = (running.clone(), running.clone());
    let seen: Arc<Mutex<Vec<Vec<Value>>>> = Arc::default();
    let s2 = seen.clone();
    let elev: Elevator = Box::new(move |ops| {
        s2.lock().unwrap().push(ops.to_vec());
        for op in ops {
            r2.lock().unwrap().retain(|n| n != op["name"].as_str().unwrap());
        }
        Elevation::Results(ops.iter().map(|_| OpResult { ok: true, error: None }).collect())
    });
    let mut a = acts(elev);
    a.hooks.dependents = Box::new(|n| if n == "SvcA" { vec!["Child".into()] } else { vec![] });
    a.hooks.service_running = Box::new(move |n| r1.lock().unwrap().iter().any(|x| x == n));
    let g = group_of(&[], "suite", &["SvcA", "SvcB"]);
    let r = a.do_stop_now(&g, &cfg2());
    assert_eq!(*seen.lock().unwrap(), vec![vec![json!({"op": "stop_service", "name": "SvcB"})]]);
    assert_eq!(r.status, "partial", "{r:?}");
    assert!(r.message.contains("SvcA") && r.message.contains("Child"));
}

fn host_of(pid: u32, names: &[&str]) -> HashMap<u32, Vec<ServiceInfo>> {
    let list = names
        .iter()
        .map(|n| ServiceInfo {
            name: n.to_string(),
            display_name: n.to_string(),
            description: String::new(),
            start_type: "automatic".into(),
            pid: Some(pid),
            binpath: String::new(),
        })
        .collect();
    HashMap::from([(pid, list)])
}

#[test]
fn service_host_is_stopped_via_its_service_not_terminated() {
    let p = Sp::spawn("sleeper", &[]);
    let seen: Arc<Mutex<Vec<Vec<Value>>>> = Arc::default();
    let (s2, pid) = (seen.clone(), p.pid);
    // "stopping the service" ends its host: our own sleeper
    let elev: Elevator = Box::new(move |ops| {
        s2.lock().unwrap().push(ops.to_vec());
        winctl::terminate(pid);
        Elevation::Results(vec![OpResult { ok: true, error: None }])
    });
    let mut a = acts(elev);
    let host = host_of(p.pid, &["FakeSvc"]);
    a.hooks.services_by_pid = Box::new(move || host.clone());
    a.hooks.service_running = Box::new(|_| true);
    a.hooks.terminate = Box::new(|_| panic!("terminated"));
    let r = a.do_stop_now(&group_of(&[&p], "suite", &["FakeSvc"]), &cfg2());
    assert_eq!(*seen.lock().unwrap(), vec![vec![json!({"op": "stop_service", "name": "FakeSvc"})]]);
    assert_eq!(r.status, "done", "{r:?}");
}

#[test]
fn shared_service_host_is_left_alone() {
    let p = Sp::spawn("sleeper", &[]);
    let mut a = acts(no_elev());
    let host = host_of(p.pid, &["FakeSvc", "Other"]);
    a.hooks.services_by_pid = Box::new(move || host.clone());
    let r = a.do_stop_now(&group_of(&[&p], "suite", &["FakeSvc"]), &cfg2());
    assert_eq!(r.status, "failed", "{r:?}");
    assert!(r.message.contains("other services"));
    assert!(p.running());
}

#[test]
fn protected_services_are_skipped() {
    let mut a = acts(no_elev());
    a.hooks.service_running = Box::new(|_| true);
    let r = a.do_stop_now(&group_of(&[], "suite", &["WinDefend"]), &cfg2());
    assert_eq!(r.status, "failed", "{r:?}");
    assert!(r.message.contains("WinDefend"));
}

// ---- startup ---------------------------------------------------------------------------

/// A throwaway HKCU subtree, deleted before and after the test.
struct TestRoot(String);
impl TestRoot {
    fn new(name: &str) -> Self {
        let r = format!(r"Software\memwatch-test-rs-actions-{name}");
        let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&r);
        TestRoot(r)
    }
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.0);
    }
}

fn entry(source: &str, name: &str, location: &str, needs_admin: bool, can_disable: bool, note: Option<&str>, key: &str) -> StartupEntry {
    StartupEntry {
        source: source.into(),
        name: name.into(),
        location: location.into(),
        command: String::new(),
        enabled: true,
        needs_admin,
        can_disable,
        note: note.map(Into::into),
        app_key: Some(key.into()),
    }
}

fn tobii_svc() -> StartupEntry {
    entry("service", "Tobii Service", "Tobii Service", true, true, None, "suite:tobii")
}

fn dummy_run_entry(root: &str) -> StartupEntry {
    let path = format!(r"{root}\Software\Microsoft\Windows\CurrentVersion\Run");
    let cmd = r#""C:\Program Files\Dummy\dummy.exe" --min"#;
    let (k, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey_with_flags(path, KEY_SET_VALUE).unwrap();
    k.set_value("DummyApp", &cmd).unwrap();
    StartupEntry { command: cmd.into(), ..entry("run", "DummyApp", r"HKCU\DummyApp", false, true, None, "suite:dummy") }
}

fn entry_enabled(root: &str, name: &str) -> bool {
    let path = format!(r"{root}\{}", startup::approved_path("run").unwrap());
    let data = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(path)
        .ok()
        .and_then(|k| k.get_raw_value(name).ok())
        .map(|v| v.bytes);
    startup::approved_is_enabled(data.as_deref())
}

#[test]
fn disable_and_undo_hkcu_entry() {
    let root = TestRoot::new("hkcu");
    let (_d, conn) = mem_conn();
    let e = dummy_run_entry(&root.0);
    let mut a = acts(no_elev());
    a.root = root.0.clone();
    let cfg = mk_cfg();
    assert_eq!(a.do_disable_startup(&conn, "suite:dummy", &[e], None, &cfg).status, "done");
    assert!(!entry_enabled(&root.0, "DummyApp"));
    let recs = list_actions(&conn, false).unwrap();
    let rec = &recs[0];
    assert_eq!((rec.action.as_str(), rec.app_key.as_str()), ("disable_startup", "suite:dummy"));
    assert_eq!(rec.before, json!({"approved": null}));
    let id = rec.id.unwrap();
    assert_eq!(a.do_undo(&conn, id, &cfg).status, "done");
    assert!(entry_enabled(&root.0, "DummyApp"));
    assert!(get_action(&conn, id).unwrap().unwrap().undone);
    assert!(list_actions(&conn, false).unwrap().is_empty());
    assert_eq!(a.do_undo(&conn, id, &cfg).status, "failed");
}

#[test]
fn double_disable_records_once() {
    let root = TestRoot::new("double");
    let (_d, conn) = mem_conn();
    let e = dummy_run_entry(&root.0);
    let mut a = acts(no_elev());
    a.root = root.0.clone();
    let cfg = mk_cfg();
    assert_eq!(a.do_disable_startup(&conn, "suite:dummy", std::slice::from_ref(&e), None, &cfg).status, "done");
    // the second click still carries the stale enabled=true entry
    let r = a.do_disable_startup(&conn, "suite:dummy", &[e], None, &cfg);
    assert!(r.status == "done" && r.message.contains("already off"), "{r:?}");
    let recs = list_actions(&conn, false).unwrap();
    assert_eq!(recs.len(), 1);
    // undo restores the true original (enabled), not the already-disabled bytes
    assert_eq!(a.do_undo(&conn, recs[0].id.unwrap(), &cfg).status, "done");
    assert!(entry_enabled(&root.0, "DummyApp"));
}

#[test]
fn disable_then_undo_updates_startup_table() {
    let root = TestRoot::new("table");
    let (_d, conn) = mem_conn();
    let e = dummy_run_entry(&root.0);
    crate::db::replace_startup(&conn, std::slice::from_ref(&e)).unwrap();
    let mut a = acts(no_elev());
    a.root = root.0.clone();
    let cfg = mk_cfg();
    assert_eq!(a.do_disable_startup(&conn, "suite:dummy", &[e], None, &cfg).status, "done");
    let enabled = || crate::db::startup_entries(&conn).unwrap().iter().map(|x| x.enabled).collect::<Vec<_>>();
    assert_eq!(enabled(), vec![false]);
    let id = list_actions(&conn, false).unwrap()[0].id.unwrap();
    assert_eq!(a.do_undo(&conn, id, &cfg).status, "done");
    assert_eq!(enabled(), vec![true]);
}

#[test]
fn declined_disable_records_nothing() {
    let (_d, conn) = mem_conn();
    let f = Fake::default();
    let a = acts(f.elevator(true, true));
    let r = a.do_disable_startup(&conn, "suite:tobii", &[tobii_svc()], Some("manual"), &mk_cfg());
    assert_eq!(r.status, "declined");
    assert!(list_actions(&conn, false).unwrap().is_empty());
}

#[test]
fn unreadable_service_start_is_refused() {
    let (_d, conn) = mem_conn();
    let mut a = acts(no_elev());
    a.hooks.service_start = Box::new(|_| None); // unreadable, boot or system
    let r = a.do_disable_startup(&conn, "suite:tobii", &[tobii_svc()], Some("manual"), &mk_cfg());
    assert!(r.status == "failed" && r.message.contains("start type"), "{r:?}");
    assert!(list_actions(&conn, false).unwrap().is_empty());
}

#[test]
fn mixed_batch_records_only_successes() {
    let (_d, conn) = mem_conn();
    let task = entry("task", "Tobii Logon", r"\Tobii\Logon", true, true, None, "suite:tobii");
    let calls: Arc<Mutex<Vec<Vec<Value>>>> = Arc::default();
    let c2 = calls.clone();
    let elev: Elevator = Box::new(move |ops| {
        c2.lock().unwrap().push(ops.to_vec());
        Elevation::Results(vec![
            OpResult { ok: true, error: None },
            OpResult { ok: false, error: Some("access is denied".into()) },
        ])
    });
    let r = acts(elev).do_disable_startup(&conn, "suite:tobii", &[tobii_svc(), task], Some("manual"), &mk_cfg());
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(calls.lock().unwrap()[0].len(), 2);
    assert!(r.status == "partial" && r.message.contains("Tobii Logon") && r.message.contains("access is denied"), "{r:?}");
    let names: Vec<String> =
        list_actions(&conn, false).unwrap().iter().map(|x| x.entry["name"].as_str().unwrap().to_string()).collect();
    assert_eq!(names, vec!["Tobii Service"]);
}

#[test]
fn admin_entries_share_one_elevation_and_undo() {
    let (_d, conn) = mem_conn();
    let task = entry("task", "Tobii Logon", r"\Tobii\Logon", true, true, None, "suite:tobii");
    let run = entry("run", "TobiiTray", r"HKLM32\TobiiTray", true, true, None, "suite:tobii");
    let nope = entry("service", "Tobii Pkg", "TobiiPkg", true, false, Some("Windows blocks changes"), "suite:tobii");
    let f = Fake::default();
    let a = acts(f.elevator(true, false));
    let cfg = mk_cfg();
    let r = a.do_disable_startup(&conn, "suite:tobii", &[tobii_svc(), task, run, nope], Some("disabled"), &cfg);
    let calls = f.calls();
    assert_eq!(calls.len(), 1);
    let ops = &calls[0];
    assert_eq!(ops[0], json!({"op": "set_service_start", "name": "Tobii Service", "start": "disabled"}));
    assert_eq!(ops[1], json!({"op": "set_task", "name": r"\Tobii\Logon", "enabled": false}));
    assert_eq!(ops[2]["op"], "set_approved");
    assert_eq!(ops[2]["hive"], "HKLM");
    assert_eq!(ops[2]["subkey"], startup::approved_path("run32").unwrap());
    assert_eq!(ops[2]["value"], "TobiiTray");
    assert!(r.status == "partial" && r.message.contains("Windows blocks changes"), "{r:?}");
    let recs = list_actions(&conn, false).unwrap();
    let befores: Vec<Value> = recs.iter().map(|x| x.before.clone()).collect();
    assert_eq!(befores, vec![json!({"start": "auto"}), json!({"enabled": true}), json!({"approved": null})]);
    for rec in &recs {
        let f = Fake::default();
        let a = acts(f.elevator(true, false));
        assert_eq!(a.do_undo(&conn, rec.id.unwrap(), &cfg).status, "done");
        let calls = f.calls();
        let op = &calls[0][0];
        let want = match op["op"].as_str().unwrap() {
            "set_service_start" => json!({"op": "set_service_start", "name": "Tobii Service", "start": "auto"}),
            "set_task" => json!({"op": "set_task", "name": r"\Tobii\Logon", "enabled": true}),
            "set_approved" => json!({"op": "set_approved", "hive": "HKLM", "subkey": startup::approved_path("run32").unwrap(),
                                     "value": "TobiiTray", "data_hex": null}),
            other => panic!("{other}"),
        };
        assert_eq!(*op, want);
        assert!(crate::elevated_runner::validate(op), "undo ops must pass the runner's whitelist");
    }
    assert!(list_actions(&conn, false).unwrap().is_empty());
}

#[test]
fn failed_elevated_op_records_nothing() {
    let (_d, conn) = mem_conn();
    let a = acts(Fake::default().elevator(false, false));
    let r = a.do_disable_startup(&conn, "suite:tobii", &[tobii_svc()], Some("manual"), &mk_cfg());
    assert_eq!(r.status, "failed");
    assert!(list_actions(&conn, false).unwrap().is_empty());
}

#[test]
fn undo_declined_keeps_record() {
    let (_d, conn) = mem_conn();
    let cfg = mk_cfg();
    acts(Fake::default().elevator(true, false)).do_disable_startup(&conn, "suite:tobii", &[tobii_svc()], Some("manual"), &cfg);
    let recs = list_actions(&conn, false).unwrap();
    let a = acts(Fake::default().elevator(true, true));
    assert_eq!(a.do_undo(&conn, recs[0].id.unwrap(), &cfg).status, "declined");
    assert_eq!(list_actions(&conn, false).unwrap(), recs);
}

#[test]
fn cannot_disable_only() {
    let (_d, conn) = mem_conn();
    let nope = entry("service", "Tobii Pkg", "TobiiPkg", true, false, Some("Windows blocks changes"), "suite:tobii");
    let r = acts(no_elev()).do_disable_startup(&conn, "suite:tobii", &[nope], Some("manual"), &mk_cfg());
    assert!(r.status == "failed" && r.message.contains("Windows blocks changes"), "{r:?}");
}

#[test]
fn delayed_auto_service_round_trips_exactly() {
    let (_d, conn) = mem_conn();
    let svc = entry("service", "Windows Search", "WSearch", true, true, None, "service:wsearch");
    let f = Fake::default();
    let mut a = acts(f.elevator(true, false));
    a.hooks.service_start = Box::new(|_| Some("delayed-auto".into()));
    let cfg = mk_cfg();
    assert_eq!(a.do_disable_startup(&conn, "service:wsearch", &[svc], Some("manual"), &cfg).status, "done");
    assert_eq!(f.calls(), vec![vec![json!({"op": "set_service_start", "name": "WSearch", "start": "demand"})]]);
    let recs = list_actions(&conn, false).unwrap();
    assert_eq!(recs[0].before, json!({"start": "delayed-auto"}));
    let f = Fake::default();
    let a = acts(f.elevator(true, false));
    assert_eq!(a.do_undo(&conn, recs[0].id.unwrap(), &cfg).status, "done");
    let calls = f.calls();
    assert_eq!(calls, vec![vec![json!({"op": "set_service_start", "name": "WSearch", "start": "delayed-auto"})]]);
    assert!(crate::elevated_runner::validate(&calls[0][0]));
}

#[test]
fn live_state_already_off_service_is_skipped() {
    let (_d, conn) = mem_conn();
    let mut a = acts(no_elev());
    a.hooks.service_start = Box::new(|_| Some("demand".into())); // already Manual
    let svc = entry("service", "Tobii Service", "TobiiSvc", true, true, None, "suite:tobii");
    let r = a.do_disable_startup(&conn, "suite:tobii", &[svc], Some("manual"), &mk_cfg());
    assert!(r.status == "done" && r.message.contains("already off"), "{r:?}");
    assert!(list_actions(&conn, false).unwrap().is_empty());
}

#[test]
fn windows_system_task_never_reaches_elevator() {
    let (_d, conn) = mem_conn();
    // a stale row that still says can_disable
    let t = entry("task", "FamilySafety", r"\Microsoft\Windows\Shell\FamilySafety", true, true, None, "suite:x");
    let r = acts(no_elev()).do_disable_startup(&conn, "suite:x", &[t], None, &mk_cfg());
    assert!(r.status == "failed" && r.message.contains("Windows system task"), "{r:?}");
    assert!(list_actions(&conn, false).unwrap().is_empty());
}

#[test]
fn elevated_undo_updates_startup_table() {
    let (_d, conn) = mem_conn();
    let svc = entry("service", "Tobii Service", "TobiiSvc", true, true, None, "suite:tobii");
    crate::db::replace_startup(&conn, std::slice::from_ref(&svc)).unwrap();
    let a = acts(Fake::default().elevator(true, false));
    let cfg = mk_cfg();
    a.do_disable_startup(&conn, "suite:tobii", &[svc], Some("manual"), &cfg);
    let enabled = || crate::db::startup_entries(&conn).unwrap().iter().map(|x| x.enabled).collect::<Vec<_>>();
    assert_eq!(enabled(), vec![false]);
    a.do_undo(&conn, list_actions(&conn, false).unwrap()[0].id.unwrap(), &cfg);
    assert_eq!(enabled(), vec![true]);
}

#[test]
fn python_written_records_undo() {
    // the exact shape Python's dataclasses.asdict / json.dumps produce
    let (_d, conn) = mem_conn();
    let rec = ActionRecord {
        id: None,
        ts: 1,
        app_key: "suite:tobii".into(),
        action: "disable_startup".into(),
        entry: serde_json::from_str(
            r#"{"source": "service", "name": "Tobii Service", "location": "TobiiSvc", "command": "",
                "enabled": true, "needs_admin": true, "can_disable": true, "note": null, "app_key": "suite:tobii"}"#,
        )
        .unwrap(),
        before: serde_json::from_str(r#"{"start": "delayed-auto"}"#).unwrap(),
        undone: false,
    };
    let id = record_action(&conn, &rec).unwrap();
    let f = Fake::default();
    let r = acts(f.elevator(true, false)).do_undo(&conn, id, &mk_cfg());
    assert_eq!(r.status, "done", "{r:?}");
    assert_eq!(f.calls(), vec![vec![json!({"op": "set_service_start", "name": "TobiiSvc", "start": "delayed-auto"})]]);
}
