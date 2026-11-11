use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use serde_json::json;
use winreg::enums::HKEY_CURRENT_USER;
use winreg::RegKey;

use super::*;
use crate::db::{connect, mark_undone, record_action, write_tick};
use crate::models::ActionRecord;
use crate::testutil::{mk_cfg, mk_sys, mkproc};

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

struct TestRoot(String);
impl TestRoot {
    fn new(name: &str) -> Self {
        let r = format!(r"Software\memwatch-test-rs-cli-{name}");
        let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&r);
        TestRoot(r)
    }
    fn run_value(&self) -> Option<String> {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(format!(r"{}\{RUN_SUBKEY}", self.0))
            .ok()?
            .get_value(RUN_NAME)
            .ok()
    }
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.0);
    }
}

#[derive(Default)]
struct Calls {
    stopped: Vec<(u32, f64)>,
    started: Vec<PathBuf>,
    links: Vec<(PathBuf, PathBuf, String)>,
    order: Vec<&'static str>,
}

fn fake_sys(found: Vec<(u32, f64)>, calls: &Rc<RefCell<Calls>>, link_err: Option<&'static str>) -> Sys {
    let (c1, c2, c3) = (calls.clone(), calls.clone(), calls.clone());
    Sys {
        find_loggers: Box::new(move || found.clone()),
        stop: Box::new(move |p| {
            let mut c = c1.borrow_mut();
            c.stopped.extend_from_slice(p);
            c.order.push("stop");
        }),
        start_logger: Box::new(move |exe| {
            let mut c = c2.borrow_mut();
            c.started.push(exe.to_path_buf());
            c.order.push("start");
            Ok(())
        }),
        make_shortcut: Box::new(move |lnk, target, args, _wd| {
            if let Some(e) = link_err {
                return Err(e.to_string());
            }
            std::fs::create_dir_all(lnk.parent().unwrap()).unwrap();
            std::fs::write(lnk, b"lnk").unwrap();
            c3.borrow_mut().links.push((lnk.to_path_buf(), target.to_path_buf(), args.to_string()));
            Ok(())
        }),
    }
}

struct Env {
    _tmp: tempfile::TempDir,
    cfg: Config,
    opts: Opts,
    desktop: PathBuf,
    dir: PathBuf,
}

/// A fake "build output" folder with both exes, an install folder, a desktop and a data dir.
fn env(root: Option<&TestRoot>) -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("build");
    std::fs::create_dir_all(&src).unwrap();
    for n in EXES {
        std::fs::write(src.join(n), n.as_bytes()).unwrap();
    }
    let (desktop, dir) = (tmp.path().join("desktop"), tmp.path().join("Programs").join("memwatch"));
    let mut cfg = mk_cfg();
    cfg.data_dir = tmp.path().join("local").join("memwatch");
    let opts = Opts {
        root: root.map(|r| r.0.clone()),
        desktop: Some(desktop.clone()),
        install_dir: Some(dir.clone()),
        src_dir: src,
        ..Default::default()
    };
    Env { _tmp: tmp, cfg, opts, desktop, dir }
}

fn run(f: impl FnOnce(&mut Vec<u8>, &mut Vec<u8>) -> i32) -> (i32, String, String) {
    let (mut o, mut e) = (vec![], vec![]);
    let code = f(&mut o, &mut e);
    (code, String::from_utf8_lossy(&o).into_owned(), String::from_utf8_lossy(&e).into_owned())
}

fn do_install(e: &Env, sys: &Sys) -> (i32, String, String) {
    run(|o, er| install(&e.cfg, &e.opts, sys, o, er))
}

fn do_uninstall(e: &Env, sys: &Sys) -> (i32, String, String) {
    run(|o, er| uninstall(&e.cfg, &e.opts, sys, o, er))
}

// ---------------------------------------------------------------- finding loggers

#[test]
fn logger_cmdline_match_is_specific() {
    assert!(is_logger_cmdline(&s(&["pythonw.exe", "-m", "memwatch", "log"])));
    assert!(is_logger_cmdline(&s(&[r"C:\Programs\memwatch\memwatchw.exe", "log"])));
    assert!(is_logger_cmdline(&s(&["MemWatch.EXE", "log"])));
    assert!(!is_logger_cmdline(&s(&["pythonw.exe", "-m", "memwatch", "report"])));
    assert!(!is_logger_cmdline(&s(&["memwatchw.exe", "report"])));
    assert!(!is_logger_cmdline(&s(&["memwatchw.exe", "elevated-run", "x", "log"])));
    assert!(!is_logger_cmdline(&s(&["memwatch.exe", "status"])));
    assert!(!is_logger_cmdline(&s(&["pythonw.exe", "-I", "-m", "memwatch.elevated_runner", "x", "log"])));
    assert!(!is_logger_cmdline(&s(&["python.exe", "other.py", "log"])));
    assert!(!is_logger_cmdline(&[]));
}

#[test]
fn loggers_in_skips_self_and_unreadable_command_lines() {
    let mut a = mkproc(11, 1, "memwatchw.exe", None);
    a.cmdline = Some(s(&["memwatchw.exe", "log"]));
    a.create_time = 5.0;
    let mut me = mkproc(12, 1, "memwatch.exe", None);
    me.cmdline = Some(s(&["memwatch.exe", "log"]));
    let unreadable = mkproc(13, 1, "memwatchw.exe", None); // cmdline None
    let mut other = mkproc(14, 1, "notepad.exe", None);
    other.cmdline = Some(s(&["notepad.exe"]));
    assert_eq!(loggers_in(&[a, me, unreadable, other], 12), vec![(11, 5.0)]);
}

// ---------------------------------------------------------------- install / uninstall

#[test]
fn install_uninstall_roundtrip() {
    let root = TestRoot::new("roundtrip");
    let e = env(Some(&root));
    let calls = Rc::new(RefCell::new(Calls::default()));
    let sys = fake_sys(vec![], &calls, None);
    let (code, out, err) = do_install(&e, &sys);
    assert_eq!((code, err.as_str()), (0, ""), "{out}");
    let val = root.run_value().unwrap();
    assert_eq!(val, format!("\"{}\" log", e.dir.join("memwatchw.exe").display()));
    for n in EXES {
        assert_eq!(std::fs::read(e.dir.join(n)).unwrap(), n.as_bytes());
    }
    let c = calls.borrow();
    assert_eq!(c.started, vec![e.dir.join("memwatchw.exe")]);
    assert_eq!(c.links.len(), 1);
    assert_eq!(c.links[0].0, e.desktop.join(SHORTCUT_NAME));
    assert_eq!((c.links[0].1.as_path(), c.links[0].2.as_str()), (e.dir.join("memwatchw.exe").as_path(), "report"));
    drop(c);
    assert!(e.desktop.join(SHORTCUT_NAME).exists());
    assert_eq!(do_uninstall(&e, &sys).0, 0);
    assert_eq!(root.run_value(), None);
    assert!(!e.desktop.join(SHORTCUT_NAME).exists());
}

#[test]
fn install_stops_old_loggers_before_copying_and_starting() {
    let root = TestRoot::new("replace");
    let e = env(Some(&root));
    let calls = Rc::new(RefCell::new(Calls::default()));
    let sys = fake_sys(vec![(7, 1.5)], &calls, None);
    assert_eq!(do_install(&e, &sys).0, 0);
    let c = calls.borrow();
    assert_eq!(c.stopped, vec![(7, 1.5)]);
    assert_eq!(c.order, vec!["stop", "start"]);
}

#[test]
fn reinstall_over_itself_does_not_copy() {
    let root = TestRoot::new("inplace");
    let mut e = env(Some(&root));
    e.opts.install_dir = Some(e.opts.src_dir.clone());
    e.dir = e.opts.src_dir.clone();
    let calls = Rc::new(RefCell::new(Calls::default()));
    assert_eq!(do_install(&e, &fake_sys(vec![], &calls, None)).0, 0);
    assert!(root.run_value().unwrap().contains("build"));
}

#[test]
fn root_requires_desktop_and_install_dir() {
    let root = TestRoot::new("refuse");
    let mut e = env(Some(&root));
    let calls = Rc::new(RefCell::new(Calls::default()));
    let sys = fake_sys(vec![], &calls, None);
    e.opts.desktop = None;
    assert_eq!(do_install(&e, &sys).0, 2);
    e.opts.desktop = Some(e.desktop.clone());
    e.opts.install_dir = None;
    assert_eq!(do_install(&e, &sys).0, 2);
    assert_eq!(root.run_value(), None);
    assert!(calls.borrow().started.is_empty() && calls.borrow().stopped.is_empty());
    e.opts.desktop = None;
    assert_eq!(do_uninstall(&e, &sys).0, 2);
}

#[test]
fn missing_exes_fail_before_touching_anything() {
    let root = TestRoot::new("noexe");
    let e = env(Some(&root));
    std::fs::remove_file(e.opts.src_dir.join("memwatchw.exe")).unwrap();
    let calls = Rc::new(RefCell::new(Calls::default()));
    let (code, _, err) = do_install(&e, &fake_sys(vec![(7, 1.0)], &calls, None));
    assert_eq!(code, 1);
    assert!(err.contains("memwatchw.exe"));
    assert_eq!(root.run_value(), None);
    assert!(calls.borrow().stopped.is_empty() && !e.dir.exists());
}

#[test]
fn shortcut_failure_returns_1_and_does_not_start() {
    let root = TestRoot::new("nolnk");
    let e = env(Some(&root));
    let calls = Rc::new(RefCell::new(Calls::default()));
    let (code, _, err) = do_install(&e, &fake_sys(vec![], &calls, Some("no shell")));
    assert_eq!(code, 1);
    assert!(err.contains("shortcut failed") && err.contains("no shell"), "{err}");
    assert!(calls.borrow().started.is_empty());
}

#[test]
fn uninstall_stops_only_found_loggers() {
    let root = TestRoot::new("stops");
    let e = env(Some(&root));
    let calls = Rc::new(RefCell::new(Calls::default()));
    assert_eq!(do_uninstall(&e, &fake_sys(vec![(1, 2.0)], &calls, None)).0, 0);
    assert_eq!(calls.borrow().stopped, vec![(1, 2.0)]);
    let calls = Rc::new(RefCell::new(Calls::default()));
    assert_eq!(do_uninstall(&e, &fake_sys(vec![], &calls, None)).0, 0);
    assert!(calls.borrow().stopped.is_empty());
}

#[test]
fn purge_deletes_data_dir_and_installed_exes() {
    let root = TestRoot::new("purge");
    let e = env(Some(&root));
    std::fs::create_dir_all(&e.cfg.data_dir).unwrap();
    std::fs::write(e.cfg.data_dir.join("memwatch.db"), b"x").unwrap();
    let calls = Rc::new(RefCell::new(Calls::default()));
    let sys = fake_sys(vec![], &calls, None);
    assert_eq!(do_install(&e, &sys).0, 0);
    let mut e2 = e;
    e2.opts.purge = true;
    assert_eq!(do_uninstall(&e2, &sys).0, 0);
    assert!(!e2.cfg.data_dir.exists() && !e2.dir.exists());
}

#[test]
fn purge_reports_leftover_files() {
    use std::os::windows::fs::OpenOptionsExt;
    let root = TestRoot::new("leftover");
    let mut e = env(Some(&root));
    std::fs::create_dir_all(&e.cfg.data_dir).unwrap();
    let locked = e.cfg.data_dir.join("memwatch.db");
    // an open handle with no sharing makes the delete fail
    let _hold = std::fs::OpenOptions::new().write(true).create(true).truncate(true).share_mode(0).open(&locked).unwrap();
    e.opts.purge = true;
    let calls = Rc::new(RefCell::new(Calls::default()));
    let (code, _, err) = do_uninstall(&e, &fake_sys(vec![], &calls, None));
    assert_eq!(code, 1);
    assert!(err.contains("memwatch.db"), "{err}");
}

fn data_with_action(e: &Env, undone: bool) {
    let c = connect(&e.cfg.data_dir.join("memwatch.db")).unwrap();
    for (src, name, loc) in [("service", "Tobii Service", "TobiiSvc"), ("run", "Discord", r"HKCU\Discord")] {
        let rec = ActionRecord {
            id: None,
            ts: 5,
            app_key: "suite:x".into(),
            action: "disable_startup".into(),
            entry: json!({"source": src, "name": name, "location": loc}),
            before: json!({}),
            undone: false,
        };
        let id = record_action(&c, &rec).unwrap();
        if undone {
            mark_undone(&c, id).unwrap();
        }
    }
}

#[test]
fn purge_refuses_while_startup_changes_are_outstanding() {
    let root = TestRoot::new("guard");
    let mut e = env(Some(&root));
    data_with_action(&e, false);
    e.opts.purge = true;
    let calls = Rc::new(RefCell::new(Calls::default()));
    let (code, _, err) = do_uninstall(&e, &fake_sys(vec![(1, 1.0)], &calls, None));
    assert_eq!(code, 1);
    for want in ["Tobii Service", "Discord", "--force", "services.msc", "Task Manager"] {
        assert!(err.contains(want), "missing {want}: {err}");
    }
    assert!(e.cfg.data_dir.join("memwatch.db").exists());
    assert!(calls.borrow().stopped.is_empty(), "nothing is touched when refusing");
}

#[test]
fn purge_force_deletes_anyway_and_undone_changes_do_not_block() {
    let root = TestRoot::new("force");
    let mut e = env(Some(&root));
    data_with_action(&e, false);
    e.opts.purge = true;
    e.opts.force = true;
    let calls = Rc::new(RefCell::new(Calls::default()));
    assert_eq!(do_uninstall(&e, &fake_sys(vec![], &calls, None)).0, 0);
    assert!(!e.cfg.data_dir.exists());

    let root = TestRoot::new("undone");
    let mut e = env(Some(&root));
    data_with_action(&e, true);
    e.opts.purge = true;
    assert_eq!(do_uninstall(&e, &fake_sys(vec![], &calls, None)).0, 0);
    assert!(!e.cfg.data_dir.exists());
}

// ---------------------------------------------------------------- status

#[test]
fn status_runs_without_db() {
    let e = env(None);
    let calls = Rc::new(RefCell::new(Calls::default()));
    let mut out = vec![];
    assert_eq!(status(&e.cfg, &fake_sys(vec![], &calls, None), &mut out), 0);
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains("logger running: no") && out.contains("logger memory: unknown"), "{out}");
    assert!(!e.cfg.data_dir.exists());
}

#[test]
fn status_with_db() {
    let e = env(None);
    let c = connect(&e.cfg.data_dir.join("memwatch.db")).unwrap();
    for i in 0..120 {
        let mut sys = mk_sys(i * 60);
        sys.logger_ws = Some(30 << 20);
        write_tick(&c, &sys, &[], &[]).unwrap();
    }
    drop(c);
    let calls = Rc::new(RefCell::new(Calls::default()));
    let mut out = vec![];
    assert_eq!(status(&e.cfg, &fake_sys(vec![(1, 1.0)], &calls, None), &mut out), 0);
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains("logger running: yes"), "{out}");
    assert!(out.contains("observed: 2.0 hours"), "{out}");
    assert!(out.contains("logger memory: 30 MB (cap 50 MB)"), "{out}");
    assert!(out.contains("db size: ") && out.contains(" MB"), "{out}");
}

// ---------------------------------------------------------------- real shell calls

#[test]
fn real_shortcut_is_written_and_points_at_the_exe() {
    let tmp = tempfile::tempdir().unwrap();
    let lnk = tmp.path().join("deep").join(SHORTCUT_NAME);
    let target = Path::new(r"C:\Windows\System32\notepad.exe");
    make_shortcut(&lnk, target, "report", tmp.path()).unwrap();
    assert!(lnk.is_file());
    assert_eq!(
        crate::startup::lnk_target(&lnk.to_string_lossy()).to_lowercase(),
        target.to_string_lossy().to_lowercase()
    );
}

#[test]
fn desktop_folder_is_found() {
    assert!(desktop_dir().is_some_and(|d| d.is_dir()));
}

#[test]
fn default_install_dir_sits_beside_the_data_dir() {
    let mut cfg = mk_cfg();
    cfg.data_dir = PathBuf::from(r"C:\Users\x\AppData\Local\memwatch");
    assert_eq!(default_install_dir(&cfg), PathBuf::from(r"C:\Users\x\AppData\Local\Programs\memwatch"));
}
