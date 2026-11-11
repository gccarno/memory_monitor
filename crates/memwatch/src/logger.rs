//! Background logger: probes every interval and writes one tick to SQLite.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
use windows::Win32::System::Threading::CreateMutexW;

use crate::config::Config;
use crate::db::{prune, replace_startup, write_tick};
use crate::grouping::group_processes;
use crate::models::{ProcInfo, ServiceInfo, StartupEntry, SystemSnapshot};
use crate::usage::{mark_usage, pkey, ProcKey};
use crate::{probe, startup};

const SERVICES_EVERY: u64 = 10;
const STARTUP_EVERY: u64 = 30;
const PRUNE_EVERY: u64 = 1440;
const LOG_MAX_BYTES: u64 = 1_000_000;
const LOG_BACKUPS: usize = 3;

// ---- log file ---------------------------------------------------------------

/// Rotating log file (1 MB x 3): `time LEVEL name: message`.
pub struct LogSink {
    path: PathBuf,
    file: Mutex<Option<File>>,
}

impl LogSink {
    pub fn open(data_dir: &Path) -> Arc<LogSink> {
        let _ = std::fs::create_dir_all(data_dir);
        let path = data_dir.join("logger.log");
        let file = OpenOptions::new().create(true).append(true).open(&path).ok();
        Arc::new(LogSink { path, file: Mutex::new(file) })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn backup(&self, n: usize) -> PathBuf {
        let mut s = self.path.as_os_str().to_os_string();
        s.push(format!(".{n}"));
        PathBuf::from(s)
    }

    fn rotate(&self, slot: &mut Option<File>) {
        *slot = None;
        let _ = std::fs::remove_file(self.backup(LOG_BACKUPS));
        for n in (1..LOG_BACKUPS).rev() {
            let _ = std::fs::rename(self.backup(n), self.backup(n + 1));
        }
        let _ = std::fs::rename(&self.path, self.backup(1));
        *slot = OpenOptions::new().create(true).append(true).open(&self.path).ok();
    }

    pub fn write(&self, level: &str, name: &str, msg: &str) {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S,%3f");
        let line = format!("{ts} {level} {name}: {msg}\n");
        let mut slot = self.file.lock().unwrap();
        if slot.as_ref().and_then(|f| f.metadata().ok()).is_some_and(|m| m.len() + line.len() as u64 > LOG_MAX_BYTES) {
            self.rotate(&mut slot);
        }
        if let Some(f) = slot.as_mut() {
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
    }

    pub fn read_all(&self) -> String {
        std::fs::read_to_string(&self.path).unwrap_or_default()
    }
}

/// Lets `log::warn!` calls from probe/startup land in the same file.
struct GlobalLog(Arc<LogSink>);

impl log::Log for GlobalLog {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Info
    }
    fn log(&self, r: &log::Record) {
        if self.enabled(r.metadata()) {
            self.0.write(&r.level().to_string(), r.target(), &r.args().to_string());
        }
    }
    fn flush(&self) {}
}

/// Route the `log` crate to `sink` for this process (first call wins).
pub fn install_global_log(sink: Arc<LogSink>) {
    if log::set_boxed_logger(Box::new(GlobalLog(sink))).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }
}

// ---- environment ------------------------------------------------------------

/// Everything the logger observes or waits on, so tests can stub it.
pub trait Env {
    fn now(&self) -> f64;
    fn sleep(&self, secs: f64);
    fn snapshot_processes(&self) -> Result<Vec<ProcInfo>, String>;
    fn services_by_pid(&self) -> Result<HashMap<u32, Vec<ServiceInfo>>, String>;
    fn inventory(&self, cfg: &Config) -> Result<Vec<StartupEntry>, String>;
    fn prune(&self, conn: &Connection, now: i64, days: i64) -> Result<(), String>;
    fn foreground_pid(&self) -> Option<u32>;
    fn window_pids(&self) -> std::collections::HashSet<u32>;
    fn seconds_since_input(&self) -> f64;
    fn system_snapshot(&self, ts: i64, procs: &[ProcInfo]) -> Result<SystemSnapshot, String>;
    fn own_working_set(&self) -> Option<i64>;
}

pub struct RealEnv;

impl Env for RealEnv {
    fn now(&self) -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    }
    fn sleep(&self, secs: f64) {
        std::thread::sleep(std::time::Duration::from_secs_f64(secs.max(0.0)));
    }
    fn snapshot_processes(&self) -> Result<Vec<ProcInfo>, String> {
        Ok(probe::snapshot_processes())
    }
    fn services_by_pid(&self) -> Result<HashMap<u32, Vec<ServiceInfo>>, String> {
        Ok(probe::services_by_pid())
    }
    fn inventory(&self, cfg: &Config) -> Result<Vec<StartupEntry>, String> {
        Ok(startup::inventory(cfg, ""))
    }
    fn prune(&self, conn: &Connection, now: i64, days: i64) -> Result<(), String> {
        prune(conn, now, days).map(|_| ()).map_err(|e| e.to_string())
    }
    fn foreground_pid(&self) -> Option<u32> {
        probe::foreground_pid()
    }
    fn window_pids(&self) -> std::collections::HashSet<u32> {
        probe::window_pids()
    }
    fn seconds_since_input(&self) -> f64 {
        probe::seconds_since_input()
    }
    fn system_snapshot(&self, ts: i64, procs: &[ProcInfo]) -> Result<SystemSnapshot, String> {
        probe::system_snapshot(ts, procs).map_err(|e| e.to_string())
    }
    fn own_working_set(&self) -> Option<i64> {
        probe::own_working_set()
    }
}

// ---- logger -----------------------------------------------------------------

/// Seconds to sleep so the next tick lands on an interval boundary. Too close to the
/// boundary waits for the following one, so `ts` values never collide.
pub fn delay_for(now: f64, interval: f64) -> f64 {
    let delay = interval - now.rem_euclid(interval);
    if delay < 1.0 {
        delay + interval
    } else {
        delay
    }
}

pub struct Logger {
    pub cfg: Config,
    pub conn: Connection,
    pub env: Box<dyn Env>,
    pub sink: Arc<LogSink>,
    n: u64,
    services: HashMap<u32, Vec<ServiceInfo>>,
    prev: HashMap<ProcKey, (f64, i64)>,
}

impl Logger {
    pub fn new(cfg: Config, conn: Connection, env: Box<dyn Env>) -> Logger {
        let sink = LogSink::open(&cfg.data_dir);
        Logger { cfg, conn, env, sink, n: 0, services: HashMap::new(), prev: HashMap::new() }
    }

    fn err(&self, what: &str, e: &str) {
        self.sink.write("ERROR", "memwatch.logger", &format!("{what}: {e}"));
    }

    /// One sample. Never fails: a broken tick is logged and the next one tries again.
    pub fn tick(&mut self) {
        let n = self.n;
        self.n += 1;
        match catch_unwind(AssertUnwindSafe(|| self.tick_inner(n))) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => self.err(&format!("tick {n} failed"), &e),
            Err(p) => {
                let msg = p
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| p.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "panic".into());
                self.err(&format!("tick {n} panicked"), &msg);
            }
        }
    }

    /// Periodic work, attempted at the start of its due tick so a later failure can't skip it.
    pub fn refresh(&mut self, n: u64) {
        if n.is_multiple_of(SERVICES_EVERY) {
            match self.env.services_by_pid() {
                Ok(s) => self.services = s,
                Err(e) => self.err("service refresh failed", &e),
            }
        }
        if n.is_multiple_of(STARTUP_EVERY) {
            match self.env.inventory(&self.cfg) {
                Ok(inv) => {
                    if let Err(e) = replace_startup(&self.conn, &inv) {
                        self.err("startup inventory failed", &e.to_string());
                    }
                }
                Err(e) => self.err("startup inventory failed", &e),
            }
        }
        if n.is_multiple_of(PRUNE_EVERY) {
            let now = self.env.now() as i64;
            if let Err(e) = self.env.prune(&self.conn, now, self.cfg.retention_days) {
                self.err("prune failed", &e);
            }
        }
    }

    fn tick_inner(&mut self, n: u64) -> Result<(), String> {
        self.refresh(n);
        let ts = self.env.now() as i64;
        let procs = self.env.snapshot_processes()?;
        let groups = group_processes(&procs, &self.services, &self.cfg);
        let flags = mark_usage(
            &groups,
            &procs,
            &self.prev,
            self.env.foreground_pid(),
            &self.env.window_pids(),
            self.env.seconds_since_input() >= self.cfg.user_away_s as f64,
            &self.cfg,
        );
        let mut system = self.env.system_snapshot(ts, &procs)?;
        system.logger_ws = self.env.own_working_set();
        let mut seen: Vec<String> = procs
            .iter()
            .filter_map(|p| self.cfg.process_markers.get(&p.name.to_lowercase()).cloned())
            .collect();
        seen.sort();
        seen.dedup();
        let apps: Vec<_> = groups.iter().map(|(k, g)| (g.clone(), flags[k])).collect();
        write_tick(&self.conn, &system, &apps, &seen).map_err(|e| e.to_string())?;
        self.prev = procs
            .iter()
            .map(|p| (pkey(p.pid, p.create_time), (p.cpu_s.unwrap_or(0.0), p.io_bytes.unwrap_or(0))))
            .collect();
        Ok(())
    }

    fn delay(&self) -> f64 {
        delay_for(self.env.now(), self.cfg.sample_interval_s as f64)
    }

    /// Tick, sleep to the next boundary, repeat until `stop` returns true (checked after each sleep).
    pub fn run_until(&mut self, mut stop: impl FnMut() -> bool) {
        loop {
            self.tick();
            let d = self.delay();
            self.env.sleep(d);
            if stop() {
                return;
            }
        }
    }

    pub fn run_forever(&mut self) {
        self.run_until(|| false);
    }
}

// ---- single instance ----------------------------------------------------------

pub struct InstanceGuard(HANDLE);

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// A guard holding the named mutex, or None if another instance already has it.
pub fn acquire_single_instance(name: &str) -> Option<InstanceGuard> {
    let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let handle = CreateMutexW(None, false, PCWSTR(w.as_ptr())).ok()?;
        if GetLastError() == ERROR_ALREADY_EXISTS {
            let _ = CloseHandle(handle);
            return None;
        }
        Some(InstanceGuard(handle))
    }
}

/// Mutex name for a data directory: the default directory keeps the original name, so a
/// Python logger and a Rust logger on the same data can never both run.
pub fn mutex_name(cfg: &Config, default_dir: &Path) -> String {
    if cfg.data_dir == default_dir {
        "Local\\memwatch-logger".to_string()
    } else {
        let sum = cfg.data_dir.to_string_lossy().to_lowercase().bytes().fold(0xcbf29ce484222325u64, |h, b| {
            (h ^ b as u64).wrapping_mul(0x100000001b3)
        });
        format!("Local\\memwatch-logger-{sum:016x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{all_apps, connect, latest_markers, latest_system};
    use crate::testutil::mkproc;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    #[derive(Default)]
    struct Calls {
        services: Vec<u64>,
        inventory: Vec<u64>,
        prune: Vec<u64>,
        sleeps: Vec<f64>,
        spy_procs: Vec<usize>,
    }

    /// Real probes, except the slow ones (services, schtasks) which are stubbed.
    struct TestEnv {
        clock: Cell<f64>,
        fail_snapshot: Cell<bool>,
        extra: RefCell<Vec<ProcInfo>>,
        hide_defender: Cell<bool>,
        fail_refresh: Cell<bool>,
        n: Rc<Cell<u64>>,
        calls: Rc<RefCell<Calls>>,
    }

    impl TestEnv {
        fn new() -> (TestEnv, Rc<RefCell<Calls>>, Rc<Cell<u64>>) {
            let calls = Rc::new(RefCell::new(Calls::default()));
            let n = Rc::new(Cell::new(0));
            let e = TestEnv {
                clock: Cell::new(1000.0),
                fail_snapshot: Cell::new(false),
                extra: RefCell::new(vec![]),
                hide_defender: Cell::new(false),
                fail_refresh: Cell::new(false),
                n: n.clone(),
                calls: calls.clone(),
            };
            (e, calls, n)
        }
    }

    impl Env for Rc<TestEnv> {
        fn now(&self) -> f64 {
            self.clock.get()
        }
        fn sleep(&self, secs: f64) {
            self.calls.borrow_mut().sleeps.push(secs);
        }
        fn snapshot_processes(&self) -> Result<Vec<ProcInfo>, String> {
            if self.fail_snapshot.get() {
                return Err("boom-snapshot".into());
            }
            let mut v = probe::snapshot_processes();
            if self.hide_defender.get() {
                v.retain(|p| p.name.to_lowercase() != "msmpeng.exe");
            }
            v.extend(self.extra.borrow().iter().cloned());
            Ok(v)
        }
        fn services_by_pid(&self) -> Result<HashMap<u32, Vec<ServiceInfo>>, String> {
            self.calls.borrow_mut().services.push(self.n.get());
            if self.fail_refresh.get() {
                return Err("boom-services".into());
            }
            Ok(HashMap::new())
        }
        fn inventory(&self, _: &Config) -> Result<Vec<StartupEntry>, String> {
            self.calls.borrow_mut().inventory.push(self.n.get());
            if self.fail_refresh.get() {
                return Err("boom-inventory".into());
            }
            Ok(vec![])
        }
        fn prune(&self, _: &Connection, _: i64, _: i64) -> Result<(), String> {
            self.calls.borrow_mut().prune.push(self.n.get());
            if self.fail_refresh.get() {
                return Err("boom-prune".into());
            }
            Ok(())
        }
        fn foreground_pid(&self) -> Option<u32> {
            probe::foreground_pid()
        }
        fn window_pids(&self) -> std::collections::HashSet<u32> {
            probe::window_pids()
        }
        fn seconds_since_input(&self) -> f64 {
            probe::seconds_since_input()
        }
        fn system_snapshot(&self, ts: i64, procs: &[ProcInfo]) -> Result<SystemSnapshot, String> {
            self.calls.borrow_mut().spy_procs.push(procs.len());
            probe::system_snapshot(ts, procs).map_err(|e| e.to_string())
        }
        fn own_working_set(&self) -> Option<i64> {
            probe::own_working_set()
        }
    }

    fn logger() -> (tempfile::TempDir, Logger, Rc<TestEnv>, Rc<RefCell<Calls>>) {
        let dir = tempfile::tempdir().unwrap();
        let (env, calls, _n) = TestEnv::new();
        let env = Rc::new(env);
        let cfg = Config { data_dir: dir.path().to_path_buf(), ..Config::default() };
        let conn = connect(&dir.path().join("m.db")).unwrap();
        let lg = Logger::new(cfg, conn, Box::new(env.clone()));
        (dir, lg, env, calls)
    }

    #[test]
    fn tick_writes_rows_and_survives_probe_error() {
        let (_d, mut lg, env, _c) = logger();
        lg.tick();
        assert!(latest_system(&lg.conn).unwrap().unwrap().logger_ws.unwrap() > 0);
        assert!(!all_apps(&lg.conn).unwrap().is_empty());
        env.fail_snapshot.set(true);
        lg.tick(); // must not panic
        let text = lg.sink.read_all();
        assert!(text.contains("tick 1 failed") && text.contains("boom-snapshot"), "{text}");
    }

    #[test]
    fn system_snapshot_reuses_process_list() {
        let (_d, mut lg, _e, calls) = logger();
        lg.tick();
        assert!(calls.borrow().spy_procs.first().is_some_and(|n| *n > 0));
    }

    #[test]
    fn single_instance() {
        let a = acquire_single_instance("Local\\memwatch-test-rs").unwrap();
        assert!(acquire_single_instance("Local\\memwatch-test-rs").is_none());
        drop(a);
        assert!(acquire_single_instance("Local\\memwatch-test-rs").is_some());
    }

    #[test]
    fn delay_sleeps_to_next_boundary() {
        assert!((delay_for(1015.0, 60.0) - 5.0).abs() < 1e-9);
        assert!((delay_for(1075.5, 60.0) - 4.5).abs() < 1e-9);
    }

    #[test]
    fn long_tick_skips_to_next_future_boundary() {
        // tick ended 70 s after it started: sleep to the next future boundary, not a past one
        assert!((delay_for(1085.0, 60.0) - 55.0).abs() < 1e-9);
    }

    #[test]
    fn near_boundary_sleeps_to_following_boundary() {
        assert!((delay_for(1019.6, 60.0) - 60.4).abs() < 1e-9);
    }

    #[test]
    fn run_loop_sleeps_each_round_and_survives_failing_tick() {
        let (_d, mut lg, env, calls) = logger();
        env.fail_snapshot.set(true);
        env.clock.set(1015.0);
        let mut rounds = 0;
        lg.run_until(|| {
            rounds += 1;
            rounds == 3
        });
        assert_eq!(calls.borrow().sleeps.len(), 3);
        assert!(calls.borrow().sleeps.iter().all(|s| (s - 5.0).abs() < 1e-9));
    }

    #[test]
    fn refreshes_fire_on_due_ticks() {
        let (_d, mut lg, _env, calls) = logger();
        for i in 0..31u64 {
            lg.env = Box::new(NumberedEnv { inner: calls.clone(), i });
            lg.refresh(i);
        }
        let c = calls.borrow();
        assert_eq!(c.services, [0, 10, 20, 30]);
        assert_eq!(c.inventory, [0, 30]);
        assert_eq!(c.prune, [0]);
    }

    /// Records which tick index each refresh hook was called on.
    struct NumberedEnv {
        inner: Rc<RefCell<Calls>>,
        i: u64,
    }

    impl Env for NumberedEnv {
        fn now(&self) -> f64 {
            1000.0
        }
        fn sleep(&self, _: f64) {}
        fn snapshot_processes(&self) -> Result<Vec<ProcInfo>, String> {
            Ok(vec![])
        }
        fn services_by_pid(&self) -> Result<HashMap<u32, Vec<ServiceInfo>>, String> {
            self.inner.borrow_mut().services.push(self.i);
            Ok(HashMap::new())
        }
        fn inventory(&self, _: &Config) -> Result<Vec<StartupEntry>, String> {
            self.inner.borrow_mut().inventory.push(self.i);
            Ok(vec![])
        }
        fn prune(&self, _: &Connection, _: i64, _: i64) -> Result<(), String> {
            self.inner.borrow_mut().prune.push(self.i);
            Ok(())
        }
        fn foreground_pid(&self) -> Option<u32> {
            None
        }
        fn window_pids(&self) -> std::collections::HashSet<u32> {
            Default::default()
        }
        fn seconds_since_input(&self) -> f64 {
            0.0
        }
        fn system_snapshot(&self, _: i64, _: &[ProcInfo]) -> Result<SystemSnapshot, String> {
            Err("unused".into())
        }
        fn own_working_set(&self) -> Option<i64> {
            None
        }
    }

    #[test]
    fn failed_tick_does_not_skip_refreshes() {
        let (_d, mut lg, env, calls) = logger();
        env.fail_snapshot.set(true);
        lg.tick(); // tick 0 fails in the probe, but its refreshes already ran
        assert_eq!(calls.borrow().inventory.len(), 1);
    }

    #[test]
    fn refresh_errors_are_logged_and_swallowed() {
        let (_d, mut lg, env, _c) = logger();
        env.fail_refresh.set(true);
        lg.tick();
        let text = lg.sink.read_all();
        for msg in ["service refresh failed", "startup inventory failed", "prune failed"] {
            assert!(text.contains(msg), "{msg} missing from {text}");
        }
        assert!(latest_system(&lg.conn).unwrap().is_some()); // the sample was still written
    }

    #[test]
    fn tick_records_protected_product_markers() {
        let (_d, mut lg, env, _c) = logger();
        env.hide_defender.set(true);
        env.extra.borrow_mut().push(mkproc(999_991, 4, "MsMpEng.exe", None));
        lg.tick();
        assert_eq!(latest_markers(&lg.conn).unwrap(), ["Windows Defender".to_string()].into());
        env.extra.borrow_mut().clear();
        env.clock.set(1060.0);
        lg.tick();
        assert!(latest_markers(&lg.conn).unwrap().is_empty());
    }

    #[test]
    fn log_file_rotates() {
        let d = tempfile::tempdir().unwrap();
        let sink = LogSink::open(d.path());
        let big = "x".repeat(100_000);
        for _ in 0..30 {
            sink.write("INFO", "t", &big);
        }
        assert!(d.path().join("logger.log.1").exists());
        assert!(!d.path().join("logger.log.4").exists());
        assert!(std::fs::metadata(sink.path()).unwrap().len() <= 1_000_000);
    }

    #[test]
    fn mutex_name_depends_on_data_dir() {
        let default_dir = PathBuf::from(r"C:\d");
        let mut cfg = Config { data_dir: default_dir.clone(), ..Config::default() };
        assert_eq!(mutex_name(&cfg, &default_dir), "Local\\memwatch-logger");
        cfg.data_dir = PathBuf::from(r"C:\scratch");
        assert_ne!(mutex_name(&cfg, &default_dir), "Local\\memwatch-logger");
    }
}
