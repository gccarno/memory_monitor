use crate::db::connect;
use crate::models::{AppGroup, ProcInfo, ServiceInfo, SystemSnapshot};
use rusqlite::Connection;

pub fn mkproc(pid: u32, ppid: u32, name: &str, exe: Option<&str>) -> ProcInfo {
    ProcInfo {
        pid,
        ppid,
        name: name.into(),
        exe: exe.map(Into::into),
        cmdline: None,
        create_time: 1.0,
        private_bytes: 10 << 20,
        working_set: 8 << 20,
        cpu_s: Some(0.0),
        io_bytes: Some(0),
        cwd: None,
        limited: false,
    }
}

pub fn svc(name: &str) -> ServiceInfo {
    ServiceInfo {
        name: name.into(),
        display_name: name.into(),
        description: String::new(),
        start_type: "manual".into(),
        pid: None,
        binpath: String::new(),
    }
}

pub fn mem_conn() -> (tempfile::TempDir, Connection) {
    let dir = tempfile::tempdir().unwrap();
    let c = connect(&dir.path().join("memwatch.db")).unwrap();
    c.execute_batch("PRAGMA synchronous=OFF").unwrap();
    (dir, c)
}

pub fn mk_group(key: &str, priv_: i64) -> AppGroup {
    AppGroup {
        app_key: key.into(),
        label: key.rsplit(':').next().unwrap().into(),
        kind: "suite".into(),
        pids: vec![(1000, 0.0)],
        private_bytes: priv_,
        working_set: priv_,
        services: vec![],
        limited: false,
        microsoft: false,
    }
}

pub fn mk_sys(ts: i64) -> SystemSnapshot {
    SystemSnapshot {
        ts,
        ram_total: 16 << 30,
        ram_avail: 8 << 30,
        commit_used: 10 << 30,
        commit_limit: 24 << 30,
        compression_ws: None,
        pool_paged: 100 << 20,
        pool_nonpaged: 50 << 20,
        boot_time: 0,
        logger_ws: None,
    }
}

pub fn mk_cfg() -> crate::config::Config {
    crate::config::load_config(Some(std::path::Path::new("nonexistent.toml")))
}

/// One tick for one group; `edit` adjusts the group (kind, label, services...).
pub fn tick_with(
    conn: &Connection,
    ts: i64,
    key: &str,
    fg: bool,
    priv_: i64,
    windows: bool,
    edit: &dyn Fn(&mut AppGroup),
) {
    let mut g = mk_group(key, priv_);
    edit(&mut g);
    let flags = crate::models::UsageFlags { foreground: fg, active: fg, has_windows: windows };
    crate::db::write_tick(conn, &mk_sys(ts), &[(g, flags)], &[]).unwrap();
}

pub fn tick(conn: &Connection, ts: i64, key: &str, fg: bool, priv_: i64, windows: bool) {
    tick_with(conn, ts, key, fg, priv_, windows, &|_| {});
}

/// `n` ticks, 60 s apart from time zero; never foreground.
pub fn seed_with(conn: &Connection, key: &str, n: i64, priv_: i64, edit: &dyn Fn(&mut AppGroup)) {
    for i in 0..n {
        tick_with(conn, i * 60, key, false, priv_, false, edit);
    }
}

pub fn seed(conn: &Connection, key: &str, n: i64, priv_: i64) {
    seed_with(conn, key, n, priv_, &|_| {});
}
