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
