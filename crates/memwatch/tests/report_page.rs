//! Page view logic (static/report.js), run under Node with TZ=UTC.
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

use memwatch::db::{connect, replace_startup, write_tick};
use memwatch::models::{AppGroup, StartupEntry, SystemSnapshot, UsageFlags};

fn node() -> Option<PathBuf> {
    let out = Command::new("where").arg("node").output().ok()?;
    String::from_utf8_lossy(&out.stdout).lines().next().map(PathBuf::from)
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn report_js() -> PathBuf {
    root().join("../../src/memwatch/static/report.js")
}

fn node_run(node: &PathBuf, script: &str, args: &[&std::path::Path]) -> std::process::Output {
    Command::new(node)
        .arg(root().join("tests/js").join(script))
        .args(args)
        .env("TZ", "UTC")
        .output()
        .expect("run node")
}

#[test]
fn view_helpers() {
    let Some(node) = node() else { return eprintln!("node is not installed; skipped") };
    let out = node_run(&node, "view_tests.js", &[&report_js()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn page_renders_a_real_report() {
    let Some(node) = node() else { return eprintln!("node is not installed; skipped") };
    let dir = tempfile::tempdir().unwrap();
    let conn = connect(&dir.path().join("memwatch.db")).unwrap();
    for i in 0..10 {
        let g = AppGroup {
            app_key: "suite:tobii".into(),
            label: "Tobii".into(),
            kind: "suite".into(),
            pids: vec![(1000, 0.0)],
            private_bytes: 900 << 20,
            working_set: 900 << 20,
            services: vec!["TobiiSvc".into()],
            limited: false,
            microsoft: false,
        };
        let sys = SystemSnapshot {
            ts: i * 60,
            ram_total: 16 << 30,
            ram_avail: 8 << 30,
            commit_used: 10 << 30,
            commit_limit: 24 << 30,
            compression_ws: None,
            pool_paged: 100 << 20,
            pool_nonpaged: 50 << 20,
            boot_time: 0,
            logger_ws: None,
        };
        write_tick(&conn, &sys, &[(g, UsageFlags { foreground: false, active: false, has_windows: false })], &[])
            .unwrap();
    }
    let e = |source: &str, name: &str, loc: &str, can_disable: bool, note: Option<&str>| StartupEntry {
        source: source.into(),
        name: name.into(),
        location: loc.into(),
        command: String::new(),
        enabled: true,
        needs_admin: true,
        can_disable,
        note: note.map(Into::into),
        app_key: Some("suite:tobii".into()),
    };
    replace_startup(
        &conn,
        &[
            e("service", "Tobii Service", "TobiiSvc", true, None),
            e("task", "Tobii Logon", r"\Microsoft\Windows\Tobii", false, Some("Windows system task")),
        ],
    )
    .unwrap();
    let cfg = memwatch::config::load_config(Some(std::path::Path::new("nonexistent.toml")));
    let rep = memwatch::suggest::build_report(&conn, &cfg, 10_000, &HashSet::new(), &|_| vec![], &|_| String::new())
        .unwrap();
    assert!(rep.stale);
    let path = dir.path().join("r.json");
    std::fs::write(&path, serde_json::to_vec(&rep).unwrap()).unwrap();
    let out = node_run(&node, "render_harness.js", &[&report_js(), &path]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let (pressure, sug) = (v["pressure"].as_str().unwrap(), v["suggestions"].as_str().unwrap());
    assert!(pressure.contains("Data as of 00:09"), "{pressure}");
    assert!(pressure.contains("hasn't recorded anything since 00:09"));
    for want in ["now 900 MB", "typical 900 MB", "working set 900 MB", "Tobii Service", "Windows system task",
                 "Stop starting with Windows", "Parts (2)"] {
        assert!(sug.contains(want), "{want} missing from {sug}");
    }
}
