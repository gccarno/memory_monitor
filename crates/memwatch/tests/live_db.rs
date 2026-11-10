//! Opens a *copy* of a real Python-written memwatch.db and reads every table.
//! Skipped unless MEMWATCH_LIVE_DB points at the copy.

use memwatch::db;

#[test]
fn reads_python_written_database() {
    let Ok(path) = std::env::var("MEMWATCH_LIVE_DB") else {
        eprintln!("MEMWATCH_LIVE_DB not set; skipping");
        return;
    };
    let conn = db::connect(std::path::Path::new(&path)).unwrap();
    let apps = db::all_apps(&conn).unwrap();
    let actions = db::list_actions(&conn, true).unwrap();
    let startup = db::startup_entries(&conn).unwrap();
    let ticks = db::system_ticks_since(&conn, 0).unwrap();
    let latest = db::latest_system(&conn).unwrap();
    let hist = db::app_history(&conn, 0).unwrap();
    let typical = db::typical_private(&conn, 0).unwrap();
    let hourly = db::hourly_max(&conn, 0).unwrap();
    let groups = db::latest_groups(&conn).unwrap();
    let markers = db::latest_markers(&conn).unwrap();
    eprintln!(
        "apps={} actions={} startup={} ticks={} history_apps={} typical={} hourly={} groups={} markers={} latest={}",
        apps.len(), actions.len(), startup.len(), ticks.len(), hist.len(),
        typical.len(), hourly.len(), groups.len(), markers.len(), latest.is_some()
    );
    assert!(!ticks.is_empty(), "live db has no ticks");
    assert!(latest.is_some());
    for a in &actions {
        assert!(!a.entry.is_null(), "action {:?} entry did not parse", a.id);
    }
    for a in &apps {
        if let Some(first) = hist.get(&a.app_key).and_then(|h| h.first()) {
            assert!(db::used_day_count(&conn, &a.app_key, first.ts).is_ok());
        }
    }
}
