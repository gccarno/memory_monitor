use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, Result};

use crate::models::{
    ActionRecord, AppGroup, AppRecord, SampleRow, StartupEntry, SystemSnapshot, UsageFlags,
};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS samples(
    ts INTEGER, app_key TEXT, private_bytes INTEGER, working_set INTEGER,
    n_procs INTEGER, foreground INTEGER, active INTEGER,
    PRIMARY KEY(ts, app_key));
CREATE INDEX IF NOT EXISTS idx_samples_app_ts ON samples(app_key, ts);
CREATE TABLE IF NOT EXISTS system(
    ts INTEGER PRIMARY KEY, ram_total INTEGER, ram_avail INTEGER,
    commit_used INTEGER, commit_limit INTEGER, compression_ws INTEGER,
    pool_paged INTEGER, pool_nonpaged INTEGER, boot_time INTEGER, logger_ws INTEGER);
CREATE TABLE IF NOT EXISTS apps(
    app_key TEXT PRIMARY KEY, label TEXT, kind TEXT, microsoft INTEGER,
    first_seen INTEGER, last_seen INTEGER, last_used INTEGER, last_active INTEGER,
    has_windows_ever INTEGER, limited INTEGER, services_json TEXT);
CREATE TABLE IF NOT EXISTS startup(
    source TEXT, name TEXT, location TEXT, command TEXT, enabled INTEGER,
    needs_admin INTEGER, can_disable INTEGER, note TEXT, app_key TEXT);
CREATE TABLE IF NOT EXISTS markers(
    ts INTEGER, name TEXT, PRIMARY KEY(ts, name));
CREATE TABLE IF NOT EXISTS actions(
    id INTEGER PRIMARY KEY, ts INTEGER, app_key TEXT, action TEXT,
    entry_json TEXT, before_json TEXT, undone INTEGER DEFAULT 0);
";

const SYSTEM_COLS: &str = "ts, ram_total, ram_avail, commit_used, commit_limit, \
    compression_ws, pool_paged, pool_nonpaged, boot_time, logger_ws";
const STARTUP_COLS: &str =
    "source, name, location, command, enabled, needs_admin, can_disable, note, app_key";
const ACTION_COLS: &str = "id, ts, app_key, action, entry_json, before_json, undone";

pub fn connect(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let conn = Connection::open(path)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

/// One tick. `markers` name products seen running this tick that have no app row
/// of their own (protected ones such as Windows Defender).
pub fn write_tick(
    conn: &Connection,
    system: &SystemSnapshot,
    apps: &[(AppGroup, UsageFlags)],
    markers: &[String],
) -> Result<()> {
    let ts = system.ts;
    let tx = conn.unchecked_transaction()?;
    for m in markers {
        tx.execute("INSERT OR IGNORE INTO markers VALUES(?,?)", params![ts, m])?;
    }
    tx.execute(
        &format!(
            "INSERT OR REPLACE INTO system({SYSTEM_COLS}) VALUES(?,?,?,?,?,?,?,?,?,?)"
        ),
        params![
            system.ts, system.ram_total, system.ram_avail, system.commit_used,
            system.commit_limit, system.compression_ws, system.pool_paged,
            system.pool_nonpaged, system.boot_time, system.logger_ws
        ],
    )?;
    for (g, f) in apps {
        tx.execute(
            "INSERT OR REPLACE INTO samples VALUES(?,?,?,?,?,?,?)",
            params![
                ts, g.app_key, g.private_bytes, g.working_set, g.pids.len() as i64,
                f.foreground, f.active
            ],
        )?;
        let services_json = serde_json::to_string(&g.services).unwrap_or_else(|_| "[]".into());
        tx.execute(
            "INSERT INTO apps(app_key, label, kind, microsoft, first_seen, last_seen,
                 last_used, last_active, has_windows_ever, limited, services_json)
             VALUES(?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(app_key) DO UPDATE SET
                 label=excluded.label, kind=excluded.kind, microsoft=excluded.microsoft,
                 last_seen=excluded.last_seen,
                 last_used=COALESCE(excluded.last_used, apps.last_used),
                 last_active=COALESCE(excluded.last_active, apps.last_active),
                 has_windows_ever=apps.has_windows_ever OR excluded.has_windows_ever,
                 limited=excluded.limited, services_json=excluded.services_json",
            params![
                g.app_key, g.label, g.kind, g.microsoft, ts, ts,
                f.foreground.then_some(ts), f.active.then_some(ts),
                f.has_windows, g.limited, services_json
            ],
        )?;
    }
    tx.commit()
}

pub fn prune(conn: &Connection, now: i64, retention_days: i64) -> Result<usize> {
    let cutoff = now - retention_days * 86400;
    let tx = conn.unchecked_transaction()?;
    let n = tx.execute("DELETE FROM samples WHERE ts < ?", [cutoff])?;
    tx.execute("DELETE FROM system WHERE ts < ?", [cutoff])?;
    tx.execute("DELETE FROM markers WHERE ts < ?", [cutoff])?;
    tx.execute("DELETE FROM apps WHERE last_seen < ?", [cutoff])?;
    tx.commit()?;
    Ok(n)
}

pub fn latest_system(conn: &Connection) -> Result<Option<SystemSnapshot>> {
    conn.query_row(
        &format!("SELECT {SYSTEM_COLS} FROM system ORDER BY ts DESC LIMIT 1"),
        [],
        |r| {
            Ok(SystemSnapshot {
                ts: r.get(0)?,
                ram_total: r.get(1)?,
                ram_avail: r.get(2)?,
                commit_used: r.get(3)?,
                commit_limit: r.get(4)?,
                compression_ws: r.get(5)?,
                pool_paged: r.get(6)?,
                pool_nonpaged: r.get(7)?,
                boot_time: r.get(8)?,
                logger_ws: r.get(9)?,
            })
        },
    )
    .optional()
}

pub fn system_ticks_since(conn: &Connection, since: i64) -> Result<Vec<i64>> {
    let mut st = conn.prepare("SELECT ts FROM system WHERE ts >= ? ORDER BY ts")?;
    let rows = st.query_map([since], |r| r.get(0))?;
    rows.collect()
}

pub fn app_history(conn: &Connection, since: i64) -> Result<BTreeMap<String, Vec<SampleRow>>> {
    let mut st = conn.prepare(
        "SELECT app_key, ts, private_bytes, working_set, foreground, active \
         FROM samples WHERE ts >= ? ORDER BY app_key, ts",
    )?;
    let mut out: BTreeMap<String, Vec<SampleRow>> = BTreeMap::new();
    let rows = st.query_map([since], |r| {
        Ok((
            r.get::<_, String>(0)?,
            SampleRow {
                ts: r.get(1)?,
                private_bytes: r.get(2)?,
                working_set: r.get(3)?,
                foreground: r.get(4)?,
                active: r.get(5)?,
            },
        ))
    })?;
    for row in rows {
        let (k, s) = row?;
        out.entry(k).or_default().push(s);
    }
    Ok(out)
}

pub fn all_apps(conn: &Connection) -> Result<Vec<AppRecord>> {
    let mut st = conn.prepare(
        "SELECT app_key, label, kind, microsoft, first_seen, last_seen, last_used, \
         last_active, has_windows_ever, limited, services_json FROM apps ORDER BY app_key",
    )?;
    let rows = st.query_map([], |r| {
        let services_json: Option<String> = r.get(10)?;
        Ok(AppRecord {
            app_key: r.get(0)?,
            label: r.get(1)?,
            kind: r.get(2)?,
            microsoft: r.get(3)?,
            first_seen: r.get(4)?,
            last_seen: r.get(5)?,
            last_used: r.get(6)?,
            last_active: r.get(7)?,
            has_windows_ever: r.get(8)?,
            limited: r.get(9)?,
            services: services_json
                .filter(|s| !s.is_empty())
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default(),
        })
    })?;
    rows.collect()
}

/// Groups present at the latest logged tick (the newest `system` row):
/// app_key -> (ts, private_bytes, working_set).
pub fn latest_groups(conn: &Connection) -> Result<HashMap<String, (i64, i64, i64)>> {
    let mut st = conn.prepare(
        "SELECT app_key, ts, private_bytes, working_set FROM samples \
         WHERE ts = (SELECT MAX(ts) FROM system)",
    )?;
    let rows = st.query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?, r.get(3)?))))?;
    rows.collect()
}

/// Process count per group at the latest logged tick.
pub fn latest_procs(conn: &Connection) -> Result<HashMap<String, i64>> {
    let mut st = conn.prepare(
        "SELECT app_key, n_procs FROM samples WHERE ts = (SELECT MAX(ts) FROM system)",
    )?;
    let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    rows.collect()
}

pub fn latest_markers(conn: &Connection) -> Result<HashSet<String>> {
    let mut st = conn.prepare(
        "SELECT name FROM markers WHERE ts = (SELECT MAX(ts) FROM system)",
    )?;
    let rows = st.query_map([], |r| r.get(0))?;
    rows.collect()
}

pub fn replace_startup(conn: &Connection, entries: &[StartupEntry]) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM startup", [])?;
    for e in entries {
        tx.execute(
            &format!("INSERT INTO startup({STARTUP_COLS}) VALUES(?,?,?,?,?,?,?,?,?)"),
            params![
                e.source, e.name, e.location, e.command, e.enabled, e.needs_admin,
                e.can_disable, e.note, e.app_key
            ],
        )?;
    }
    tx.commit()
}

/// Reflect a change memwatch just made, until the logger's next inventory.
pub fn set_startup_enabled(
    conn: &Connection,
    source: &str,
    location: &str,
    enabled: bool,
) -> Result<()> {
    conn.execute(
        "UPDATE startup SET enabled = ? WHERE source = ? AND location = ?",
        params![enabled, source, location],
    )?;
    Ok(())
}

pub fn startup_entries(conn: &Connection) -> Result<Vec<StartupEntry>> {
    let mut st =
        conn.prepare(&format!("SELECT {STARTUP_COLS} FROM startup ORDER BY rowid"))?;
    let rows = st.query_map([], |r| {
        Ok(StartupEntry {
            source: r.get(0)?,
            name: r.get(1)?,
            location: r.get(2)?,
            command: r.get(3)?,
            enabled: r.get(4)?,
            needs_admin: r.get(5)?,
            can_disable: r.get(6)?,
            note: r.get(7)?,
            app_key: r.get(8)?,
        })
    })?;
    rows.collect()
}

fn action_from_row(r: &rusqlite::Row) -> Result<ActionRecord> {
    let entry: String = r.get(4)?;
    let before: String = r.get(5)?;
    Ok(ActionRecord {
        id: Some(r.get(0)?),
        ts: r.get(1)?,
        app_key: r.get(2)?,
        action: r.get(3)?,
        entry: serde_json::from_str(&entry).unwrap_or(serde_json::Value::Null),
        before: serde_json::from_str(&before).unwrap_or(serde_json::Value::Null),
        undone: r.get::<_, i64>(6)? != 0,
    })
}

pub fn record_action(conn: &Connection, rec: &ActionRecord) -> Result<i64> {
    conn.execute(
        "INSERT INTO actions(ts, app_key, action, entry_json, before_json, undone) \
         VALUES(?,?,?,?,?,?)",
        params![
            rec.ts,
            rec.app_key,
            rec.action,
            rec.entry.to_string(),
            rec.before.to_string(),
            rec.undone
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn list_actions(conn: &Connection, include_undone: bool) -> Result<Vec<ActionRecord>> {
    let wh = if include_undone { "" } else { "WHERE undone = 0" };
    let mut st =
        conn.prepare(&format!("SELECT {ACTION_COLS} FROM actions {wh} ORDER BY id"))?;
    let rows = st.query_map([], action_from_row)?;
    rows.collect()
}

pub fn get_action(conn: &Connection, id: i64) -> Result<Option<ActionRecord>> {
    conn.query_row(
        &format!("SELECT {ACTION_COLS} FROM actions WHERE id = ?"),
        [id],
        action_from_row,
    )
    .optional()
}

pub fn mark_undone(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("UPDATE actions SET undone = 1 WHERE id = ?", [id])?;
    Ok(())
}

/// Per app, (hour, max private_bytes) buckets at or after `since`, oldest first.
pub fn hourly_max(conn: &Connection, since: i64) -> Result<BTreeMap<String, Vec<(i64, i64)>>> {
    let mut st = conn.prepare(
        "SELECT app_key, ts / 3600 AS h, MAX(private_bytes) FROM samples \
         WHERE ts >= ? GROUP BY app_key, h ORDER BY app_key, h",
    )?;
    let mut out: BTreeMap<String, Vec<(i64, i64)>> = BTreeMap::new();
    let rows = st.query_map([since], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
    })?;
    for row in rows {
        let (k, h, mx) = row?;
        out.entry(k).or_default().push((h, mx));
    }
    Ok(out)
}

/// Per app, median private_bytes over a thinned sample of history (roughly one
/// tick in ten, chosen by timestamp so the filter runs on the index, not the table).
/// An even count averages the middle pair and truncates, like Python's `int(median)`.
pub fn typical_private(conn: &Connection, since: i64) -> Result<HashMap<String, i64>> {
    let mut st = conn.prepare(
        "SELECT app_key, private_bytes FROM samples WHERE ts >= ? AND ts % 600 < 60",
    )?;
    let mut vals: HashMap<String, Vec<i64>> = HashMap::new();
    let rows = st.query_map([since], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    for row in rows {
        let (k, v) = row?;
        vals.entry(k).or_default().push(v);
    }
    Ok(vals
        .into_iter()
        .map(|(k, mut v)| {
            v.sort_unstable();
            let n = v.len();
            let med = if n % 2 == 1 {
                v[n / 2]
            } else {
                ((v[n / 2 - 1] as i128 + v[n / 2] as i128) / 2) as i64
            };
            (k, med)
        })
        .collect())
}

/// Distinct local calendar days with at least one foreground sample.
pub fn used_day_count(conn: &Connection, key: &str, since: i64) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(DISTINCT date(ts, 'unixepoch', 'localtime')) FROM samples \
         WHERE app_key = ? AND ts >= ? AND foreground = 1",
        params![key, since],
        |r| r.get(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;
    use crate::testutil::*;
    use serde_json::json;

    const NONE: UsageFlags = UsageFlags { foreground: false, active: false, has_windows: false };
    fn fl(fg: bool, act: bool, win: bool) -> UsageFlags {
        UsageFlags { foreground: fg, active: act, has_windows: win }
    }

    #[test]
    fn write_tick_tracks_last_used_and_active() {
        let (_d, c) = mem_conn();
        write_tick(&c, &mk_sys(100), &[(mk_group("suite:steam", 300), fl(true, false, true))], &[]).unwrap();
        write_tick(&c, &mk_sys(160), &[(mk_group("suite:steam", 310), fl(false, true, false))], &[]).unwrap();
        let rec = all_apps(&c).unwrap().into_iter().find(|a| a.app_key == "suite:steam").unwrap();
        assert_eq!((rec.first_seen, rec.last_seen), (100, 160));
        assert_eq!((rec.last_used, rec.last_active), (Some(100), Some(160)));
        assert!(rec.has_windows_ever);
    }

    #[test]
    fn prune_removes_old() {
        let (_d, c) = mem_conn();
        write_tick(&c, &mk_sys(0), &[(mk_group("a", 1), NONE)], &[]).unwrap();
        write_tick(&c, &mk_sys(31 * 86400), &[(mk_group("b", 1), NONE)], &[]).unwrap();
        assert_eq!(prune(&c, 31 * 86400, 30).unwrap(), 1);
        let keys: Vec<_> = all_apps(&c).unwrap().into_iter().map(|a| a.app_key).collect();
        assert_eq!(keys, ["b"]);
        assert_eq!(system_ticks_since(&c, 0).unwrap(), [31 * 86400]);
    }

    #[test]
    fn actions_roundtrip() {
        let (_d, c) = mem_conn();
        let rec = ActionRecord {
            id: None,
            ts: 5,
            app_key: "suite:discord".into(),
            action: "disable_startup".into(),
            entry: json!({"source": "run"}),
            before: json!({"approved": null}),
            undone: false,
        };
        let i = record_action(&c, &rec).unwrap();
        assert_eq!(list_actions(&c, false).unwrap()[0].entry, json!({"source": "run"}));
        mark_undone(&c, i).unwrap();
        assert!(list_actions(&c, false).unwrap().is_empty());
        assert!(get_action(&c, i).unwrap().unwrap().undone);
        assert_eq!(list_actions(&c, true).unwrap().len(), 1);
        assert!(get_action(&c, 999).unwrap().is_none());
    }

    #[test]
    fn refresh_fields_and_services() {
        let (_d, c) = mem_conn();
        let mut g = mk_group("x", 5);
        g.label = "Old".into();
        g.services = vec!["svcA".into()];
        write_tick(&c, &mk_sys(10), &[(g, NONE)], &[]).unwrap();
        let mut g = mk_group("x", 6);
        g.label = "New".into();
        g.services = vec!["svcB".into(), "svcC".into()];
        g.limited = true;
        g.microsoft = true;
        write_tick(&c, &mk_sys(20), &[(g, NONE)], &[]).unwrap();
        let rec = &all_apps(&c).unwrap()[0];
        assert_eq!(rec.label, "New");
        assert_eq!(rec.services, ["svcB", "svcC"]);
        assert!(rec.limited && rec.microsoft);
        assert_eq!(rec.first_seen, 10);
        assert!(rec.last_used.is_none() && rec.last_active.is_none() && !rec.has_windows_ever);
    }

    #[test]
    fn latest_system_and_ticks() {
        let (_d, c) = mem_conn();
        assert!(latest_system(&c).unwrap().is_none());
        write_tick(&c, &mk_sys(1), &[], &[]).unwrap();
        let mut s2 = mk_sys(2);
        s2.logger_ws = Some(7);
        write_tick(&c, &s2, &[], &[]).unwrap();
        assert_eq!(latest_system(&c).unwrap().unwrap(), s2);
        assert_eq!(system_ticks_since(&c, 2).unwrap(), [2]);
    }

    #[test]
    fn history_and_latest_groups() {
        let (_d, c) = mem_conn();
        write_tick(&c, &mk_sys(1), &[(mk_group("a", 10), fl(true, false, false))], &[]).unwrap();
        let mut b = mk_group("b", 20);
        b.working_set = 30;
        write_tick(&c, &mk_sys(2), &[(mk_group("a", 11), NONE), (b, NONE)], &[]).unwrap();
        let h = app_history(&c, 0).unwrap();
        assert_eq!(h["a"].iter().map(|s| s.ts).collect::<Vec<_>>(), [1, 2]);
        assert!(h["a"][0].foreground && !h["a"][1].foreground);
        let h2 = app_history(&c, 2).unwrap();
        assert_eq!(h2.len(), 2);
        assert_eq!(h2["a"].len(), 1);
        let lg = latest_groups(&c).unwrap();
        assert_eq!(lg["a"], (2, 11, 11));
        assert_eq!(lg["b"], (2, 20, 30));
    }

    #[allow(clippy::too_many_arguments)]
    fn entry(src: &str, name: &str, loc: &str, cmd: &str, en: bool, na: bool, cd: bool, note: Option<&str>, key: Option<&str>) -> StartupEntry {
        StartupEntry {
            source: src.into(),
            name: name.into(),
            location: loc.into(),
            command: cmd.into(),
            enabled: en,
            needs_admin: na,
            can_disable: cd,
            note: note.map(Into::into),
            app_key: key.map(Into::into),
        }
    }

    #[test]
    fn startup_replace() {
        let (_d, c) = mem_conn();
        let e = entry("run", "Foo", "HKCU\\Run", "foo.exe", true, false, true, None, Some("suite:foo"));
        let f = entry("task", "Bar", "\\Bar", "bar.exe", false, true, false, Some("note"), None);
        replace_startup(&c, &[e, f.clone()]).unwrap();
        assert_eq!(startup_entries(&c).unwrap().len(), 2);
        replace_startup(&c, std::slice::from_ref(&f)).unwrap();
        assert_eq!(startup_entries(&c).unwrap(), [f]);
    }

    #[test]
    fn hourly_max_typical_and_used_days() {
        let (_d, c) = mem_conn();
        for (ts, p, fg) in [(0, 10, true), (60, 30, false), (3600, 20, false), (3 * 86400, 5, true)] {
            write_tick(&c, &mk_sys(ts), &[(mk_group("a", p), fl(fg, fg, false))], &[]).unwrap();
        }
        assert_eq!(hourly_max(&c, 0).unwrap()["a"], [(0, 30), (1, 20), (72, 5)]);
        assert_eq!(hourly_max(&c, 3600).unwrap()["a"], [(1, 20), (72, 5)]);
        // only ts=0, 3600, 259200 pass the thinning: median(10, 20, 5) = 10
        assert_eq!(typical_private(&c, 0).unwrap()["a"], 10);
        assert_eq!(used_day_count(&c, "a", 0).unwrap(), 2);
        assert_eq!(used_day_count(&c, "b", 0).unwrap(), 0);
    }

    #[test]
    fn median_of_even_count_truncates() {
        let (_d, c) = mem_conn();
        // ts 0 and 600 both pass `ts % 600 < 60`
        write_tick(&c, &mk_sys(0), &[(mk_group("a", 10), NONE)], &[]).unwrap();
        write_tick(&c, &mk_sys(600), &[(mk_group("a", 21), NONE)], &[]).unwrap();
        assert_eq!(typical_private(&c, 0).unwrap()["a"], 15); // int(15.5)
    }

    #[test]
    fn latest_groups_follows_latest_system_tick() {
        let (_d, c) = mem_conn();
        write_tick(&c, &mk_sys(1), &[(mk_group("a", 10), NONE)], &[]).unwrap();
        write_tick(&c, &mk_sys(2), &[], &[]).unwrap();
        assert!(latest_groups(&c).unwrap().is_empty());
    }

    #[test]
    fn markers_written_read_and_pruned() {
        let (_d, c) = mem_conn();
        write_tick(&c, &mk_sys(0), &[], &["Windows Defender".to_string()]).unwrap();
        assert!(latest_markers(&c).unwrap().contains("Windows Defender"));
        write_tick(&c, &mk_sys(31 * 86400), &[], &[]).unwrap();
        assert!(latest_markers(&c).unwrap().is_empty());
        prune(&c, 31 * 86400, 30).unwrap();
        let n: i64 = c.query_row("SELECT COUNT(*) FROM markers", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn set_startup_enabled_toggles() {
        let (_d, c) = mem_conn();
        let e = entry("run", "Foo", "HKCU\\Foo", "foo.exe", true, false, true, None, Some("suite:foo"));
        let f = entry("run", "Bar", "HKCU\\Bar", "bar.exe", true, false, true, None, Some("suite:bar"));
        replace_startup(&c, &[e, f]).unwrap();
        set_startup_enabled(&c, "run", "HKCU\\Foo", false).unwrap();
        let en: Vec<_> = startup_entries(&c).unwrap().iter().map(|x| x.enabled).collect();
        assert_eq!(en, [false, true]);
        set_startup_enabled(&c, "run", "HKCU\\Foo", true).unwrap();
        let en: Vec<_> = startup_entries(&c).unwrap().iter().map(|x| x.enabled).collect();
        assert_eq!(en, [true, true]);
    }
}
