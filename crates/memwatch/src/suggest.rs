//! Turn the logged history into plain-English stop suggestions.

use std::collections::{BTreeSet, HashMap, HashSet};

use chrono::{Local, TimeZone};
use rusqlite::{Connection, Result};

use crate::config::Config;
use crate::db::{
    all_apps, hourly_max, latest_groups, latest_markers, latest_procs, latest_system, list_actions,
    startup_entries, system_ticks_since, typical_private, used_day_count,
};
use crate::models::{AppRecord, AppSummary, Report, StartupEntry, Suggestion};
use crate::probe;

const HISTORY_DAYS: i64 = 30;
const AUTOSTART_SOURCES: [&str; 4] = ["run", "startup_folder", "packaged", "service"];
const GIB: i64 = 1 << 30;
const MIB: i64 = 1 << 20;

pub fn fmt_size(b: i64) -> String {
    if b >= GIB {
        format!("{:.1} GB", b as f64 / GIB as f64)
    } else {
        format!("{:.0} MB", b as f64 / MIB as f64)
    }
}

pub fn fmt_dur(s: i64) -> String {
    let (n, unit) = if s < 3600 {
        (s / 60, "minute")
    } else if s < 48 * 3600 {
        (s / 3600, "hour")
    } else {
        (s / 86400, "day")
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

pub fn default_service_desc(service: &str) -> String {
    probe::service_description(service)
}

const UNKNOWN: &str = "<unknown>";

/// Running services that list `service` in DependOnService (readable without admin).
fn registry_dependents(service: &str) -> std::io::Result<Vec<String>> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let want = service.to_lowercase();
    let root = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SYSTEM\CurrentControlSet\Services")?;
    let mut out = Vec::new();
    for name in root.enum_keys().flatten() {
        let Ok(k) = root.open_subkey(&name) else { continue };
        let Ok(deps) = k.get_value::<Vec<String>, _>("DependOnService") else { continue };
        if !deps.iter().any(|d| d.to_lowercase() == want) {
            continue;
        }
        if probe::service_is_running(&name).unwrap_or(true) {
            out.push(name);
        }
    }
    Ok(out)
}

/// SCM first, then the registry; if neither can tell, a non-empty sentinel so callers
/// never offer 'disabled'. Never fails.
pub fn dependents_with(
    service: &str,
    scm: &dyn Fn(&str) -> std::result::Result<Vec<String>, String>,
    registry: &dyn Fn(&str) -> std::io::Result<Vec<String>>,
) -> Vec<String> {
    if let Ok(v) = scm(service) {
        return v;
    }
    registry(service).unwrap_or_else(|_| vec![UNKNOWN.to_string()])
}

pub fn default_dependents(service: &str) -> Vec<String> {
    dependents_with(service, &probe::scm_dependents, &registry_dependents)
}

fn local_day(ts: i64) -> chrono::NaiveDate {
    Local
        .timestamp_opt(ts, 0)
        .single()
        .map(|d| d.date_naive())
        .unwrap_or_default()
}

type Present = HashMap<String, (i64, i64, i64)>;

/// Startup entries per app key. A service entry joins the group that hosts that
/// service (a shared svchost group is keyed `service:a+b`, its entries `service:a`),
/// preferring a group seen in the latest tick.
pub fn startup_by_app(
    conn: &Connection,
    apps: Option<&[AppRecord]>,
    present: Option<&Present>,
) -> Result<HashMap<String, Vec<StartupEntry>>> {
    let owned_apps;
    let apps = match apps {
        Some(a) => a,
        None => {
            owned_apps = all_apps(conn)?;
            &owned_apps
        }
    };
    let owned_present;
    let present = match present {
        Some(p) => p,
        None => {
            owned_present = latest_groups(conn)?;
            &owned_present
        }
    };
    let mut host: HashMap<String, &str> = HashMap::new();
    let mut order: Vec<&AppRecord> = apps.iter().collect();
    order.sort_by_key(|a| present.contains_key(&a.app_key)); // present groups win
    for a in order {
        for s in &a.services {
            host.insert(s.to_lowercase(), &a.app_key);
        }
    }
    let mut out: HashMap<String, Vec<StartupEntry>> = HashMap::new();
    for e in startup_entries(conn)? {
        let key = if e.source == "service" {
            host.get(&e.location.to_lowercase()).map(|s| s.to_string()).or_else(|| e.app_key.clone())
        } else {
            e.app_key.clone()
        };
        if let Some(k) = key.filter(|k| !k.is_empty()) {
            out.entry(k).or_default().push(e);
        }
    }
    Ok(out)
}

pub fn build_report(
    conn: &Connection,
    cfg: &Config,
    now: i64,
    exclude_keys: &HashSet<String>,
    dependents: &dyn Fn(&str) -> Vec<String>,
    service_desc: &dyn Fn(&str) -> String,
) -> Result<Report> {
    let interval = cfg.sample_interval_s;
    let since = now - HISTORY_DAYS * 86400;
    let ticks = system_ticks_since(conn, since)?;
    let observed_s = ticks.len() as i64 * interval;
    let observed_hours = observed_s as f64 / 3600.0;
    let partial_note = (observed_hours < cfg.partial_hours as f64)
        .then(|| format!("Based on {} of data", fmt_dur(observed_s)));
    let observed_days = ticks.iter().map(|&t| local_day(t)).collect::<BTreeSet<_>>().len() as i64;
    let recent = &ticks[ticks.len().saturating_sub(10)..];

    let system = latest_system(conn)?;
    let uptime_s = system.as_ref().map_or(0, |s| (now - s.boot_time).max(0));
    let kernel_note = system.as_ref().and_then(|s| {
        (s.pool_nonpaged > cfg.nonpaged_warn_mb * MIB).then(|| {
            format!(
                "Windows kernel memory is high ({} non-paged). This is often a driver leak; \
                 a reboot clears it. Up {}.",
                fmt_size(s.pool_nonpaged),
                fmt_dur(uptime_s)
            )
        })
    });
    let logger_ws = system.as_ref().and_then(|s| s.logger_ws);
    let logger_over_cap = logger_ws.is_some_and(|w| w > cfg.logger_cap_mb * MIB);
    let data_ts = system.as_ref().map(|s| s.ts);
    let stale = data_ts.is_some_and(|t| now - t > 3 * interval);

    let present = latest_groups(conn)?;
    let n_procs = latest_procs(conn)?;
    let sparks = hourly_max(conn, now - 48 * 3600)?;
    let typicals = typical_private(conn, since)?;
    let app_list = all_apps(conn)?;
    let apps: HashMap<&str, &AppRecord> = app_list.iter().map(|a| (a.app_key.as_str(), a)).collect();
    let entries_by_app = startup_by_app(conn, Some(&app_list), Some(&present))?;

    let mut keys: Vec<&String> = present.keys().collect();
    keys.sort();
    let cands: Vec<(&String, &AppRecord)> = keys
        .into_iter()
        .filter_map(|k| {
            let rec = *apps.get(k.as_str())?;
            (rec.kind != "protected" && !exclude_keys.contains(k)).then_some((k, rec))
        })
        .collect();

    let autostart = |rec: &AppRecord| -> bool {
        entries_by_app.get(&rec.app_key).is_some_and(|es| {
            es.iter().any(|e| {
                e.enabled
                    && (AUTOSTART_SOURCES.contains(&e.source.as_str())
                        || (e.source == "task" && !rec.microsoft))
            })
        })
    };

    // DUPLICATE: category membership by app label (case-insensitive). Protected
    // products (Defender) have no app row; they count through the tick's markers and
    // never carry the reason themselves.
    let mut dup: HashMap<String, (String, Vec<String>)> = HashMap::new();
    let by_label: HashMap<String, &AppRecord> =
        cands.iter().map(|(_, r)| (r.label.to_lowercase(), *r)).collect();
    let marked: HashSet<String> = latest_markers(conn)?.iter().map(|m| m.to_lowercase()).collect();
    for (cat, members) in &cfg.categories {
        let mut labels: Vec<String> = Vec::new();
        let mut here: Vec<&AppRecord> = Vec::new();
        for m in members {
            let lm = m.to_lowercase();
            if let Some(r) = by_label.get(&lm) {
                here.push(r);
                labels.push(r.label.clone());
            } else if marked.contains(&lm) {
                labels.push(m.clone());
            }
        }
        if labels.len() >= 2 {
            for r in here {
                dup.entry(r.app_key.clone()).or_insert_with(|| (cat.clone(), labels.clone()));
            }
        }
    }

    let mut suggestions: Vec<Suggestion> = Vec::new();
    let mut summaries: Vec<AppSummary> = Vec::new();
    for (key, rec) in &cands {
        let (_, priv_, ws) = present[*key];
        let instance = rec.kind == "instance";
        let n_idle = match rec.last_used {
            None => ticks.len() - ticks.partition_point(|&t| t < rec.first_seen),
            Some(lu) => ticks.len() - ticks.partition_point(|&t| t <= lu),
        } as i64;
        let idle_s = n_idle * interval;
        let (size, idle) = (fmt_size(priv_), fmt_dur(idle_s));
        let large = priv_ >= cfg.large_mb * MIB;
        let is_idle = idle_s as f64 >= cfg.idle_days * 86400.0;
        let mut reasons: Vec<String> = Vec::new();
        let mut codes: Vec<String> = Vec::new();
        let mut add = |code: &str, text: String| {
            codes.push(code.to_string());
            reasons.push(text);
        };

        if large && is_idle {
            add("LARGE_IDLE", format!("Big and idle: {size}, not used in {idle} of laptop use"));
        } else if is_idle && (rec.has_windows_ever || instance) {
            add("IDLE", format!("Not used in {idle} of laptop use, holding {size}"));
        } else if large {
            add("LARGE", format!("Using a lot of memory: {size}"));
        }
        if instance
            && rec.last_active.is_some_and(|la| !recent.is_empty() && la >= recent[0])
            && idle_s >= 3600
        {
            add("POLLING", format!("Still running and busy, but you haven't looked at it in {idle}"));
        }
        let age = now - rec.first_seen;
        if instance && age as f64 >= cfg.long_running_days * 86400.0 {
            add("LONG_RUNNING", format!("Running for {}", fmt_dur(age)));
        }
        let is_auto = autostart(rec);
        if is_auto && observed_days >= cfg.rare_min_observed_days {
            let used_days = used_day_count(conn, key, since)?;
            if used_days <= cfg.rare_max_days_used {
                add(
                    "AUTOSTART_RARE",
                    format!(
                        "Starts with Windows but you used it on only {used_days} of the last \
                         {observed_days} days"
                    ),
                );
            }
        }
        if !rec.has_windows_ever && !instance {
            let note = cfg.notes.get(key.as_str());
            if !rec.services.is_empty() || note.is_some() {
                let desc = note
                    .cloned()
                    .or_else(|| rec.services.iter().map(|s| service_desc(s)).find(|d| !d.is_empty()))
                    .unwrap_or_else(|| format!("{} (no description available)", rec.services.join(", ")));
                add("STANDALONE", format!("Background service with no app you use: {desc}"));
            } else {
                // a tray agent or helper, not a Windows service
                add(
                    "STANDALONE",
                    "Runs in the background with no window you have opened while memwatch was watching"
                        .to_string(),
                );
            }
        }
        if let Some((cat, labels)) = dup.get(key.as_str()) {
            add(
                "DUPLICATE",
                format!("Duplicate: {} {cat} products running ({})", labels.len(), labels.join(", ")),
            );
        }

        summaries.push(AppSummary {
            app_key: key.to_string(),
            label: rec.label.clone(),
            private_bytes: priv_,
            last_used: rec.last_used,
            autostart: is_auto,
            spark: {
                let all: Vec<i64> =
                    sparks.get(key.as_str()).map(|v| v.iter().map(|&(_, m)| m).collect()).unwrap_or_default();
                all[all.len().saturating_sub(48)..].to_vec()
            },
        });
        if codes.is_empty() {
            continue;
        }
        let caution = rec.microsoft.then(|| {
            cfg.notes
                .get(key.as_str())
                .cloned()
                .unwrap_or_else(|| "Part of Windows; turning it off may affect some features.".into())
        });
        let mut startup = entries_by_app.get(key.as_str()).cloned().unwrap_or_default();
        startup.sort_by_key(|e| !e.enabled);
        // Modes come from the service startup entries a disable would change, not from
        // running services: an Automatic-but-stopped service still needs a choice.
        let svc_entries: Vec<&str> = startup
            .iter()
            .filter(|e| e.source == "service" && e.can_disable)
            .map(|e| e.location.as_str())
            .collect();
        let mut modes: Vec<String> = Vec::new();
        if !svc_entries.is_empty() {
            modes.push("manual".into());
            if !svc_entries.iter().any(|s| !dependents(s).is_empty()) {
                modes.push("disabled".into());
            }
        }
        suggestions.push(Suggestion {
            app_key: key.to_string(),
            label: rec.label.clone(),
            kind: rec.kind.clone(),
            private_bytes: priv_,
            working_set: ws,
            typical_private: typicals.get(key.as_str()).copied().unwrap_or(priv_),
            last_used: rec.last_used,
            idle_observed_s: idle_s,
            reasons,
            reason_codes: codes,
            has_windows: rec.has_windows_ever,
            caution,
            limited: rec.limited,
            startup,
            service_modes: modes,
            services: rec.services.clone(),
            n_procs: n_procs.get(key.as_str()).copied().unwrap_or(0),
        });
    }

    suggestions.sort_by_key(|s| {
        (
            s.reason_codes.iter().all(|c| c == "DUPLICATE" || c == "STANDALONE"),
            std::cmp::Reverse(s.private_bytes),
        )
    });
    summaries.sort_by_key(|a| std::cmp::Reverse(a.private_bytes));
    Ok(Report {
        now,
        system,
        observed_hours,
        partial_note,
        reclaimable: suggestions.iter().map(|s| s.private_bytes).sum(),
        suggestions,
        apps: summaries,
        kernel_note,
        uptime_s,
        logger_ws,
        logger_over_cap,
        undo: list_actions(conn, false)?,
        data_ts,
        stale,
    })
}

/// `build_report` with the live service lookups.
pub fn build_report_live(
    conn: &Connection,
    cfg: &Config,
    now: i64,
    exclude_keys: &HashSet<String>,
) -> Result<Report> {
    build_report(conn, cfg, now, exclude_keys, &default_dependents, &default_service_desc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{replace_startup, write_tick};
    use crate::models::{AppGroup, UsageFlags};
    use crate::testutil::*;

    const DAY: i64 = 86400;

    fn none() -> HashSet<String> {
        HashSet::new()
    }
    fn no_deps(_: &str) -> Vec<String> {
        vec![]
    }
    fn no_desc(_: &str) -> String {
        String::new()
    }
    fn report(c: &Connection, cfg: &Config, now: i64) -> Report {
        build_report(c, cfg, now, &none(), &no_deps, &no_desc).unwrap()
    }
    fn report_x(c: &Connection, cfg: &Config, now: i64, ex: &[&str]) -> Report {
        let ex = ex.iter().map(|s| s.to_string()).collect();
        build_report(c, cfg, now, &ex, &no_deps, &no_desc).unwrap()
    }

    fn flags(fg: bool, active: bool, windows: bool) -> UsageFlags {
        UsageFlags { foreground: fg, active, has_windows: windows }
    }
    fn entry(source: &str, enabled: bool, name: &str) -> StartupEntry {
        StartupEntry {
            source: source.into(),
            name: name.into(),
            location: "loc".into(),
            command: "cmd".into(),
            enabled,
            needs_admin: false,
            can_disable: true,
            note: None,
            app_key: Some("suite:app".into()),
        }
    }
    fn svc_entry(name: &str, key: &str) -> StartupEntry {
        StartupEntry {
            source: "service".into(),
            name: name.into(),
            location: name.into(),
            command: "svchost.exe -k x".into(),
            enabled: true,
            needs_admin: true,
            can_disable: true,
            note: None,
            app_key: Some(key.into()),
        }
    }
    fn local_ts(y: i32, m: u32, d: u32, h: u32) -> i64 {
        Local.with_ymd_and_hms(y, m, d, h, 0, 0).unwrap().timestamp()
    }
    fn four_days(c: &Connection, key: &str, microsoft: bool, used_days: i64, days: i64) -> i64 {
        let base = local_ts(2026, 1, 1, 12);
        for d in 0..days {
            tick_with(c, base + d * DAY, key, d < used_days, 50 << 20, true, &|g| g.microsoft = microsoft);
        }
        base + (days - 1) * DAY
    }
    fn kind(k: &'static str) -> impl Fn(&mut AppGroup) {
        move |g| g.kind = k.into()
    }

    #[test]
    fn idle_counts_only_observed_time() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        tick(&c, 0, "suite:discord", true, 200 << 20, true);
        tick(&c, 60, "suite:discord", false, 200 << 20, false);
        tick(&c, 5 * DAY, "suite:discord", false, 200 << 20, false);
        let s = report(&c, &cfg, 5 * DAY);
        assert_eq!(s.apps.iter().map(|a| a.app_key.as_str()).collect::<Vec<_>>(), ["suite:discord"]);
        assert!(s.suggestions.is_empty()); // only 2 minutes observed
        assert_eq!(s.apps[0].last_used, Some(0));
    }

    #[test]
    fn large_idle_sentence() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        seed_with(&c, "emulator:31:1", 3 * 1440, 4 << 30, &kind("instance"));
        let sug = &report(&c, &cfg, 3 * DAY).suggestions[0];
        assert_eq!(sug.reasons[0], "Big and idle: 4.0 GB, not used in 3 days of laptop use");
        assert_eq!(sug.reason_codes[..2], ["LARGE_IDLE", "LONG_RUNNING"]);
        assert_eq!(sug.reasons[1], "Running for 3 days");
    }

    #[test]
    fn partial_note_and_no_history() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        let r = report(&c, &cfg, 0);
        assert!(r.suggestions.is_empty() && r.system.is_none());
        tick(&c, 0, "suite:steam", false, 300 << 20, false);
        assert!(report(&c, &cfg, 0).partial_note.unwrap().starts_with("Based on"));
    }

    #[test]
    fn no_partial_note_after_72_hours() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        seed(&c, "suite:a", 72 * 60, 1 << 20);
        assert_eq!(report(&c, &cfg, 72 * 3600).partial_note, None);
    }

    #[test]
    fn protected_and_excluded_never_suggested() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        seed_with(&c, "protected:windows", 10, 5 << 30, &kind("protected"));
        seed_with(&c, "python:9:1", 10, 5 << 30, &kind("instance"));
        assert!(report_x(&c, &cfg, 600, &["python:9:1"]).suggestions.is_empty());
        let r = report(&c, &cfg, 600);
        assert_eq!(r.apps.iter().map(|a| a.app_key.as_str()).collect::<Vec<_>>(), ["python:9:1"]);
        assert_eq!(r.suggestions[0].app_key, "python:9:1"); // positive control
    }

    fn defender_ticks(c: &Connection, with_zoom: bool, n: i64) {
        for i in 0..n {
            let mut gs: Vec<(AppGroup, UsageFlags)> = vec![];
            let mut add = |k: &str, p: i64, lbl: &str, kind: &str| {
                let mut g = mk_group(k, p << 20);
                g.label = lbl.into();
                g.kind = kind.into();
                gs.push((g, flags(false, false, false)));
            };
            add("suite:reason security", 300, "Reason Security", "suite");
            add("protected:windows", 500, "Windows core", "protected");
            if with_zoom {
                add("suite:zoom", 1900, "Zoom", "suite");
            }
            write_tick(c, &mk_sys(i * 60), &gs, &["Windows Defender".to_string()]).unwrap();
        }
    }

    #[test]
    fn duplicate_antivirus_and_ranking() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        defender_ticks(&c, true, 10);
        let r = report(&c, &cfg, 600);
        let keys: Vec<_> = r.suggestions.iter().map(|s| s.app_key.as_str()).collect();
        assert_eq!(keys, ["suite:zoom", "suite:reason security"]);
        assert_eq!(
            r.suggestions.last().unwrap().reasons.last().unwrap(),
            "Duplicate: 2 antivirus products running (Reason Security, Windows Defender)"
        );
    }

    #[test]
    fn duplicate_antivirus_with_protected_defender() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        defender_ticks(&c, false, 10);
        let r = report(&c, &cfg, 600);
        assert_eq!(r.suggestions.len(), 1);
        let s = &r.suggestions[0];
        assert_eq!(s.app_key, "suite:reason security");
        assert_eq!(s.reason_codes.last().unwrap(), "DUPLICATE");
        assert_eq!(
            s.reasons.last().unwrap(),
            "Duplicate: 2 antivirus products running (Reason Security, Windows Defender)"
        );
    }

    #[test]
    fn no_duplicate_when_defender_marker_absent() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        let mut g = mk_group("suite:reason security", 300 << 20);
        g.label = "Reason Security".into();
        write_tick(&c, &mk_sys(0), &[(g.clone(), flags(false, false, false))], &["Windows Defender".into()])
            .unwrap();
        write_tick(&c, &mk_sys(60), &[(g, flags(false, false, false))], &[]).unwrap();
        let r = report(&c, &cfg, 60);
        assert!(r.suggestions.iter().all(|s| !s.reason_codes.contains(&"DUPLICATE".to_string())));
    }

    #[test]
    fn duplicate_browsers_still_work() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        seed_with(&c, "suite:google chrome", 10, 300 << 20, &|g| g.label = "Google Chrome".into());
        seed_with(&c, "suite:firefox", 10, 200 << 20, &|g| g.label = "Firefox".into());
        let r = report(&c, &cfg, 600);
        let dups: Vec<_> = r.suggestions.iter().filter(|s| s.reason_codes.contains(&"DUPLICATE".into())).collect();
        let keys: HashSet<_> = dups.iter().map(|s| s.app_key.as_str()).collect();
        assert_eq!(keys, HashSet::from(["suite:google chrome", "suite:firefox"]));
        assert_eq!(
            dups[0].reasons.last().unwrap(),
            "Duplicate: 2 browser products running (Google Chrome, Firefox)"
        );
    }

    fn windows_svc(services: &'static [&'static str], microsoft: bool) -> impl Fn(&mut AppGroup) {
        move |g| {
            g.kind = "windows".into();
            g.microsoft = microsoft;
            g.services = services.iter().map(|s| s.to_string()).collect();
        }
    }

    #[test]
    fn service_modes_drop_disabled_with_dependents() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        seed_with(&c, "service:wsearch", 10, 50 << 20, &windows_svc(&["WSearch"], true));
        replace_startup(&c, &[svc_entry("WSearch", "service:wsearch")]).unwrap();
        let dep = |_: &str| vec!["WMPNetworkSvc".to_string()];
        let r = build_report(&c, &cfg, 600, &none(), &dep, &no_desc).unwrap();
        let s = &r.suggestions[0];
        assert_eq!(s.service_modes, ["manual"]);
        assert!(s.caution.as_ref().unwrap().starts_with("Windows Search indexing"));
        let s = &report(&c, &cfg, 600).suggestions[0];
        assert_eq!(s.service_modes, ["manual", "disabled"]);
        assert_eq!(s.reasons, [format!("Background service with no app you use: {}", cfg.notes["service:wsearch"])]);
    }

    #[test]
    fn standalone_uses_service_desc_then_fallback() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        seed_with(&c, "service:foo", 5, 10 << 20, &windows_svc(&["Foo"], false));
        let desc = |_: &str| "Does foo things".to_string();
        let r = build_report(&c, &cfg, 300, &none(), &no_deps, &desc).unwrap();
        assert_eq!(r.suggestions[0].reasons, ["Background service with no app you use: Does foo things"]);
        assert_eq!(r.suggestions[0].caution, None);
        let s = &report(&c, &cfg, 300).suggestions[0];
        assert_eq!(s.reasons, ["Background service with no app you use: Foo (no description available)"]);
    }

    #[test]
    fn windowless_app_without_services_is_not_called_a_service() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        seed_with(&c, "suite:discord", 5, 10 << 20, &|g| g.label = "Discord".into());
        let desc = |_: &str| "unused".to_string();
        let r = build_report(&c, &cfg, 300, &none(), &no_deps, &desc).unwrap();
        assert_eq!(
            r.suggestions[0].reasons,
            ["Runs in the background with no window you have opened while memwatch was watching"]
        );
        assert_eq!(r.suggestions[0].reason_codes, ["STANDALONE"]);
    }

    #[test]
    fn service_modes_empty_without_services() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        seed(&c, "suite:x", 5, 900 << 20);
        assert!(report(&c, &cfg, 300).suggestions[0].service_modes.is_empty());
    }

    #[test]
    fn kernel_note() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        let mut sys = mk_sys(0);
        sys.pool_nonpaged = 1545 << 20;
        write_tick(&c, &sys, &[(mk_group("suite:x", 1), flags(false, false, false))], &[]).unwrap();
        assert!(report(&c, &cfg, 0).kernel_note.unwrap().contains("1.5 GB non-paged"));
    }

    #[test]
    fn no_kernel_note_below_threshold() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        tick(&c, 0, "suite:x", false, 1, false);
        assert_eq!(report(&c, &cfg, 0).kernel_note, None);
    }

    #[test]
    fn never_used_idle_counts_from_first_seen_inclusive() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        for i in 0..3 * 1440 {
            tick(&c, i * 60, "suite:win", false, 100 << 20, true);
        }
        let s = &report(&c, &cfg, 3 * DAY).suggestions[0];
        assert_eq!(s.idle_observed_s, 3 * 1440 * 60);
        assert_eq!(s.reasons, ["Not used in 3 days of laptop use, holding 100 MB"]);
    }

    #[test]
    fn used_idle_counts_ticks_after_last_used() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        tick(&c, 0, "suite:win", true, 100 << 20, true);
        for i in 1..3 * 1440 {
            tick(&c, i * 60, "suite:win", false, 100 << 20, false);
        }
        let s = &report(&c, &cfg, 3 * DAY).suggestions[0];
        assert_eq!(s.idle_observed_s, (3 * 1440 - 1) * 60);
        assert_eq!(s.last_used, Some(0));
    }

    #[test]
    fn large_not_idle() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        seed(&c, "suite:big", 10, 600 << 20);
        let s = &report(&c, &cfg, 600).suggestions[0];
        assert_eq!(s.reasons[0], "Using a lot of memory: 600 MB");
        assert_eq!(s.reason_codes[0], "LARGE");
    }

    #[test]
    fn polling() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        let n = 120;
        for i in 0..n {
            tick_with(&c, i * 60, "python:1:1", false, 50 << 20, false, &kind("instance"));
        }
        let mut g = mk_group("python:1:1", 50 << 20);
        g.kind = "instance".into();
        write_tick(&c, &mk_sys(n * 60), &[(g, flags(false, true, false))], &[]).unwrap();
        let s = &report(&c, &cfg, n * 60).suggestions[0];
        assert_eq!(s.reason_codes, ["POLLING"]);
        assert_eq!(s.reasons[0], "Still running and busy, but you haven't looked at it in 2 hours");
    }

    #[test]
    fn autostart_rare() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        let now = four_days(&c, "suite:app", false, 1, 4);
        replace_startup(&c, &[entry("run", false, "App"), entry("run", true, "B")]).unwrap();
        let r = report(&c, &cfg, now);
        let s = &r.suggestions[0];
        assert_eq!(s.reason_codes, ["AUTOSTART_RARE"]);
        assert_eq!(s.reasons[0], "Starts with Windows but you used it on only 1 of the last 4 days");
        assert_eq!(s.startup.iter().map(|e| e.enabled).collect::<Vec<_>>(), [true, false]);
        assert!(r.apps[0].autostart);
    }

    #[test]
    fn autostart_needs_enabled_entry_and_enough_days() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        let now = four_days(&c, "suite:app", false, 1, 4);
        replace_startup(&c, &[entry("run", false, "App")]).unwrap();
        assert!(report(&c, &cfg, now).suggestions.is_empty());
    }

    #[test]
    fn autostart_needs_min_observed_days() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        let now = four_days(&c, "suite:app", false, 1, 2);
        replace_startup(&c, &[entry("run", true, "App")]).unwrap();
        assert!(report(&c, &cfg, now).suggestions.is_empty());
    }

    #[test]
    fn autostart_not_rare_when_used_often() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        let now = four_days(&c, "suite:app", false, 3, 4);
        replace_startup(&c, &[entry("run", true, "App")]).unwrap();
        assert!(report(&c, &cfg, now).suggestions.is_empty());
    }

    #[test]
    fn microsoft_logon_task_is_not_autostart() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        let now = four_days(&c, "suite:app", true, 1, 4);
        replace_startup(&c, &[entry("task", true, "App")]).unwrap();
        let r = report(&c, &cfg, now);
        assert!(!r.apps[0].autostart && r.suggestions.is_empty());
    }

    #[test]
    fn non_microsoft_task_counts() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        let now = four_days(&c, "suite:app", false, 1, 4);
        replace_startup(&c, &[entry("task", true, "App")]).unwrap();
        assert!(report(&c, &cfg, now).apps[0].autostart);
    }

    #[test]
    fn report_extras() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        let mut sys = mk_sys(0);
        sys.boot_time = -3600;
        sys.logger_ws = Some(60 << 20);
        write_tick(&c, &sys, &[(mk_group("suite:a", 1 << 20), flags(false, false, true))], &[]).unwrap();
        let r = report(&c, &cfg, 0);
        assert_eq!(r.uptime_s, 3600);
        assert!(r.logger_over_cap);
        assert_eq!(r.logger_ws, Some(60 << 20));
        assert_eq!(r.apps[0].spark, [1 << 20]);
        assert!(r.undo.is_empty() && r.system.is_some());
    }

    #[test]
    fn typical_private_is_median() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        for (i, p) in [100i64, 900, 700, 700, 800].iter().enumerate() {
            tick(&c, i as i64 * 3600, "suite:a", false, p << 20, true);
        }
        let s = &report(&c, &cfg, 4 * 3600).suggestions;
        // the thinned median sees one sample per hour here; 700 is the middle value
        assert_eq!(s.iter().find(|s| s.app_key == "suite:a").map(|s| s.typical_private), Some(700 << 20));
    }

    #[test]
    fn formatters() {
        assert_eq!(fmt_size(4 << 30), "4.0 GB");
        assert_eq!(fmt_size(600 << 20), "600 MB");
        assert_eq!(fmt_dur(60), "1 minute");
        assert_eq!(fmt_dur(150), "2 minutes");
        assert_eq!(fmt_dur(3600), "1 hour");
        assert_eq!(fmt_dur(47 * 3600 + 3599), "47 hours");
        assert_eq!(fmt_dur(48 * 3600), "2 days");
        assert_eq!(fmt_dur(86400 * 3 + 5), "3 days");
    }

    #[test]
    fn default_service_desc_never_fails() {
        assert_eq!(default_service_desc("definitely-not-a-service-xyz"), "");
    }

    #[test]
    fn default_dependents_fails_closed() {
        let boom_scm = |_: &str| Err::<Vec<String>, String>("access denied".into());
        let boom_reg = |_: &str| Err::<Vec<String>, _>(std::io::Error::other("denied"));
        assert_eq!(dependents_with("RpcSs", &boom_scm, &boom_reg), ["<unknown>"]);
    }

    #[test]
    fn default_dependents_falls_back_to_registry() {
        let denied = |_: &str| Err::<Vec<String>, String>("access denied".into());
        let reg = |_: &str| Ok::<_, std::io::Error>(vec!["Dep1".to_string()]);
        assert_eq!(dependents_with("X", &denied, &reg), ["Dep1"]);
    }

    #[test]
    fn unknown_dependents_drop_disabled() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        seed_with(&c, "service:foo", 5, 10 << 20, &windows_svc(&["Foo"], false));
        replace_startup(&c, &[svc_entry("Foo", "service:foo")]).unwrap();
        let dep = |_: &str| vec!["<unknown>".to_string()];
        let r = build_report(&c, &cfg, 300, &none(), &dep, &no_desc).unwrap();
        assert_eq!(r.suggestions[0].service_modes, ["manual"]);
    }

    #[test]
    fn default_dependents_live_never_fails() {
        let _ = default_dependents("definitely-not-a-service-xyz");
    }

    #[test]
    fn build_report_is_fast_on_realistic_history() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        let (n_apps, n_ticks) = (130i64, 7 * 1440i64);
        let base = local_ts(2026, 1, 1, 0);
        let ts_list: Vec<i64> = (0..n_ticks).map(|i| base + i * 60).collect();
        c.execute_batch("BEGIN").unwrap();
        for t in &ts_list {
            c.execute(
                "INSERT INTO system VALUES(?,?,?,?,?,?,?,?,?,?)",
                rusqlite::params![t, 16i64 << 30, 8i64 << 30, 10i64 << 30, 24i64 << 30, None::<i64>, 100i64 << 20, 50i64 << 20, 0, None::<i64>],
            )
            .unwrap();
        }
        for a in 0..n_apps {
            let key = format!("suite:app{a}");
            c.execute(
                "INSERT INTO apps VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                rusqlite::params![key, format!("app{a}"), "suite", 0, base, ts_list[ts_list.len() - 1],
                    if a % 3 == 0 { Some(base) } else { None }, None::<i64>, 1, 0, "[]"],
            )
            .unwrap();
            for (i, t) in ts_list.iter().enumerate() {
                c.execute(
                    "INSERT INTO samples VALUES(?,?,?,?,?,?,?)",
                    rusqlite::params![t, key, (50 + a + i as i64 % 7) << 20, 40i64 << 20, 3,
                        (a % 3 == 0 && i % 500 == 0) as i64, 0],
                )
                .unwrap();
            }
        }
        c.execute_batch("COMMIT").unwrap();
        let start = std::time::Instant::now();
        let r = report(&c, &cfg, *ts_list.last().unwrap());
        let elapsed = start.elapsed().as_secs_f64();
        assert_eq!(r.apps.len() as i64, n_apps);
        assert!(!r.suggestions.is_empty());
        assert!(r.apps.iter().all(|a| a.spark.len() <= 48) && !r.apps[0].spark.is_empty());
        assert!(elapsed < 2.0, "{elapsed}s");
    }

    #[test]
    fn stale_data_flag() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        tick(&c, 1000, "suite:a", false, 600 << 20, false);
        let r = report(&c, &cfg, 1000 + 3 * cfg.sample_interval_s);
        assert_eq!((r.data_ts, r.stale), (Some(1000), false));
        let r = report(&c, &cfg, 1000 + 3 * cfg.sample_interval_s + 1);
        assert_eq!((r.data_ts, r.stale), (Some(1000), true));
    }

    #[test]
    fn no_data_is_not_stale() {
        let (_d, c) = mem_conn();
        let r = report(&c, &mk_cfg(), 1_000_000_000);
        assert_eq!((r.data_ts, r.stale), (None, false));
    }

    #[test]
    fn shared_svchost_startup_entry_maps_to_group() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        let now = four_days(&c, "service:bits+wuauserv", false, 1, 4);
        c.execute("UPDATE apps SET services_json = ?, has_windows_ever = 0", ["[\"BITS\", \"wuauserv\"]"]).unwrap();
        let mut e = svc_entry("Background Intelligent Transfer", "service:bits");
        e.location = "BITS".into();
        replace_startup(&c, &[e]).unwrap();
        let dep = |_: &str| vec![];
        let r = build_report(&c, &cfg, now, &none(), &dep, &no_desc).unwrap();
        let s = &r.suggestions[0];
        assert_eq!(s.app_key, "service:bits+wuauserv");
        assert_eq!(s.startup.iter().map(|x| x.location.as_str()).collect::<Vec<_>>(), ["BITS"]);
        assert!(r.apps[0].autostart);
        let m = startup_by_app(&c, None, None).unwrap();
        assert_eq!(m["service:bits+wuauserv"][0].location, "BITS");
    }

    #[test]
    fn service_modes_come_from_service_startup_entries() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        seed_with(&c, "suite:tobii", 10, 600 << 20, &|g| g.label = "Tobii".into());
        let mut e = svc_entry("Tobii Service", "suite:tobii");
        e.location = "TobiiSvc".into();
        replace_startup(&c, &[e]).unwrap();
        let asked = std::cell::RefCell::new(vec![]);
        let dep = |n: &str| {
            asked.borrow_mut().push(n.to_string());
            vec![]
        };
        let r = build_report(&c, &cfg, 600, &none(), &dep, &no_desc).unwrap();
        assert_eq!(r.suggestions[0].service_modes, ["manual", "disabled"]);
        assert_eq!(*asked.borrow(), ["TobiiSvc"]);
        let dep2 = |_: &str| vec!["Dep".to_string()];
        let r = build_report(&c, &cfg, 600, &none(), &dep2, &no_desc).unwrap();
        assert_eq!(r.suggestions[0].service_modes, ["manual"]);
    }

    #[test]
    fn running_services_without_service_entries_get_no_modes() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        seed_with(&c, "suite:x", 5, 900 << 20, &|g| g.services = vec!["XSvc".into()]);
        assert!(report(&c, &cfg, 300).suggestions[0].service_modes.is_empty());
    }

    #[test]
    fn suggestion_parts() {
        let (_d, c) = mem_conn();
        let cfg = mk_cfg();
        seed_with(&c, "suite:x", 5, 900 << 20, &|g| g.services = vec!["XSvc".into()]);
        let s = &report(&c, &cfg, 300).suggestions[0];
        assert_eq!(s.services, ["XSvc"]);
        assert_eq!(s.n_procs, 1);
    }
}
