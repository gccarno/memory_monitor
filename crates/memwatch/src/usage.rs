//! Per-app usage flags: foreground, active (CPU/IO delta) and has-windows.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::config::Config;
use crate::models::{AppGroup, ProcInfo, UsageFlags};

/// (pid, create_time bits): create times are never NaN, so bit equality is value equality.
pub type ProcKey = (u32, u64);

pub fn pkey(pid: u32, create_time: f64) -> ProcKey {
    (pid, create_time.to_bits())
}

/// PIDs above `pid`, guarding against cycles and PID reuse.
fn ancestors(pid: u32, by_pid: &HashMap<u32, &ProcInfo>) -> HashSet<u32> {
    let mut out = HashSet::new();
    let mut child = by_pid.get(&pid).copied();
    while let Some(c) = child {
        let Some(parent) = by_pid.get(&c.ppid).copied() else { break };
        if out.contains(&parent.pid) || parent.pid == pid || parent.create_time > c.create_time {
            break;
        }
        out.insert(parent.pid);
        child = Some(parent);
    }
    out
}

pub fn mark_usage(
    groups: &BTreeMap<String, AppGroup>,
    procs: &[ProcInfo],
    prev: &HashMap<ProcKey, (f64, i64)>,
    fg_pid: Option<u32>,
    win_pids: &HashSet<u32>,
    user_away: bool,
    cfg: &Config,
) -> BTreeMap<String, UsageFlags> {
    let by_pid: HashMap<u32, &ProcInfo> = procs.iter().map(|p| (p.pid, p)).collect();
    let by_key: HashMap<ProcKey, &ProcInfo> =
        procs.iter().map(|p| (pkey(p.pid, p.create_time), p)).collect();
    let mut fg_keys: HashSet<&str> = HashSet::new();
    if let (Some(fg), false) = (fg_pid, user_away) {
        for (key, g) in groups {
            if g.pids.iter().any(|(pid, _)| *pid == fg) {
                fg_keys.insert(key);
            }
        }
        if let Some(p) = by_pid.get(&fg) {
            if cfg.terminal_names.contains(&p.name.to_lowercase()) {
                for (key, g) in groups {
                    if g.kind == "instance"
                        && g.pids.first().is_some_and(|(first, _)| ancestors(*first, &by_pid).contains(&fg))
                    {
                        fg_keys.insert(key);
                    }
                }
            }
        }
    }

    let mut flags = BTreeMap::new();
    for (key, g) in groups {
        let mut cpu_d = 0.0_f64;
        let mut io_d = 0_i64;
        for (pid, ct) in &g.pids {
            let k = pkey(*pid, *ct);
            let (Some(p), Some(old)) = (by_key.get(&k), prev.get(&k)) else { continue };
            if let Some(cpu) = p.cpu_s {
                cpu_d += (cpu - old.0).max(0.0);
            }
            if let Some(io) = p.io_bytes {
                io_d += (io - old.1).max(0);
            }
        }
        flags.insert(
            key.clone(),
            UsageFlags {
                foreground: fg_keys.contains(key.as_str()),
                active: cpu_d >= cfg.cpu_active_s || io_d >= cfg.io_active_bytes,
                has_windows: g.pids.iter().any(|(pid, _)| win_pids.contains(pid)),
            },
        );
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grouping::group_processes;
    use crate::testutil::mkproc;

    const CLAUDE: &str = r"C:\u\.local\bin\claude.exe";
    const STEAM: &str = r"C:\Program Files (x86)\Steam\steam.exe";

    fn term_procs() -> Vec<ProcInfo> {
        vec![
            mkproc(60, 1, "mintty.exe", Some("x")),
            mkproc(61, 60, "bash.exe", Some("x")),
            mkproc(62, 61, "claude.exe", Some(CLAUDE)),
            mkproc(70, 1, "mintty.exe", Some("x")),
            mkproc(72, 70, "claude.exe", Some(CLAUDE)),
        ]
    }

    fn set(pids: &[u32]) -> HashSet<u32> {
        pids.iter().copied().collect()
    }

    fn run(
        procs: &[ProcInfo],
        prev: &HashMap<ProcKey, (f64, i64)>,
        fg: Option<u32>,
        wins: &HashSet<u32>,
        away: bool,
    ) -> BTreeMap<String, UsageFlags> {
        let cfg = Config::default();
        let g = group_processes(procs, &HashMap::new(), &cfg);
        mark_usage(&g, procs, prev, fg, wins, away, &cfg)
    }

    #[test]
    fn terminal_focus_credits_cli_sessions_inside_it() {
        let procs = term_procs();
        let f = run(&procs, &HashMap::new(), Some(60), &set(&[60, 70]), false);
        assert!(f["claude-cli:62:1"].foreground && !f["claude-cli:72:1"].foreground);
    }

    #[test]
    fn user_away_means_no_foreground() {
        let procs = term_procs();
        let f = run(&procs, &HashMap::new(), Some(60), &set(&[60, 70]), true);
        assert!(!f.values().any(|x| x.foreground));
    }

    #[test]
    fn foreground_group_containing_pid() {
        let p = vec![mkproc(80, 1, "steam.exe", Some(STEAM))];
        let f = run(&p, &HashMap::new(), Some(80), &set(&[80]), false);
        assert!(f["suite:steam"].foreground && f["suite:steam"].has_windows);
    }

    #[test]
    fn active_by_cpu_delta() {
        let mut p = mkproc(80, 1, "steam.exe", Some(STEAM));
        p.cpu_s = Some(10.6);
        let prev = HashMap::from([(pkey(80, 1.0), (10.0, 0))]);
        assert!(run(&[p], &prev, None, &set(&[]), false)["suite:steam"].active);
    }

    #[test]
    fn active_by_io_delta_and_new_process_is_idle() {
        let mut p = mkproc(80, 1, "steam.exe", Some(STEAM));
        p.io_bytes = Some(5_000_000);
        let prev = HashMap::from([(pkey(80, 1.0), (0.0, 0))]);
        assert!(run(std::slice::from_ref(&p), &prev, None, &set(&[]), false)["suite:steam"].active);
        assert!(!run(&[p], &HashMap::new(), None, &set(&[]), false)["suite:steam"].active);
    }

    #[test]
    fn limited_none_values_are_delta_zero() {
        let mut p = mkproc(80, 1, "steam.exe", Some(STEAM));
        p.cpu_s = None;
        p.io_bytes = None;
        p.limited = true;
        let prev = HashMap::from([(pkey(80, 1.0), (0.0, 0))]);
        assert!(!run(&[p], &prev, None, &set(&[]), false)["suite:steam"].active);
    }

    #[test]
    fn ancestor_cycle_and_pid_reuse_are_guarded() {
        let mut m90 = mkproc(90, 1, "mintty.exe", Some("x"));
        m90.create_time = 50.0;
        let mut c92 = mkproc(92, 90, "claude.exe", Some(CLAUDE));
        c92.create_time = 5.0;
        let procs = vec![
            mkproc(60, 61, "mintty.exe", Some("x")),
            mkproc(61, 60, "bash.exe", Some("x")),
            mkproc(62, 61, "claude.exe", Some(CLAUDE)),
            // parent created later than child: PID reuse, must not be credited
            m90,
            c92,
        ];
        let f = run(&procs, &HashMap::new(), Some(90), &set(&[]), false);
        assert!(!f["claude-cli:92:5"].foreground);
        let f = run(&procs, &HashMap::new(), Some(60), &set(&[]), false);
        assert!(f["claude-cli:62:1"].foreground);
    }
}
