//! Recognising memwatch's own processes, so actions and the report never touch them.

use std::collections::{HashMap, HashSet};

use crate::models::ProcInfo;

/// True for any `python -m memwatch[...]` process (the Python build's logger, report,
/// runner). Kept so a still-running Python install is recognised during the migration.
pub fn is_memwatch_cmdline(cmdline: &[String]) -> bool {
    let args: Vec<String> = cmdline.iter().map(|a| a.to_lowercase()).collect();
    for (i, a) in args.iter().enumerate() {
        let module = if a == "-m" {
            args.get(i + 1).map(String::as_str).unwrap_or("")
        } else {
            a.strip_prefix("-m").unwrap_or_default() // "-mmemwatch"
        };
        if module == "memwatch" || module.starts_with("memwatch.") {
            return true;
        }
    }
    false
}

/// A memwatch process of either build: the Rust exes by image name, or the Python module.
pub fn is_memwatch_proc(p: &ProcInfo) -> bool {
    let image = p
        .exe
        .as_deref()
        .and_then(|e| e.rsplit(['\\', '/']).next())
        .unwrap_or(&p.name)
        .to_lowercase();
    image == "memwatch.exe"
        || image == "memwatchw.exe"
        || p.cmdline.as_deref().is_some_and(is_memwatch_cmdline)
}

/// `me`, its launching tree (ancestors) and everything it started (descendants, such as
/// a browser opened for the report).
pub fn own_pids_in(procs: &[ProcInfo], me: u32) -> HashSet<u32> {
    let parent: HashMap<u32, u32> = procs.iter().map(|p| (p.pid, p.ppid)).collect();
    let mut kids: HashMap<u32, Vec<u32>> = HashMap::new();
    for p in procs {
        kids.entry(p.ppid).or_default().push(p.pid);
    }
    let mut mine = HashSet::from([me]);
    let mut cur = me;
    while let Some(&pp) = parent.get(&cur) {
        if !parent.contains_key(&pp) || !mine.insert(pp) {
            break;
        }
        cur = pp;
    }
    let mut stack = vec![me];
    while let Some(pid) = stack.pop() {
        for &k in kids.get(&pid).into_iter().flatten() {
            if mine.insert(k) {
                stack.push(k);
            }
        }
    }
    mine
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::mkproc;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn python_module_forms() {
        assert!(is_memwatch_cmdline(&s(&["python.exe", "-m", "memwatch", "log"])));
        assert!(is_memwatch_cmdline(&s(&["python.exe", "-mmemwatch"])));
        assert!(is_memwatch_cmdline(&s(&["python.exe", "-m", "MemWatch.cli"])));
        assert!(!is_memwatch_cmdline(&s(&["python.exe", "-m", "memwatcher"])));
        assert!(!is_memwatch_cmdline(&s(&["python.exe", "memwatch.py"])));
        assert!(!is_memwatch_cmdline(&[]));
    }

    #[test]
    fn rust_exes_are_recognised_by_image() {
        let p = mkproc(1, 0, "memwatchw.exe", Some(r"C:\x\Programs\memwatch\memwatchw.exe"));
        assert!(is_memwatch_proc(&p));
        assert!(is_memwatch_proc(&mkproc(2, 0, "MEMWATCH.EXE", None)));
        assert!(!is_memwatch_proc(&mkproc(3, 0, "memwatch-helper.exe", Some(r"C:\memwatch\other.exe"))));
    }

    #[test]
    fn own_pids_include_ancestors_and_descendants() {
        let procs = vec![
            mkproc(10, 1, "grand.exe", None),
            mkproc(20, 10, "me.exe", None),
            mkproc(30, 20, "child.exe", None),
            mkproc(31, 30, "grandchild.exe", None),
            mkproc(40, 1, "other.exe", None),
        ];
        let got = own_pids_in(&procs, 20);
        assert_eq!(got, HashSet::from([10, 20, 30, 31]));
    }
}
