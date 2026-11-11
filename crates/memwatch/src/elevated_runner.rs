//! The only code memwatch runs as administrator.
//!
//! Started through UAC as `memwatchw.exe elevated-run <ops_b64> <out.json>`. The ops
//! arrive as base64url-encoded JSON **on the command line**, which UAC fixes at approval
//! time, so no user-writable file can change what runs. Only ops on a fixed whitelist run,
//! after strict validation; anything else is answered `{"ok": false, "error": "rejected"}`
//! and never runs. Every op always gets an answer. Results go to `out.json` in memwatch's
//! data dir: a forged result file can only misreport what happened, never cause anything to
//! execute. No shell is ever used.

use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use serde_json::{json, Map, Value};
use winreg::enums::*;
use winreg::{RegKey, RegValue};

use crate::config::Config;
use crate::selfid::is_memwatch_proc;
use crate::{startup, winctl};

pub const MAX_OPS: usize = 64;
/// Encoded ops; well under the 32767-character command-line limit.
pub const MAX_ARG_LEN: usize = 30_000;
/// Finish before the caller stops waiting (120 s).
pub const BUDGET_S: f64 = 100.0;
const STARTS: [&str; 4] = ["demand", "disabled", "auto", "delayed-auto"];
const CT_TOLERANCE: f64 = 1e-3;

fn allowed_keys(op: &str) -> Option<&'static [&'static str]> {
    Some(match op {
        "kill" => &["pid", "create_time"],
        "stop_service" => &["name"],
        "set_service_start" => &["name", "start"],
        "set_approved" => &["hive", "subkey", "value", "data_hex"],
        "set_task" => &["name", "enabled"],
        _ => return None,
    })
}

pub fn encode_ops(ops: &[Value]) -> String {
    URL_SAFE.encode(serde_json::to_vec(ops).unwrap_or_default())
}

/// The op list from a command-line argument, or None when it is unusable.
pub fn decode_ops(arg: &str) -> Option<Vec<Value>> {
    if arg.is_empty() || arg.len() > MAX_ARG_LEN {
        return None;
    }
    let raw = URL_SAFE.decode(arg.as_bytes()).ok()?;
    match serde_json::from_slice::<Value>(&raw).ok()? {
        Value::Array(v) => Some(v),
        _ => None,
    }
}

// ---- validation ------------------------------------------------------------

/// Python's `str.isprintable` for the cases that matter: no control, format or
/// separator characters other than a plain space.
fn printable(s: &str) -> bool {
    s.chars().all(|c| c == ' ' || (!c.is_control() && !c.is_whitespace() && !is_format(c)))
}

fn is_format(c: char) -> bool {
    matches!(c, '\u{ad}' | '\u{600}'..='\u{605}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{2064}' | '\u{feff}' | '\u{e000}'..='\u{f8ff}')
}

fn text(v: Option<&Value>, max_len: usize) -> Option<&str> {
    let s = v?.as_str()?;
    let n = s.chars().count();
    (n > 0 && n <= max_len && printable(s)).then_some(s)
}

fn service_name(v: Option<&Value>) -> Option<&str> {
    text(v, 256).filter(|s| !s.contains('\\') && !s.contains('/'))
}

fn hex_ok(v: &Value) -> bool {
    match v {
        Value::Null => true, // set_approved with null data deletes the value
        Value::String(s) => !s.is_empty() && s.len() % 2 == 0 && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_hexdigit()),
        _ => false,
    }
}

fn task_name_ok(v: Option<&Value>) -> bool {
    let Some(s) = text(v, 512) else { return false };
    if !s.starts_with('\\') || s.contains('"') || s.contains('/') || s.contains("\\\\") {
        return false;
    }
    if s.split('\\').any(|part| part == "..") {
        return false;
    }
    !s.to_lowercase().starts_with("\\microsoft\\windows\\") // Windows' own tasks
}

/// Strict whitelist check. Never panics: anything unexpected is a rejection.
pub fn validate(op: &Value) -> bool {
    let Some(map) = op.as_object() else { return false };
    let Some(name) = map.get("op").and_then(Value::as_str) else { return false };
    let Some(keys) = allowed_keys(name) else { return false };
    if map.len() != keys.len() + 1 || !keys.iter().all(|k| map.contains_key(*k)) {
        return false;
    }
    match name {
        "kill" => {
            let pid_ok = map["pid"].as_u64().is_some_and(|p| p > 4 && p <= u64::from(u32::MAX));
            let ct_ok = matches!(&map["create_time"], Value::Number(n) if n.as_f64().is_some_and(|f| f.is_finite() && f > 0.0));
            pid_ok && ct_ok
        }
        "stop_service" => service_name(map.get("name")).is_some(),
        "set_service_start" => {
            service_name(map.get("name")).is_some() && map["start"].as_str().is_some_and(|s| STARTS.contains(&s))
        }
        "set_approved" => {
            map["hive"].as_str() == Some("HKLM")
                && map["subkey"].as_str().is_some_and(|s| startup::approved_paths().iter().any(|p| p == s))
                && text(map.get("value"), 260).is_some()
                && hex_ok(&map["data_hex"])
        }
        "set_task" => task_name_ok(map.get("name")) && map["enabled"].is_boolean(),
        _ => false,
    }
}

// ---- execution -------------------------------------------------------------

fn left(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn kill(pid: u32, create_time: f64, deadline: Instant) -> Result<(), String> {
    let cfg = Config::default(); // built-in lists only; config.toml can only extend them
    let procs = crate::probe::snapshot_processes();
    let p = procs
        .iter()
        .find(|p| p.pid == pid)
        .ok_or_else(|| format!("process {pid} does not exist"))?;
    if (p.create_time - create_time).abs() > CT_TOLERANCE {
        return Err("process changed since it was checked (pid reused)".into());
    }
    let low = p.name.to_lowercase();
    if pid == std::process::id() || cfg.protected_names.contains(&low) || low == "svchost.exe" {
        return Err(format!("{} is never stopped", p.name));
    }
    if is_memwatch_proc(p) {
        return Err("memwatch will not stop itself".into());
    }
    match winctl::terminate(pid) {
        winctl::Term::Done | winctl::Term::Gone => {}
        winctl::Term::Denied => return Err("access is denied".into()),
        winctl::Term::Failed(e) => return Err(e),
    }
    let wait = left(deadline).min(Duration::from_secs(5));
    if winctl::wait_gone(&[(pid, create_time)], wait).is_empty() {
        Ok(())
    } else {
        Err(format!("pid {pid} did not exit"))
    }
}

fn service_guard(name: &str) -> Result<(), String> {
    if Config::default().protected_services.contains(&name.to_lowercase()) {
        return Err(format!("{name} is a Windows core service"));
    }
    Ok(())
}

fn set_approved(subkey: &str, value: &str, data_hex: Option<&str>) -> Result<(), String> {
    let (k, _) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .create_subkey_with_flags(subkey, KEY_SET_VALUE | KEY_WOW64_64KEY)
        .map_err(|e| e.to_string())?;
    match data_hex {
        None => match k.delete_value(value) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        },
        Some(h) => {
            let bytes = startup::hex_decode(h).ok_or("bad hex")?;
            k.set_raw_value(value, &RegValue { bytes, vtype: REG_BINARY }).map_err(|e| e.to_string())
        }
    }
}

/// `%SystemRoot%\System32\schtasks.exe`, from the system directory, never from PATH.
pub fn schtasks_path() -> Result<std::path::PathBuf, String> {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if n == 0 || n >= buf.len() {
        return Err("cannot find the system directory".into());
    }
    let exe = std::path::PathBuf::from(String::from_utf16_lossy(&buf[..n])).join("schtasks.exe");
    if exe.is_file() {
        Ok(exe)
    } else {
        Err(format!("{} not found", exe.display()))
    }
}

fn set_task(name: &str, enabled: bool, deadline: Instant) -> Result<(), String> {
    let mut child = Command::new(schtasks_path()?)
        .args(["/Change", "/TN", name, if enabled { "/ENABLE" } else { "/DISABLE" }])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .spawn()
        .map_err(|e| e.to_string())?;
    let until = Instant::now() + left(deadline).min(Duration::from_secs(60)).max(Duration::from_secs(1));
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            break;
        }
        if Instant::now() >= until {
            let _ = child.kill();
            return Err("schtasks timed out".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        return Ok(());
    }
    let msg = String::from_utf8_lossy(if out.stderr.is_empty() { &out.stdout } else { &out.stderr }).trim().to_string();
    Err(if msg.is_empty() { format!("schtasks exit {}", out.status.code().unwrap_or(-1)) } else { msg })
}

fn execute(op: &Map<String, Value>, deadline: Instant) -> Result<(), String> {
    let s = |k: &str| op[k].as_str().unwrap_or_default();
    match s("op") {
        "kill" => kill(op["pid"].as_u64().unwrap_or(0) as u32, op["create_time"].as_f64().unwrap_or(0.0), deadline),
        "stop_service" => {
            service_guard(s("name"))?;
            winctl::stop_service(s("name"), left(deadline).min(Duration::from_secs(30)))
        }
        "set_service_start" => {
            service_guard(s("name"))?;
            winctl::set_service_start(s("name"), s("start"))
        }
        "set_approved" => set_approved(s("subkey"), s("value"), op["data_hex"].as_str()),
        "set_task" => set_task(s("name"), op["enabled"].as_bool().unwrap_or(false), deadline),
        _ => Err("unknown op".into()), // unreachable after validate()
    }
}

fn rejected() -> Value {
    json!({"ok": false, "error": "rejected"})
}

pub fn run_ops(ops: &[Value], budget_s: f64) -> Vec<Value> {
    run_ops_with(ops, budget_s, &execute)
}

type Exec<'a> = &'a dyn Fn(&Map<String, Value>, Instant) -> Result<(), String>;

/// `exec` is replaceable so tests can run the whole pipeline without touching the system.
fn run_ops_with(
    ops: &[Value],
    budget_s: f64,
    exec: Exec,
) -> Vec<Value> {
    if ops.len() > MAX_OPS {
        return ops.iter().map(|_| rejected()).collect();
    }
    let deadline = Instant::now() + Duration::from_secs_f64(budget_s.max(0.0));
    ops.iter()
        .map(|op| {
            if !validate(op) {
                return rejected();
            }
            if left(deadline).is_zero() {
                return json!({"ok": false, "error": "out of time; not attempted"});
            }
            let map = op.as_object().expect("validated");
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| exec(map, deadline))) {
                Ok(Ok(())) => json!({"ok": true, "error": null}),
                Ok(Err(e)) => json!({"ok": false, "error": e.chars().take(300).collect::<String>()}),
                Err(_) => json!({"ok": false, "error": "internal error"}),
            }
        })
        .collect()
}

/// The only result path the runner will write: `elev-<32 hex>-out.json`, as `elevate` makes it.
fn out_name_ok(p: &std::path::Path) -> bool {
    p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
        n.strip_prefix("elev-")
            .and_then(|r| r.strip_suffix("-out.json"))
            .is_some_and(|h| h.len() == 32 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    })
}

/// Write the results without following links: this process is elevated and the folder is
/// user-writable. The name must match, the parent must not be a reparse point, and the file
/// is created new (an existing file or link there makes it fail) without following reparse points.
fn write_results(out: &str, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const REPARSE: u32 = 0x400; // FILE_ATTRIBUTE_REPARSE_POINT
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let path = std::path::Path::new(out);
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, m.to_string());
    if !out_name_ok(path) {
        return Err(bad("unexpected result file name"));
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).ok_or_else(|| bad("no directory"))?;
    if std::fs::symlink_metadata(parent)?.file_attributes() & REPARSE != 0 {
        return Err(bad("result directory is a link"));
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(OPEN_REPARSE_POINT)
        .open(path)?;
    f.write_all(data)
}

/// `elevated-run <ops_b64> <out.json>`; returns the process exit code.
pub fn main(args: &[String]) -> i32 {
    let [arg, out] = args else { return 2 };
    let Some(ops) = decode_ops(arg) else { return 2 };
    let results = run_ops(&ops, BUDGET_S);
    match write_results(out, &serde_json::to_vec(&results).unwrap_or_default()) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn run_key() -> String {
        startup::approved_path("run").unwrap()
    }

    fn bad_ops() -> Vec<Value> {
        let run = run_key();
        vec![
            json!("not a dict"),
            Value::Null,
            json!([1, 2]),
            json!({"pid": 5, "create_time": 1.0}),
            json!({"op": ["kill"], "pid": 1234, "create_time": 1.0}),
            json!({"op": "kill", "pid": 1234}),
            json!({"op": "kill", "pid": true, "create_time": 1.0}),
            json!({"op": "kill", "pid": "1234", "create_time": 1.0}),
            json!({"op": "kill", "pid": 1234.0, "create_time": 1.0}),
            json!({"op": "kill", "pid": 4, "create_time": 1.0}),
            json!({"op": "kill", "pid": 0, "create_time": 1.0}),
            json!({"op": "kill", "pid": 1234, "create_time": "1.0"}),
            json!({"op": "kill", "pid": 1234, "create_time": true}),
            json!({"op": "kill", "pid": 1234, "create_time": [1.0]}),
            json!({"op": "kill", "pid": 1234, "create_time": 0}),
            json!({"op": "kill", "pid": 1234, "create_time": 1.0, "x": 1}),
            json!({"op": "format_c"}),
            json!({"op": "stop_service", "name": ""}),
            json!({"op": "stop_service", "name": "a\\b"}),
            json!({"op": "stop_service", "name": 7}),
            json!({"op": "stop_service", "name": ["Foo"]}),
            json!({"op": "stop_service", "name": "Foo\u{0}"}),
            json!({"op": "set_service_start", "name": "Foo", "start": "boot"}),
            json!({"op": "set_service_start", "name": "Foo", "start": "manual"}),
            json!({"op": "set_service_start", "name": "Foo", "start": []}),
            json!({"op": "set_service_start", "name": "Foo", "start": {"auto": 1}}),
            json!({"op": "set_service_start", "name": "Foo", "start": null}),
            json!({"op": "set_service_start", "name": "Foo", "start": "delayed"}),
            json!({"op": "set_service_start", "name": "Foo", "start": "Delayed-Auto"}),
            json!({"op": "set_service_start", "name": "Foo", "start": "system"}),
            json!({"op": "set_approved", "hive": "HKCU", "subkey": run, "value": "X", "data_hex": "02"}),
            json!({"op": "set_approved", "hive": ["HKLM"], "subkey": run, "value": "X", "data_hex": "02"}),
            json!({"op": "set_approved", "hive": "HKLM", "subkey": {}, "value": "X", "data_hex": "02"}),
            json!({"op": "set_approved", "hive": "HKLM", "subkey": [run], "value": "X", "data_hex": "02"}),
            json!({"op": "set_approved", "hive": "HKLM", "subkey": r"Software\Microsoft\Windows\CurrentVersion\Run",
                   "value": "X", "data_hex": "02"}),
            json!({"op": "set_approved", "hive": "HKLM", "subkey": run, "value": "", "data_hex": "02"}),
            json!({"op": "set_approved", "hive": "HKLM", "subkey": run, "value": null, "data_hex": "02"}),
            json!({"op": "set_approved", "hive": "HKLM", "subkey": run, "value": "X", "data_hex": "0"}),
            json!({"op": "set_approved", "hive": "HKLM", "subkey": run, "value": "X", "data_hex": "zz"}),
            json!({"op": "set_approved", "hive": "HKLM", "subkey": run, "value": "X", "data_hex": ""}),
            json!({"op": "set_approved", "hive": "HKLM", "subkey": run, "value": "X", "data_hex": 2}),
            json!({"op": "set_approved", "hive": "HKLM", "subkey": run, "value": "X", "data_hex": ["02"]}),
            json!({"op": "set_task", "name": "\\Foo", "enabled": "no"}),
            json!({"op": "set_task", "name": "\\Foo", "enabled": 0}),
            json!({"op": "set_task", "name": "\\Foo", "enabled": null}),
            json!({"op": "set_task", "name": "\\Foo\\\" /DELETE \\\"x", "enabled": false}),
            json!({"op": "set_task", "name": "Foo", "enabled": false}),
            json!({"op": "set_task", "name": "\\Foo\n", "enabled": false}),
            json!({"op": "set_task", "name": ["\\Foo"], "enabled": false}),
            json!({"op": "set_task", "name": "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", "enabled": false}),
            json!({"op": "set_task", "name": "\\MICROSOFT\\windows\\UpdateOrchestrator\\Reboot", "enabled": false}),
            json!({"op": "set_task", "name": "\\\\Microsoft\\Windows\\X", "enabled": false}),
            json!({"op": "set_task", "name": "\\Vendor\\..\\Microsoft\\Windows\\X", "enabled": false}),
            json!({"op": "set_task", "name": "/Microsoft/Windows/X", "enabled": false}),
        ]
    }

    #[test]
    fn rejects_malformed_ops() {
        for op in bad_ops() {
            assert!(!validate(&op), "should be rejected: {op}");
        }
        let ran = RefCell::new(0);
        let out = run_ops_with(&bad_ops(), 5.0, &|_, _| {
            *ran.borrow_mut() += 1;
            Ok(())
        });
        assert_eq!(*ran.borrow(), 0, "nothing invalid may execute");
        assert!(out.iter().all(|r| *r == rejected()));
        assert_eq!(out.len(), bad_ops().len());
    }

    #[test]
    fn accepts_well_formed_ops() {
        let mut good = vec![
            json!({"op": "kill", "pid": 1234, "create_time": 1.5}),
            json!({"op": "kill", "pid": 1234, "create_time": 2}),
            json!({"op": "stop_service", "name": "Tobii Service"}),
            json!({"op": "set_approved", "hive": "HKLM", "subkey": run_key(), "value": "X", "data_hex": null}),
            json!({"op": "set_task", "name": "\\Vendor\\Updater Logon", "enabled": true}),
            json!({"op": "set_task", "name": "\\Microsoft\\Office\\Office Feature Updates", "enabled": false}),
        ];
        for s in STARTS {
            good.push(json!({"op": "set_service_start", "name": "Foo", "start": s}));
        }
        for sk in startup::approved_paths() {
            good.push(json!({"op": "set_approved", "hive": "HKLM", "subkey": sk, "value": "X",
                             "data_hex": format!("02{}", "00".repeat(11))}));
        }
        for op in &good {
            assert!(validate(op), "should be accepted: {op}");
        }
    }

    #[test]
    fn too_many_ops_are_all_rejected() {
        let ops = vec![json!({"op": "stop_service", "name": "Foo"}); MAX_OPS + 1];
        let out = run_ops_with(&ops, 5.0, &|_, _| panic!("must not run"));
        assert_eq!(out, vec![rejected(); ops.len()]);
    }

    #[test]
    fn out_of_budget_does_not_execute() {
        let ops = vec![json!({"op": "kill", "pid": 1234, "create_time": 1.0})];
        let out = run_ops_with(&ops, 0.0, &|_, _| panic!("must not run"));
        assert_eq!(out[0]["ok"], false);
        assert!(out[0]["error"].as_str().unwrap().contains("time"));
    }

    #[test]
    fn each_op_answers_for_itself() {
        let ops = vec![
            json!({"op": "stop_service", "name": "Ok"}),
            json!({"op": "stop_service", "name": "Fails"}),
            json!({"op": "stop_service", "name": "Panics"}),
        ];
        let out = run_ops_with(&ops, 5.0, &|op, _| match op["name"].as_str().unwrap() {
            "Ok" => Ok(()),
            "Fails" => Err("nope".into()),
            _ => panic!("boom"),
        });
        assert_eq!(out[0], json!({"ok": true, "error": null}));
        assert_eq!(out[1], json!({"ok": false, "error": "nope"}));
        assert_eq!(out[2]["ok"], false);
    }

    #[test]
    fn encode_decode_round_trip_and_bad_arguments() {
        let ops = vec![json!({"op": "x"})];
        assert_eq!(decode_ops(&encode_ops(&ops)), Some(ops));
        assert_eq!(decode_ops(&encode_ops(&[])), Some(vec![]));
        assert!(decode_ops("").is_none());
        assert!(decode_ops("!!not base64!!").is_none());
        assert!(decode_ops(&URL_SAFE.encode(br#"{"op": "kill"}"#)).is_none()); // not a list
        assert!(decode_ops(&encode_ops(&vec![json!({"op": "nope"}); 5000])).is_none()); // too long
    }

    #[test]
    fn main_writes_results_and_refuses_bad_input() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join(format!("elev-{}-out.json", "a".repeat(32)));
        let arg = encode_ops(&[json!({"op": "nope"}), json!({"op": "kill", "pid": 1, "create_time": 0, "x": 1})]);
        assert_eq!(main(&[arg, out.to_string_lossy().into()]), 0);
        let got: Vec<Value> = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
        assert_eq!(got, vec![rejected(); 2]);
        let out2 = dir.path().join(format!("elev-{}-out.json", "b".repeat(32)));
        for bad in ["", "!!not base64!!"] {
            assert_ne!(main(&[bad.into(), out2.to_string_lossy().into()]), 0);
        }
        assert_ne!(main(&[]), 0);
        assert!(!out2.exists());
        // wrong name, and an existing file (or link) at the path, are refused
        let good = encode_ops(&[json!({"op": "nope"})]);
        let odd = dir.path().join("out.json");
        assert_eq!(main(&[good.clone(), odd.to_string_lossy().into()]), 1);
        assert!(!odd.exists());
        assert_eq!(main(&[good, out.to_string_lossy().into()]), 1, "must not overwrite");
    }

    #[test]
    fn schtasks_comes_from_the_system_directory() {
        let exe = schtasks_path().unwrap();
        let sys = std::env::var("SystemRoot").unwrap();
        assert!(exe.starts_with(std::path::Path::new(&sys).join("System32")) || exe.to_string_lossy().to_lowercase().starts_with(&sys.to_lowercase()));
        assert!(exe.is_file());
    }
}
