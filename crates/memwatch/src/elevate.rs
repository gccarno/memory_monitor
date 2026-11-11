//! Send whitelisted ops to the elevated runner through a UAC prompt.
//!
//! The ops travel as one base64url JSON command-line argument (UAC fixes the command line
//! when the user approves), never through a file. Only the result comes back via
//! `data_dir\elev-<random>-out.json`; a forged result can misreport, not execute.

use std::path::{Path, PathBuf};

use serde_json::Value;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HWND, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::config::Config;
use crate::elevated_runner::{decode_ops, encode_ops, MAX_ARG_LEN, MAX_OPS};

pub const TIMEOUT_S: u32 = 120;
const ERROR_CANCELLED: i32 = 1223;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpResult {
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Elevation {
    /// The UAC prompt was cancelled.
    Declined,
    /// One result per op, in order.
    Results(Vec<OpResult>),
}

/// Runs a batch of ops with administrator rights.
pub type Elevator = Box<dyn Fn(&[Value]) -> Elevation + Send + Sync>;

/// How a launch of the runner ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Launch {
    Exit(u32),
    Declined,
    TimedOut,
}

fn quote(arg: &str) -> String {
    if arg.is_empty() || arg.contains(' ') {
        format!("\"{arg}\"")
    } else {
        arg.to_string()
    }
}

/// The exe UAC should run: the windowless sibling of this exe when present.
fn runner_exe() -> std::io::Result<PathBuf> {
    let me = std::env::current_exe()?;
    let w = me.with_file_name("memwatchw.exe");
    Ok(if w.is_file() { w } else { me })
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Launch `exe args` with the `runas` verb and wait for it.
fn run_as_admin(exe: &Path, args: &[String], timeout_s: u32) -> Result<Launch, String> {
    let file = wide(&exe.to_string_lossy());
    let params = wide(&args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" "));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        hwnd: HWND::default(),
        lpVerb: w!("runas"),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    unsafe {
        if let Err(e) = ShellExecuteExW(&mut info) {
            // HRESULT_FROM_WIN32(1223)
            return if e.code().0 == (0x8007_0000u32 | ERROR_CANCELLED as u32) as i32 {
                Ok(Launch::Declined)
            } else {
                Err(e.message())
            };
        }
        let h = info.hProcess;
        if h.is_invalid() {
            return Err("no process handle".into());
        }
        let r = if WaitForSingleObject(h, timeout_s * 1000) == WAIT_OBJECT_0 {
            let mut code = 0u32;
            match GetExitCodeProcess(h, &mut code) {
                Ok(()) => Ok(Launch::Exit(code)),
                Err(e) => Err(e.message()),
            }
        } else {
            Ok(Launch::TimedOut)
        };
        let _ = CloseHandle(h);
        r
    }
}

fn failed(n: usize, why: &str) -> Vec<OpResult> {
    (0..n).map(|_| OpResult { ok: false, error: Some(why.to_string()) }).collect()
}

fn read_results(path: &Path, n: usize) -> Vec<OpResult> {
    let Ok(raw) = std::fs::read(path) else { return failed(n, "elevated runner wrote no result") };
    let Ok(Value::Array(items)) = serde_json::from_slice::<Value>(&raw) else {
        return failed(n, "elevated runner wrote a malformed result");
    };
    if items.len() != n || !items.iter().all(|r| r.get("ok").is_some_and(Value::is_boolean)) {
        return failed(n, "elevated runner wrote a malformed result");
    }
    items
        .iter()
        .map(|r| {
            let ok = r["ok"].as_bool().unwrap_or(false);
            let error = if ok {
                None
            } else {
                Some(match r.get("error") {
                    Some(Value::String(s)) if !s.is_empty() => s.clone(),
                    _ => "failed".to_string(),
                })
            };
            OpResult { ok, error }
        })
        .collect()
}

fn random_hex() -> String {
    let mut b = [0u8; 16];
    let _ = getrandom::getrandom(&mut b);
    crate::startup::hex_encode(b)
}

pub fn run_elevated(ops: &[Value], cfg: &Config) -> Elevation {
    run_elevated_with(ops, cfg, &|args| {
        let exe = runner_exe().map_err(|e| e.to_string())?;
        run_as_admin(&exe, args, TIMEOUT_S)
    })
}

/// `launch` receives the runner's arguments (`elevated-run <ops> <out>`).
pub fn run_elevated_with(
    ops: &[Value],
    cfg: &Config,
    launch: &dyn Fn(&[String]) -> Result<Launch, String>,
) -> Elevation {
    if ops.is_empty() {
        return Elevation::Results(vec![]);
    }
    let n = ops.len();
    if n > MAX_OPS {
        return Elevation::Results(failed(n, &format!("too many changes at once (max {MAX_OPS})")));
    }
    let arg = encode_ops(ops);
    if arg.len() > MAX_ARG_LEN {
        return Elevation::Results(failed(n, "too many changes at once"));
    }
    let _ = std::fs::create_dir_all(&cfg.data_dir);
    let out = cfg.data_dir.join(format!("elev-{}-out.json", random_hex()));
    let args = vec!["elevated-run".to_string(), arg, out.to_string_lossy().into_owned()];
    let res = match launch(&args) {
        Err(e) => Elevation::Results(failed(n, &format!("could not start elevated runner: {e}"))),
        Ok(Launch::Declined) => Elevation::Declined,
        Ok(Launch::TimedOut) => {
            Elevation::Results(failed(n, &format!("elevated runner did not finish within {TIMEOUT_S} s")))
        }
        Ok(Launch::Exit(_)) => Elevation::Results(read_results(&out, n)),
    };
    let _ = std::fs::remove_file(&out);
    res
}

/// Used by tests and the runner's own round trip: decode what a launch was given.
pub fn ops_from_args(args: &[String]) -> Option<Vec<Value>> {
    decode_ops(args.get(1)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::mk_cfg;
    use serde_json::json;

    fn rejected() -> OpResult {
        OpResult { ok: false, error: Some("rejected".into()) }
    }

    #[test]
    fn round_trip_cleans_up_and_never_writes_ops() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = mk_cfg();
        cfg.data_dir = dir.path().to_path_buf();
        let seen = std::cell::RefCell::new(vec![]);
        let r = run_elevated_with(&[json!({"op": "nope"})], &cfg, &|args| {
            seen.borrow_mut().push(args.to_vec());
            assert_eq!(args[0], "elevated-run");
            assert_eq!(ops_from_args(args), Some(vec![json!({"op": "nope"})]));
            assert!(args[1].chars().all(|c| c.is_ascii_alphanumeric() || "-_=".contains(c)));
            // act as the runner
            assert_eq!(crate::elevated_runner::main(&args[1..]), 0);
            Ok(Launch::Exit(0))
        });
        assert_eq!(r, Elevation::Results(vec![rejected()]));
        let args = &seen.borrow()[0];
        let out = Path::new(&args[2]);
        assert_eq!(out.parent().unwrap(), dir.path());
        let name = out.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("elev-") && name.ends_with("-out.json"));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn oversized_batches_are_refused_without_launching() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = mk_cfg();
        cfg.data_dir = dir.path().to_path_buf();
        let never = |_: &[String]| -> Result<Launch, String> { panic!("launched") };
        let many = vec![json!({"op": "stop_service", "name": "Foo"}); 65];
        let Elevation::Results(r) = run_elevated_with(&many, &cfg, &never) else { panic!() };
        assert_eq!(r.len(), 65);
        assert!(r.iter().all(|x| !x.ok));
        let long = vec![json!({"op": "set_task", "name": format!("\\{}", "x".repeat(500)), "enabled": false}); 60];
        let Elevation::Results(r) = run_elevated_with(&long, &cfg, &never) else { panic!() };
        assert_eq!(r.len(), 60);
        assert!(r.iter().all(|x| !x.ok));
        assert_eq!(run_elevated_with(&[], &cfg, &never), Elevation::Results(vec![]));
    }

    #[test]
    fn declined_timeout_and_launch_errors() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = mk_cfg();
        cfg.data_dir = dir.path().to_path_buf();
        let ops = [json!({"op": "a"}), json!({"op": "b"})];
        assert_eq!(run_elevated_with(&ops, &cfg, &|_| Ok(Launch::Declined)), Elevation::Declined);
        for launch in [Ok(Launch::TimedOut), Err("boom".to_string())] {
            let Elevation::Results(r) = run_elevated_with(&ops, &cfg, &|_| match &launch {
                Ok(Launch::TimedOut) => Ok(Launch::TimedOut),
                Err(e) => Err(e.clone()),
                _ => unreachable!(),
            }) else {
                panic!()
            };
            assert_eq!(r.len(), 2);
            assert!(r.iter().all(|x| !x.ok && x.error.is_some()));
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn missing_or_short_output_fails_every_op() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = mk_cfg();
        cfg.data_dir = dir.path().to_path_buf();
        let ops = [json!({"op": "a"}), json!({"op": "b"})];
        let Elevation::Results(r) = run_elevated_with(&ops, &cfg, &|_| Ok(Launch::Exit(0))) else { panic!() };
        assert!(r.iter().all(|x| !x.ok && x.error.is_some()) && r.len() == 2);
        let Elevation::Results(r) = run_elevated_with(&ops, &cfg, &|args| {
            std::fs::write(&args[2], br#"[{"ok": true, "error": null}]"#).unwrap();
            Ok(Launch::Exit(0))
        }) else {
            panic!()
        };
        assert_eq!(r.iter().map(|x| x.ok).collect::<Vec<_>>(), vec![false, false]);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn quoting_matches_the_command_line_rules() {
        assert_eq!(quote("plain"), "plain");
        assert_eq!(quote("has space"), "\"has space\"");
        assert_eq!(quote(""), "\"\"");
    }
}
