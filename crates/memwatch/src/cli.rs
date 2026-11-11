//! Command line. Phase 2 has only `log`; the rest arrives with the CLI port.

use std::path::PathBuf;

use crate::config::{load_config, Config};
use crate::install;
use crate::logger::{acquire_single_instance, install_global_log, mutex_name, Logger, LogSink, RealEnv};

/// Run the CLI; returns the process exit code.
pub fn main(args: Vec<String>) -> i32 {
    match args.first().map(String::as_str) {
        Some("log") => cmd_log(&args[1..]),
        Some("report") => cmd_report(&args[1..]),
        Some("install") => cmd_install(&args[1..], false),
        Some("uninstall") => cmd_install(&args[1..], true),
        Some("status") if args.len() == 1 => {
            let cfg = load_config(None);
            install::status(&cfg, &install::Sys::real(), &mut std::io::stdout())
        }
        // started through UAC; runs only whitelisted, validated ops
        Some("elevated-run") => crate::elevated_runner::main(&args[1..]),
        _ => {
            eprintln!(
                "usage: memwatch log | report [--no-browser] | install | uninstall [--purge] [--force] | status"
            );
            2
        }
    }
}

/// Open the on-demand report. `--no-browser` prints the URL instead of opening it.
fn cmd_report(args: &[String]) -> i32 {
    let open = match args {
        [] => true,
        [a] if a == "--no-browser" => false,
        _ => return 2,
    };
    let cfg = load_config(None);
    let sink = LogSink::open(&cfg.data_dir);
    install_global_log(sink.clone());
    match crate::server::serve_report(cfg, open) {
        Ok(()) => 0,
        Err(e) => {
            sink.write("ERROR", "memwatch.cli", &format!("memwatch report failed: {e}"));
            1
        }
    }
}

fn cmd_log(args: &[String]) -> i32 {
    let mut cfg: Config = load_config(None);
    let default_dir = cfg.data_dir.clone();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--data-dir" => match it.next() {
                Some(p) => cfg.data_dir = PathBuf::from(p),
                None => return 2,
            },
            _ => return 2,
        }
    }
    let sink = LogSink::open(&cfg.data_dir);
    install_global_log(sink.clone());
    let Some(_guard) = acquire_single_instance(&mutex_name(&cfg, &default_dir)) else {
        return 0; // another logger already owns this data directory
    };
    let conn = match crate::db::connect(&cfg.data_dir.join("memwatch.db")) {
        Ok(c) => c,
        Err(e) => {
            sink.write("ERROR", "memwatch.cli", &format!("memwatch log failed: cannot open database: {e}"));
            return 1;
        }
    };
    Logger::new(cfg, conn, Box::new(RealEnv)).run_forever();
    0
}

/// `install` / `uninstall`, with the hidden `--root`, `--desktop` and `--install-dir`
/// test hooks.
fn cmd_install(args: &[String], uninstall: bool) -> i32 {
    let mut o = install::Opts {
        src_dir: std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(PathBuf::from))
            .unwrap_or_default(),
        ..Default::default()
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match (a.as_str(), uninstall) {
            ("--root", _) => o.root = it.next().cloned(),
            ("--desktop", _) => o.desktop = it.next().map(PathBuf::from),
            ("--install-dir", _) => o.install_dir = it.next().map(PathBuf::from),
            ("--purge", true) => o.purge = true,
            ("--force", true) => o.force = true,
            _ => {
                eprintln!("memwatch: unexpected argument {a}");
                return 2;
            }
        }
    }
    let cfg = load_config(None);
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    let sys = install::Sys::real();
    if uninstall {
        install::uninstall(&cfg, &o, &sys, &mut out, &mut err)
    } else {
        install::install(&cfg, &o, &sys, &mut out, &mut err)
    }
}
