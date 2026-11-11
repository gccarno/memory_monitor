//! A windowless process that sleeps. `--child PATH` also spawns one child sleeper and writes
//! its pid to PATH. Exits on its own after 120 s so a failed test leaks nothing. Other
//! arguments are ignored (tests pass `-m memwatch` to imitate a memwatch process).
use std::process::Command;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--child") {
        if let (Some(path), Ok(me)) = (args.get(i + 1), std::env::current_exe()) {
            if let Ok(child) = Command::new(me).spawn() {
                let _ = std::fs::write(path, child.id().to_string());
            }
        }
    }
    std::thread::sleep(Duration::from_secs(120));
}
