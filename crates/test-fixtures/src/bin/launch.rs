//! Start `argv[1] argv[2..]`, print its pid and exit at once, so the started process is
//! not a descendant of the test process (memwatch guards its own descendants).
use std::process::{Command, Stdio};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((exe, rest)) = args.split_first() else { std::process::exit(2) };
    #[allow(clippy::zombie_processes)] // deliberately not waited on: it must outlive us
    let child = Command::new(exe)
        .args(rest)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    println!("{}", child.id());
}
