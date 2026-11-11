// Same program without a console window: what the Run key, the shortcut and UAC launch.
#![windows_subsystem = "windows"]

fn main() {
    std::process::exit(memwatch::cli::main(std::env::args().skip(1).collect()));
}
