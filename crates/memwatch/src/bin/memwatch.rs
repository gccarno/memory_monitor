fn main() {
    std::process::exit(memwatch::cli::main(std::env::args().skip(1).collect()));
}
