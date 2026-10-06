fn main() {
    std::process::exit(allowit_cli::run(std::env::args().skip(1).collect()));
}
