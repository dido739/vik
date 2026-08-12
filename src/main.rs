use clap::Parser;

fn main() {
    let cli = vik::Cli::parse();
    if let Err(err) = vik::run(cli) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
