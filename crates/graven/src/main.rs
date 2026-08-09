#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "graven", version, about = "WIST consumer CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Sync {
        #[arg(long)]
        anchor: String,
        #[arg(long = "log")]
        log_base: String,
        #[arg(long)]
        dir: PathBuf,
        #[arg(long = "allow-http")]
        allow_http: bool,
    },
}

fn main() -> Result<(), graven::Error> {
    let cli = Cli::parse();
    match cli.command {
        Command::Sync {
            anchor,
            log_base,
            dir,
            allow_http,
        } => {
            let report = graven::sync::run(&anchor, &log_base, &dir, allow_http)?;
            println!(
                "synced to log_position {:?}, head block {}",
                report.log_position_before, report.head
            );
        }
    }
    Ok(())
}
