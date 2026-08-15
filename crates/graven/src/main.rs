#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use graven::sync::SyncReport;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "graven", version, about = "WIST consumer CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Follow {
        #[arg(long)]
        anchor: String,
        #[arg(long = "log")]
        log_base: String,
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        tier1: bool,
        #[arg(long = "allow-http")]
        allow_http: bool,
    },
    Sync {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, requires = "log_base")]
        anchor: Option<String>,
        #[arg(long = "log", requires = "anchor")]
        log_base: Option<String>,
        #[arg(long)]
        tier1: bool,
        #[arg(long = "allow-http")]
        allow_http: bool,
    },
    Serve {
        #[arg(long)]
        dir: PathBuf,
    },
}

fn print_report(report: &SyncReport) {
    println!(
        "[{}] synced to log_position {:?}, head block {}, withdrawn {}",
        report.log_id, report.log_position_before, report.head, report.withdrawn
    );
}

fn main() -> Result<(), graven::Error> {
    let cli = Cli::parse();
    match cli.command {
        Command::Follow {
            anchor,
            log_base,
            dir,
            tier1,
            allow_http,
        } => {
            let report = graven::sync::run(&anchor, &log_base, &dir, allow_http, tier1)?;
            print_report(&report);
        }
        Command::Sync {
            dir,
            anchor,
            log_base,
            tier1,
            allow_http,
        } => match (anchor, log_base) {
            (Some(anchor), Some(log_base)) => {
                let report = graven::sync::run(&anchor, &log_base, &dir, allow_http, tier1)?;
                print_report(&report);
            }
            _ => {
                let reports = graven::sync::run_all(&dir, allow_http)?;
                for report in &reports {
                    print_report(report);
                }
            }
        },
        Command::Serve { dir } => {
            graven::registry::check_not_legacy(&dir)?;
            let registry = graven::registry::load(&dir)?;
            let entry = registry.logs.first().ok_or_else(|| {
                graven::Error::Verify(format!(
                    "no logs registered in {}; run `graven follow` first",
                    dir.display()
                ))
            })?;
            let log_dir = graven::registry::log_dir(&dir, &entry.log_id);
            let log_id = entry.log_id.clone();
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(graven::mcp::serve_stdio(&log_dir, log_id))?;
        }
    }
    Ok(())
}
