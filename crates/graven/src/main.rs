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
        /// A further base URL serving the Log's static files, tried when
        /// one source does not hold a file. Repeatable.
        #[arg(long = "mirror")]
        mirrors: Vec<String>,
        /// A Witness this Consumer trusts, as its
        /// `<name>+<key ID>+<key>` verifier-key string. Repeatable;
        /// supplying any replaces the roster held for the log.
        #[arg(long = "witness")]
        witnesses: Vec<String>,
        /// Catch up through the newest Snapshot instead of walking when it
        /// stands at least N Epochs above the verified head; default 720.
        #[arg(long = "catch-up-epochs", value_name = "N")]
        catch_up_epochs: Option<u64>,
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
        #[arg(long = "mirror")]
        mirrors: Vec<String>,
        #[arg(long = "witness")]
        witnesses: Vec<String>,
        /// Catch up through the newest Snapshot instead of walking when it
        /// stands at least N Epochs above the verified head; default 720.
        #[arg(long = "catch-up-epochs", value_name = "N", requires = "anchor")]
        catch_up_epochs: Option<u64>,
        /// Payloads of a batch fetched concurrently, each verified on its
        /// own; 1 fetches them one at a time.
        #[arg(
            long = "payload-fetches",
            value_name = "N",
            default_value_t = graven::sync::DEFAULT_PAYLOAD_FETCHES,
            value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..)
        )]
        payload_fetches: usize,
    },
    Serve {
        #[arg(long)]
        dir: PathBuf,
    },
    Pack {
        #[command(subcommand)]
        command: PackCommand,
    },
    /// Adds a Labeler to the subscription list this index applies
    /// (WIST-4 §6); without --labeler, lists the subscriptions.
    Subscribe {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        labeler: Option<String>,
    },
    /// Removes a Labeler from the subscription list.
    Unsubscribe {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        labeler: String,
    },
    /// Ranking profiles: list them, show one, or select the one queries
    /// use when they name none.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
}

#[derive(Subcommand)]
enum ProfileCommand {
    List {
        #[arg(long)]
        dir: PathBuf,
    },
    Show {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        name: String,
    },
    Use {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand)]
enum PackCommand {
    Import {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long = "log-id")]
        log_id: String,
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        key: String,
    },
}

fn print_report(report: &SyncReport) {
    println!("{report}");
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
            mirrors,
            witnesses,
            catch_up_epochs,
        } => {
            let report = graven::sync::follow(
                &graven::sync::Follow {
                    anchor: &anchor,
                    log_base: &log_base,
                    mirrors: &mirrors,
                    witnesses: &witnesses,
                    tier1,
                    allow_http,
                    catch_up_epochs,
                    payload_fetches: graven::sync::DEFAULT_PAYLOAD_FETCHES,
                },
                &dir,
            )?;
            print_report(&report);
        }
        Command::Sync {
            dir,
            anchor,
            log_base,
            tier1,
            allow_http,
            mirrors,
            witnesses,
            catch_up_epochs,
            payload_fetches,
        } => match (anchor, log_base) {
            (Some(anchor), Some(log_base)) => {
                let report = graven::sync::follow(
                    &graven::sync::Follow {
                        anchor: &anchor,
                        log_base: &log_base,
                        mirrors: &mirrors,
                        witnesses: &witnesses,
                        tier1,
                        allow_http,
                        catch_up_epochs,
                        payload_fetches,
                    },
                    &dir,
                )?;
                print_report(&report);
            }
            _ => {
                let reports = graven::sync::run_all(&dir, allow_http, payload_fetches)?;
                for report in &reports {
                    print_report(report);
                }
            }
        },
        Command::Serve { dir } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(graven::mcp::serve_stdio(&dir))?;
        }
        Command::Subscribe { dir, labeler } => {
            let mut labelers = graven::store::load_subscriptions(&dir)?;
            if let Some(labeler) = labeler {
                labelers.insert(labeler);
                graven::store::save_subscriptions(&dir, &labelers)?;
            }
            for labeler in &labelers {
                println!("{labeler}");
            }
        }
        Command::Unsubscribe { dir, labeler } => {
            let mut labelers = graven::store::load_subscriptions(&dir)?;
            labelers.remove(&labeler);
            graven::store::save_subscriptions(&dir, &labelers)?;
        }
        Command::Profile { command } => match command {
            ProfileCommand::List { dir } => {
                for profile in graven::ranking::list_profiles(&dir)? {
                    println!(
                        "{}{} — {} ({}, {})",
                        if profile.active { "* " } else { "  " },
                        profile.name,
                        profile.description,
                        profile.author,
                        profile.license
                    );
                }
            }
            ProfileCommand::Show { dir, name } => {
                let profile = graven::ranking::load_profile(&dir, &name)?;
                println!("{}", serde_json::to_string_pretty(&profile)?);
            }
            ProfileCommand::Use { dir, name } => {
                graven::ranking::set_active_profile(&dir, &name)?;
                println!("queries without a profile now use {name}");
            }
        },
        Command::Pack { command } => match command {
            PackCommand::Import {
                dir,
                log_id,
                pack,
                key,
            } => {
                let report = graven::pack::import(&dir, &log_id, &pack, &key)?;
                println!(
                    "imported {} vectors ({} skipped) for log {log_id}",
                    report.imported, report.skipped
                );
            }
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload_fetches(args: &[&str]) -> Result<usize, clap::Error> {
        let cli = Cli::try_parse_from(["graven", "sync", "--dir", "d"].iter().chain(args))?;
        match cli.command {
            Command::Sync {
                payload_fetches, ..
            } => Ok(payload_fetches),
            _ => unreachable!(),
        }
    }

    #[test]
    fn payload_fetches_defaults_to_four() {
        assert_eq!(payload_fetches(&[]).unwrap(), 4);
    }

    #[test]
    fn payload_fetches_accepts_one_and_rejects_zero() {
        assert_eq!(payload_fetches(&["--payload-fetches", "1"]).unwrap(), 1);
        assert!(payload_fetches(&["--payload-fetches", "0"]).is_err());
    }
}
