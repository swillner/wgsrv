mod helpers;
mod networks;
mod peers;
mod settings;

use crate::settings::Settings;
use clap::{Parser, Subcommand};
use std::error::Error;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(long, default_value = "/etc/wireguard/wgsrv.json")]
    settings: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Network {
        #[command(subcommand)]
        command: networks::Command,
    },
    Peer {
        #[command(subcommand)]
        command: peers::Command,
    },
}

impl Command {
    fn run(self, settings: Settings) -> Result<(), Box<dyn Error>> {
        match self {
            Command::Network { command } => command.run(settings),
            Command::Peer { command } => command.run(settings),
        }
    }
}

fn main() -> Result<(), String> {
    let args = Cli::parse();

    (|| {
        let settings = Settings::from_file(&args.settings)?;
        args.command.run(settings)
    })()
    .map_err(|e| e.to_string())
}
