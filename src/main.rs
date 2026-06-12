use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use browser_rnd::{analyze, sample::Sample};

#[derive(Parser)]
#[command(name = "browser_rnd", about = "Reverse engineer browser Math.random() PRNGs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fingerprint a captured sample: which engine produced it?
    Analyze {
        /// Path to a captured sample file, or `-` for stdin.
        #[arg(default_value = "-")]
        input: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Analyze { input } => {
            let text = read_input(&input)?;
            let sample = Sample::parse(&text).map_err(anyhow::Error::msg)?;
            print!("{}", analyze::report(&sample));
        }
    }
    Ok(())
}

fn read_input(input: &str) -> Result<String> {
    if input == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("reading stdin")?;
        Ok(buf)
    } else {
        let path = PathBuf::from(input);
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))
    }
}
