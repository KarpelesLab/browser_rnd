use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use browser_rnd::{analyze, predict, sample::Sample};

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
    /// Identify the engine, then predict the next/previous Math.random() values.
    Predict {
        /// Path to a captured sample file, or `-` for stdin.
        #[arg(default_value = "-")]
        input: String,
        /// How many values to predict in each direction.
        #[arg(short, long, default_value_t = 5)]
        n: usize,
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
        Command::Predict { input, n } => {
            let text = read_input(&input)?;
            let sample = Sample::parse(&text).map_err(anyhow::Error::msg)?;
            match predict::identify(&sample.values) {
                None => println!("could not identify the generator"),
                Some(id) => {
                    println!("engine:      {}", id.engine);
                    println!("algorithm:   {}", id.algorithm);
                    println!("browsers:    {}", id.browsers);
                    if id.grid_bits == 0 {
                        println!("grid:        non-dyadic (1/R², R = 2³¹−2)");
                    } else {
                        println!("grid:        2^-{}", id.grid_bits);
                    }
                    println!("time-seeded: {}", id.time_seeded);
                    if !id.predictable {
                        println!("\nNot predictable (cryptographic RNG) — cannot recover state.");
                    } else if let Some(p) = predict::recover(&sample.values) {
                        let before = p.backward(n);
                        let after = p.forward(n);
                        println!("\n{} values BEFORE the capture:", n);
                        for v in &before { println!("  {v:.17}"); }
                        println!("{} values AFTER the capture:", n);
                        for v in &after { println!("  {v:.17}"); }
                    }
                }
            }
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
