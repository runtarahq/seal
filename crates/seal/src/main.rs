//! The seal credential broker service and CLI.

#![forbid(unsafe_code)]
// A CLI's output goes to standard output.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use seal::config::Config;
use seal_format::KeysetId;

#[derive(Parser)]
#[command(
    name = "seal",
    version,
    about = "A credential broker: applications use credentials they cannot read."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Runs the service.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Checks a configuration and prints how the memory ceiling adds up.
    CheckConfig {
        #[arg(long)]
        config: PathBuf,
    },
    /// Makes a keyset's first key in the configured key source, or a wrapping key file.
    Keygen {
        #[arg(long, required_unless_present = "wrapping_key")]
        config: Option<PathBuf>,
        #[arg(long, requires = "config")]
        keyset: Option<String>,
        /// Writes a new wrapping key to this file instead.
        #[arg(long, conflicts_with_all = ["config", "keyset"])]
        wrapping_key: Option<PathBuf>,
    },
    /// Reseals values under a keyset's current key. Reads and writes JSON lines of
    /// `{"item": …, "field": …, "envelope": …}`.
    Reseal {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        keyset: String,
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long = "out")]
        output: PathBuf,
    },
    /// Prints the version.
    Version,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        // Colour only for a person, never in files or the journal.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("seal: {message}");
            ExitCode::FAILURE
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| "cannot start the runtime".to_owned())
}

fn keyset(name: &str) -> Result<KeysetId, String> {
    KeysetId::new(name).map_err(|_| "the keyset is not valid".to_owned())
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Command::Version => {
            println!("seal {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        Command::CheckConfig { config } => {
            let config = Config::load(&config).map_err(|error| error.to_string())?;
            let fits = seal::cli::check_config(&config, &mut std::io::stdout().lock())?;
            Ok(if fits {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Command::Keygen {
            wrapping_key: Some(path),
            ..
        } => {
            seal::cli::create_wrapping_key(&path)?;
            println!("wrote a new wrapping key to {}", path.display());
            Ok(ExitCode::SUCCESS)
        }
        Command::Keygen {
            config: Some(config),
            keyset: Some(name),
            ..
        } => {
            let config = Config::load(&config).map_err(|error| error.to_string())?;
            let keyset = keyset(&name)?;
            let kid = runtime()?.block_on(seal::cli::keygen(&config, &keyset))?;
            println!("made key {kid} for keyset {keyset}");
            Ok(ExitCode::SUCCESS)
        }
        Command::Keygen { .. } => {
            Err("keygen needs --config and --keyset, or --wrapping-key".to_owned())
        }
        Command::Reseal {
            config,
            keyset: name,
            input,
            output,
        } => {
            let config = Config::load(&config).map_err(|error| error.to_string())?;
            let keyset = keyset(&name)?;
            let reader = std::io::BufReader::new(
                std::fs::File::open(&input)
                    .map_err(|_| format!("cannot read {}", input.display()))?,
            );
            let mut writer = std::fs::File::create_new(&output)
                .map_err(|_| format!("cannot create {}; it must not exist", output.display()))?;
            let changed =
                runtime()?.block_on(seal::cli::reseal(&config, &keyset, reader, &mut writer))?;
            writer
                .sync_all()
                .map_err(|_| "cannot write the output".to_owned())?;
            println!("resealed {changed} values");
            Ok(ExitCode::SUCCESS)
        }
        Command::Serve { config } => {
            let config = Config::load(&config).map_err(|error| error.to_string())?;
            let hardened = seal::hardening::harden(config.keys.lock_memory)?;
            tracing::info!(
                memory_locked = hardened.memory_locked,
                "hardened the process"
            );
            runtime()?.block_on(seal::serve::run(
                config,
                |listening| match listening {
                    seal::serve::Listening::Unix(path) => {
                        eprintln!("seal: listening on unix:{}", path.display())
                    }
                    seal::serve::Listening::Tcp(address) => {
                        eprintln!("seal: listening on tcp:{address}")
                    }
                },
                shutdown_signal(),
            ))?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(_) => return std::future::pending().await,
            };
        tokio::select! {
            _ = terminate.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
