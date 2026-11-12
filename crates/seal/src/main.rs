//! The seal credential broker service and CLI.

#![forbid(unsafe_code)]
// A CLI's output goes to standard output.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use seal::config::{Config, WrapConfig};
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
    /// `{"item": …, "field": …, "envelope": …}`. With `--rewrite-policies`, an input
    /// line may add `"policy": …`, the policy that value is to have from now on.
    Reseal {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        keyset: String,
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long = "out")]
        output: PathBuf,
        /// Gives each value the policy its input line names, if it names one. Read the
        /// input first: this changes where existing secrets may go.
        #[arg(long)]
        rewrite_policies: bool,
    },
    /// Deletes every key of a keyset from the configured key source, when a tenant
    /// leaves. This cannot be undone: nothing sealed to the keyset opens again.
    DestroyKeyset {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        keyset: String,
        /// The keyset's name again, to confirm it.
        #[arg(long)]
        confirm: String,
    },
    /// Rotates the wrapping key, or moves to another kind of one: wraps every key in
    /// the configured key directory again, under a new wrapping key, into a new
    /// directory. Nothing configured is changed; point the configuration at the new
    /// directory and wrapping key, and restart seal.
    Rewrap {
        #[arg(long)]
        config: PathBuf,
        /// The new wrapping key, a file made with `keygen --wrapping-key`.
        #[arg(long, required_unless_present = "new_wrap")]
        new_wrapping_key: Option<PathBuf>,
        /// The new wrapping key, as `keys.wrap` is written in the configuration, such
        /// as `{ ovh_kms = { … } }`.
        #[arg(long, conflicts_with = "new_wrapping_key")]
        new_wrap: Option<String>,
        /// Where the re-wrapped keys go. It must not exist.
        #[arg(long = "out")]
        output: PathBuf,
    },
    /// Prints the version.
    Version,
}

/// What is logged unless `RUST_LOG` says otherwise. The AWS SDK is silent: when a
/// credential source fails it logs the whole response, which may hold a token. seal
/// logs such a failure itself, without the response.
const DEFAULT_LOG_FILTER: &str = "info,aws_config=off,aws_credential_types=off,aws_runtime=off,\
     aws_sdk_kms=off,aws_sdk_sso=off,aws_sdk_ssooidc=off,aws_sdk_sts=off,aws_sigv4=off,aws_smithy_async=off,aws_smithy_http=off,\
     aws_smithy_http_client=off,aws_smithy_runtime=off,aws_smithy_runtime_api=off,\
     aws_smithy_types=off,aws_types=off";

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        // Colour only for a person, never in files or the journal.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(DEFAULT_LOG_FILTER)),
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
        Command::DestroyKeyset {
            config,
            keyset: name,
            confirm,
        } => {
            if confirm != name {
                return Err("--confirm must repeat the keyset's name".to_owned());
            }
            let config = Config::load(&config).map_err(|error| error.to_string())?;
            let keyset = keyset(&name)?;
            runtime()?.block_on(seal::cli::destroy_keyset(&config, &keyset))?;
            println!("destroyed keyset {keyset}; running instances stop using it within max_stale");
            Ok(ExitCode::SUCCESS)
        }
        Command::Reseal {
            config,
            keyset: name,
            input,
            output,
            rewrite_policies,
        } => {
            let config = Config::load(&config).map_err(|error| error.to_string())?;
            let keyset = keyset(&name)?;
            let reader = std::io::BufReader::new(
                std::fs::File::open(&input)
                    .map_err(|_| format!("cannot read {}", input.display()))?,
            );
            let mut writer = std::fs::File::create_new(&output)
                .map_err(|_| format!("cannot create {}; it must not exist", output.display()))?;
            let done = runtime()?.block_on(seal::cli::reseal(
                &config,
                &keyset,
                rewrite_policies,
                reader,
                &mut writer,
            ))?;
            writer
                .sync_all()
                .map_err(|_| "cannot write the output".to_owned())?;
            if rewrite_policies {
                println!(
                    "resealed {} values, {} with a new policy",
                    done.values, done.policies
                );
            } else {
                println!("resealed {} values", done.values);
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Rewrap {
            config,
            new_wrapping_key,
            new_wrap,
            output,
        } => {
            let config = Config::load(&config).map_err(|error| error.to_string())?;
            let new_wrap = match (new_wrapping_key, new_wrap) {
                (Some(path), None) => WrapConfig::File(path),
                (None, Some(text)) => {
                    WrapConfig::parse(&text).map_err(|error| format!("--new-wrap: {error}"))?
                }
                _ => return Err("rewrap needs --new-wrapping-key or --new-wrap".to_owned()),
            };
            let keys = runtime()?.block_on(seal::cli::rewrap(&config, &new_wrap, &output))?;
            println!("re-wrapped {keys} keys into {}", output.display());
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
