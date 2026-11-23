//! `seal-sealer`: seals a secret under an offer, and prints the envelope.

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let args = seal_sealer::Args::parse();
    match seal_sealer::run(&args, &mut std::io::stdin().lock()) {
        Ok(envelope) => {
            let mut out = std::io::stdout().lock();
            match writeln!(out, "{envelope}") {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            }
        }
        Err(message) => {
            // The message names what was wrong, and never holds a value.
            let _ = writeln!(std::io::stderr().lock(), "seal-sealer: {message}");
            ExitCode::FAILURE
        }
    }
}
