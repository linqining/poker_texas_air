//! Verify browser-produced native shuffle and reveal proof bundles.
//!
//! The command is intentionally a minimal Rust consumer for the WASM vector
//! regression. It receives public Borsh bytes only; no wallet secret enters
//! this process.

use std::{env, process::ExitCode};

use borsh::BorshDeserialize;
use poker_protocol::browser_proof_bundle::{BrowserRevealTokenBundle, BrowserShuffleV2Bundle};

fn run() -> Result<(), String> {
    let kind = env::args().nth(1).ok_or_else(|| {
        "usage: verify_browser_crypto_borsh <shuffle|reveal> <bundle_borsh_hex>".to_owned()
    })?;
    let encoded = env::args()
        .nth(2)
        .ok_or_else(|| "missing bundle_borsh_hex".to_owned())?;
    let bytes = hex::decode(encoded).map_err(|error| format!("invalid bundle hex: {error}"))?;
    match kind.as_str() {
        "shuffle" => BrowserShuffleV2Bundle::try_from_slice(&bytes)
            .map_err(|error| format!("decode shuffle bundle: {error}"))?
            .verify()
            .map_err(|error| format!("verify shuffle bundle: {error}")),
        "reveal" => BrowserRevealTokenBundle::try_from_slice(&bytes)
            .map_err(|error| format!("decode reveal bundle: {error}"))?
            .verify()
            .map_err(|error| format!("verify reveal bundle: {error}")),
        _ => Err("bundle kind must be shuffle or reveal".to_owned()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("browser native crypto bundle rejected: {error}");
            ExitCode::FAILURE
        }
    }
}
