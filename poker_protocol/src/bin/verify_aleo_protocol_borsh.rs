//! Verify an Aleo-native BLS12-377 protocol-proof attachment emitted by WASM.
//!
//! This deliberately verifies both the proof relation and the canonical action
//! context. A valid proof for another action must never be reusable here.

use std::{env, process::ExitCode};

use borsh::BorshDeserialize;
use poker_protocol::aleo_protocol::{AleoProtocolContext, AleoProtocolProofBundle};

fn decode_hex(name: &str, value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value).map_err(|error| format!("invalid {name} hex: {error}"))
}

fn run() -> Result<(), String> {
    let kind = env::args().nth(1).ok_or_else(|| {
        "usage: verify_aleo_protocol_borsh <schnorr|reveal|showdown-reveal-batch|shuffle|showdown-shuffle|reconstruct> <context_borsh_hex> <bundle_borsh_hex>"
            .to_owned()
    })?;
    let expected_context_hex = env::args()
        .nth(2)
        .ok_or_else(|| "missing context_borsh_hex".to_owned())?;
    let bundle_hex = env::args()
        .nth(3)
        .ok_or_else(|| "missing bundle_borsh_hex".to_owned())?;
    let expected_context =
        AleoProtocolContext::try_from_slice(&decode_hex("context Borsh", &expected_context_hex)?)
            .map_err(|error| format!("decode Aleo protocol context: {error}"))?;
    let bundle = AleoProtocolProofBundle::try_from_slice(&decode_hex("bundle Borsh", &bundle_hex)?)
        .map_err(|error| format!("decode Aleo protocol bundle: {error}"))?;

    let actual_kind = match &bundle {
        AleoProtocolProofBundle::Schnorr(_) => "schnorr",
        AleoProtocolProofBundle::Reveal(_) => "reveal",
        AleoProtocolProofBundle::Shuffle(_) => "shuffle",
        AleoProtocolProofBundle::Reconstruct(_) => "reconstruct",
        AleoProtocolProofBundle::ShowdownShuffle(_) => "showdown-shuffle",
        AleoProtocolProofBundle::ShowdownRevealBatch(_) => "showdown-reveal-batch",
    };
    if kind != actual_kind {
        return Err(format!(
            "expected {kind} Aleo protocol bundle, received {actual_kind}"
        ));
    }
    if bundle.context() != expected_context {
        return Err(
            "Aleo protocol bundle context does not match the canonical action context".into(),
        );
    }
    if !bundle.verify() {
        return Err("Aleo protocol proof relation did not verify".into());
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Aleo protocol bundle rejected: {error}");
            ExitCode::FAILURE
        }
    }
}
