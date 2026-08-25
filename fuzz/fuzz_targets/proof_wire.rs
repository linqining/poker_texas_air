#![no_main]

use libfuzzer_sys::fuzz_target;
use poker_texas_air::ristretto_reconstruction_proof_wire::RistrettoReconstructionProofEnvelope;

fuzz_target!(|bytes: &[u8]| {
    let _ = RistrettoReconstructionProofEnvelope::decode_wire(bytes);
});
