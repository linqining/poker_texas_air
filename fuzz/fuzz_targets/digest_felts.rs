//! Fuzz: aggregate digest 双 felt 拆/合——任何 32 字节输入不得 panic，
//! canonical 输入必须 split→merge 往返一致。
#![no_main]

use libfuzzer_sys::fuzz_target;
use poker_texas_air::starknet_settlement::AggregateDigestFelts;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() < 64 {
        return;
    }
    let mut hi = [0u8; 32];
    let mut lo = [0u8; 32];
    hi.copy_from_slice(&bytes[..32]);
    lo.copy_from_slice(&bytes[32..64]);

    if let Ok(felts) = AggregateDigestFelts::split(&hi) {
        if let Ok(roundtrip) = AggregateDigestFelts::merge(felts.hi, felts.lo) {
            assert_eq!(roundtrip, hi, "canonical digest must roundtrip");
        }
    }
    if let Ok(felts) = AggregateDigestFelts::split(&lo) {
        let _ = AggregateDigestFelts::merge(felts.lo, felts.hi);
    }
});
