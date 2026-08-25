#![no_main]

use libfuzzer_sys::fuzz_target;
use poker_l1::transaction::Transaction;

fuzz_target!(|bytes: &[u8]| {
    let _ = Transaction::from_bcs(bytes);
});
