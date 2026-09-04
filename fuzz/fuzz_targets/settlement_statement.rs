//! Fuzz: 不信任字节的结算隐私语句解码 + 校验——绝不能 panic。
//! （取代 BLS/mirror 时代的 proof_wire/tx_decode target，2026-09-05 清理。）
#![no_main]

use borsh::BorshDeserialize;
use libfuzzer_sys::fuzz_target;
use poker_texas_air::settlement_private_circuit::SettlementPrivateStatement;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(statement) = SettlementPrivateStatement::try_from_slice(bytes) {
        // 校验失败是合法输出；panic/越界才是 bug。
        let _ = statement.validate();
    }
});
