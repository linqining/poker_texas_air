//! Dual-proof settlement contract (DUAL_PROOF_PROTOCOL.md §7.1, MVP).
//!
//! Two proof tracks must agree before chips move:
//!
//! - **P** (poker_protocol, BN254 G1 direct-sigma): every per-player proof is
//!   verified **on-chain** through [`super::dual::sigma_verifier`] — this
//!   contract is the strongest verifier, not a digest registrar.
//! - **G** (牌局过程 STARK): Phase 1 MVP = host-verified canonical STARK whose
//!   commitments are registered here via the unified `hand_binding`
//!   (Phase 2 on-chain STARK verification is §7.3, four routes).
//!
//! Binding invariants (§6): a hand settles only when
//! (a) the `hand_binding` was registered and is not yet settled,
//! (b) the recomputed Poseidon `settlement_digest` matches the registered one,
//! (c) every player's P proof verifies on-chain,
//! (d) the deltas are zero-sum.
use openzeppelin::access::ownable::OwnableComponent;
use starknet::ContractAddress;

#[starknet::interface]
pub trait IPokerDualSettlement<TContractState> {
    /// Register a hand's unified binding (authorized prover only).
    ///
    /// `hand_binding` — Poseidon digest over the documented §6 field order
    /// (Rust: `poker_texas_air::hand_binding`).
    /// `settlement_digest` — the existing settlement commitment.
    /// `g_attestation` — Phase 1 registration of the host-verified G-STARK
    /// commitments (Poseidon over binding + settlement + state roots).
    /// `expected_n_reveal/leave/recon` — completeness hardening: the
    /// caller's expected bucket counts for the hand-batch header
    /// (words 2..4: [n_reveal, n_leave, n_recon]). They are stored packed
    /// as one felt and the linear settle entry asserts the submitted batch
    /// header matches exactly when the packed value is non-zero; **all-zero
    /// = unconstrained** (the legacy default — existing registrants keep
    /// working, and the Rust server currently registers zeros).
    fn register_hand(
        ref self: TContractState,
        hand_binding: felt252,
        settlement_digest: felt252,
        g_attestation: felt252,
        expected_n_reveal: felt252,
        expected_n_leave: felt252,
        expected_n_recon: felt252,
    );

    /// Plan D STARK-curve variant of `verify_and_settle_dapv`: the P layer
    /// folds on the Cairo-native STARK curve via the EC_OP builtin
    /// (`dual::hand_batch_stark::verify_hand_batch_stark`). Payload words
    /// are felt252-range u256s (coordinates/scalars are < n < P and convert
    /// losslessly); challenges and rho are Poseidon (host
    /// `StarkCurve::hash_to_scalar`), transcript domain stays keccak.
    fn verify_and_settle_dapv_stark(
        ref self: TContractState,
        hand_binding: felt252,
        hand_id_bytes: Span<u8>,
        hand_id: u64,
        players: Span<ContractAddress>,
        deltas: Span<i128>,
        p_batch: Span<felt252>,
    );

    fn set_prover(ref self: TContractState, prover: ContractAddress);
    fn remove_prover(ref self: TContractState, prover: ContractAddress);
    fn is_prover(self: @TContractState, prover: ContractAddress) -> bool;
    fn hand_binding(self: @TContractState, binding: felt252) -> (felt252, felt252, felt252);
    fn hand_settled(self: @TContractState, binding: felt252) -> bool;
    fn vault(self: @TContractState) -> ContractAddress;

    /// Part A Phase 1（SETTLEMENT_PRIVACY_PLAN.md §4）：隐私结算入口。
    /// 与 `verify_and_settle_dapv_stark` 相同的 DAPV 校验与 digest 断言，
    /// 但派奖方式不同：
    /// - 输家（delta < 0）仍经 vault.apply_settlement 公开扣款
    ///   （Phase 1 已知残余，Phase 2 由 ZK 消除）；
    /// - 赢家（delta > 0）不再记入公开 chip 余额，改为按座位写入认领
    ///   承诺 `cm = poseidon(commitment, hand_binding, amount_lo,
    ///   amount_hi)`（commitment 为玩家在 vault 注册的 payout 承诺
    ///   `poseidon(secret)`），并把赢家总额经 `vault.settlement_fund_escrow`
    ///   划入认领托管；
    /// - 赢家凭 secret 原像经 STRK20 池私密认领（见
    ///   SettlementPayoutAnonymizer）。
    /// `settlement_digest` 仍约束同一 (players, deltas) 明文——Phase 2 用
    /// Stwo 把"开根"搬进证明后，明文才真正离开 calldata。
    fn verify_and_settle_dapv_stark_private(
        ref self: TContractState,
        hand_binding: felt252,
        hand_id_bytes: Span<u8>,
        hand_id: u64,
        players: Span<ContractAddress>,
        deltas: Span<i128>,
        p_batch: Span<felt252>,
    );

    /// P2-M3（SETTLEMENT_PRIVACY_PLAN.md §4 Phase 2）：零明文结算入口。
    /// calldata 只含 (hand_binding, hand_id, segment)，**不含 players/deltas**；
    /// segment 是 settlement_private 电路（program_hash 钉死）的公开段：
    /// `[MAGIC, hand_id, digest, n, binding, cm_0..cm_7, total_winnings]`。
    /// 信任锚为 fact-registry：`fact = poseidon([program_hash ++ segment])`
    /// 须已由授权 prover/owner 登记（Stwo Cairo verifier 上链前的过渡形态，
    /// 与 G 层 host-verified 同一 residual-trust 口径）；托管金额取自公开段
    /// total_winnings（零和由电路证明，Σ claim ≤ escrow 由 vault 余额封顶）。
    fn verify_and_settle_dapv_stark_private_v2(
        ref self: TContractState,
        hand_binding: felt252,
        hand_id: u64,
        segment: Span<felt252>,
    );
    /// Owner-gated: 钉死电路 program hash（fact 的绑定根，换电路须重设）。
    fn set_circuit_program_hash(ref self: TContractState, program_hash: felt252);
    /// Prover/owner-gated: 登记已生成证明的 fact（prove-hand 后由运营侧调用）。
    fn register_settlement_fact(ref self: TContractState, fact: felt252);
    /// View: 钉死的电路 program hash。
    fn circuit_program_hash(self: @TContractState) -> felt252;
    /// View: fact 是否已登记。
    fn settlement_fact(self: @TContractState, fact: felt252) -> bool;
    /// View: 该手是否为 v2（金额藏在 cm 中，consume_claim 走隐藏模式）。
    fn amounts_hidden(self: @TContractState, hand_binding: felt252) -> bool;
    /// Owner-gated: set the claim escrow helper that receives the winners'
    /// pot via `vault.settlement_fund_escrow`.
    fn set_claim_helper(ref self: TContractState, helper: ContractAddress);
    /// View: the stored claim commitment for (hand_binding, seat_index).
    fn claim_cm(self: @TContractState, hand_binding: felt252, seat_index: u32) -> felt252;
    /// View: the claimable amount for (hand_binding, seat_index).
    fn claim_amount(self: @TContractState, hand_binding: felt252, seat_index: u32) -> u256;
    /// Claim-helper gated: consume a claim (idempotence + amount assert).
    fn consume_claim(
        ref self: TContractState,
        hand_binding: felt252,
        seat_index: u32,
        amount: u256,
    );
    /// View: the configured claim helper.
    fn claim_helper(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PokerDualSettlement {
    use openzeppelin::access::ownable::OwnableComponent;
    use starknet::ContractAddress;
    use core::num::traits::Zero;
    use core::hash::HashStateTrait;
    use core::poseidon::{poseidon_hash_span, PoseidonTrait};
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use super::super::dual::hand_batch_stark::verify_hand_batch_stark;
    use super::IVaultDispatcherDispatcherTrait;

    // P2-M3 公开段常量与 fact 公式（与 proving-tool/src/settlement_private.cairo
    // 及 texas/src/starknet/settlement_prover.rs 三方一致）。
    const SETTLEMENT_SEGMENT_MAGIC: felt252 = 0x5350324d5f4f4b;
    const SETTLEMENT_SEGMENT_LEN: usize = 14;

    fn fact_for_segment(program_hash: felt252, segment: Span<felt252>) -> felt252 {
        let mut h = PoseidonTrait::new();
        h = h.update(program_hash);
        let mut w: u32 = 0;
        while w < segment.len() {
            h = h.update(*segment.at(w));
            w += 1;
        }
        h.finalize()
    }

/// Big-endian bytes → felt252 (Horner). Used to bind the DAPV batch's
/// hand-domain input to the registered `hand_binding` felt.
fn bytes_to_felt(bytes: Span<u8>) -> felt252 {
    let mut acc: felt252 = 0;
    let mut i: u32 = 0;
    while i < bytes.len() {
        acc = acc * 256 + (*bytes.at(i)).into();
        i += 1;
    }
    acc
}

/// Shared settlement-digest recompute (settlement_hash.cairo layout):
/// Poseidon over [hand_id, (player, sign, |delta|)*]. Keeping ONE copy is
/// also what keeps the contract's CASM under the Starknet bytecode limit —
/// every settle entry must compare against the registered digest through
/// this helper, not inline its own loop.
fn compute_settlement_digest(
    hand_id: u64,
    players: Span<ContractAddress>,
    deltas: Span<i128>,
) -> felt252 {
    let mut felements: Array<felt252> = array![hand_id.into()];
    let mut i: u32 = 0;
    while i < players.len() {
        felements.append((*players.at(i)).into());
        let delta = *deltas.at(i);
        if delta >= 0_i128 {
            let as_u: u64 = delta.try_into().expect('delta fits u64');
            felements.append(1);
            felements.append(as_u.into());
        } else {
            let abs_delta = -delta;
            let as_u: u64 = abs_delta.try_into().expect('abs delta fits u64');
            felements.append(0);
            felements.append(as_u.into());
        }
        i += 1;
    }
    poseidon_hash_span(felements.span())
}

/// Shared zero-sum assertion (settlement invariant (d)).
fn assert_zero_sum(deltas: Span<i128>) {
    let zero: i128 = 0_i128;
    let mut sum: i128 = 0_i128;
    let mut d: u32 = 0;
    while d < deltas.len() {
        sum += *deltas.at(d);
        d += 1;
    }
    assert!(sum == zero, "Settlement not zero-sum");
}

/// Shared per-player net-delta application through the vault.
fn apply_deltas_through_vault(
    vault_addr: ContractAddress,
    players: Span<ContractAddress>,
    deltas: Span<i128>,
) {
    let mut m: u32 = 0;
    while m < players.len() {
        let player = *players.at(m);
        let delta = *deltas.at(m);
        let vault = super::IVaultDispatcherDispatcher { contract_address: vault_addr };
        vault.apply_settlement(player, delta);
        m += 1;
    }
}

/// Shared registration read: the (settlement_digest, g_attestation, flag)
/// tuple read + flag assert, deduplicated across the settle entries
/// (one shared copy of the tuple-read code, not three).
fn read_registered_digest(self: @ContractState, hand_binding: felt252) -> felt252 {
    let (registered_digest, _g_attestation, registered_flag) =
        self.bindings.read(hand_binding);
    assert!(registered_flag == 1, "Binding not registered");
    registered_digest
}

/// Shared settle-entry preamble: binding sanity, players/deltas bounds and
/// replay protection.
fn assert_settle_common(
    self: @ContractState,
    hand_binding: felt252,
    players: Span<ContractAddress>,
    deltas: Span<i128>,
) {
    assert!(hand_binding != 0, "Zero binding");
    assert!(players.len() == deltas.len(), "Players/deltas mismatch");
    assert!(players.len() > 0_u32, "No participants");
    assert!(players.len() < 10_u32, "Too many participants");
    assert!(!self.settled_bindings.read(hand_binding), "Hand already settled");
}

/// Expected bucket counts are packed into one felt as
/// `n_reveal + n_leave·2^64 + n_recon·2^128` (each count < 2^64): one
/// scalar storage cell + one felt equality instead of a tuple read.
/// Packing is injective for any batch that can pass the fold: counts are
/// bounded by the actual payload length (a count ≥ 2^60 could never fit in
/// a real calldata Span), so distinct small triples give distinct integers
/// < 2^192 < P.
const EXPECTED_PACK_SHIFT: felt252 = 0x10000000000000000; // 2^64
const EXPECTED_PACK_SHIFT2: felt252 =
    0x100000000000000000000000000000000; // 2^128

fn pack_expected_counts(
    n_reveal: felt252,
    n_leave: felt252,
    n_recon: felt252,
) -> felt252 {
    n_reveal + n_leave * EXPECTED_PACK_SHIFT + n_recon * EXPECTED_PACK_SHIFT2
}

/// Shared registration write (deduplicates the dup-check, bindings tuple
/// write, expected-counts write and event across `register_hand` and
/// `register_hand_proved`): the FIRST registration of a binding — linear
/// or proved — locks it.
fn write_registration(
    ref self: ContractState,
    hand_binding: felt252,
    settlement_digest: felt252,
    g_attestation: felt252,
    expected_n_reveal: felt252,
    expected_n_leave: felt252,
    expected_n_recon: felt252,
) {
    let (existing_digest, _, existing_flag) = self.bindings.read(hand_binding);
    assert!(
        existing_flag == 0 && existing_digest == 0,
        "Binding already registered"
    );
    self.bindings.write(hand_binding, (settlement_digest, g_attestation, 1));
    self.expected_packed.write(
        hand_binding,
        pack_expected_counts(expected_n_reveal, expected_n_leave, expected_n_recon),
    );
    self.emit(HandRegistered { hand_binding, settlement_digest, g_attestation });
}

/// Shared DAPV prelude (linear + proved entries): common bounds/replay
/// checks, batch-domain binding, registration read and settlement-digest
/// recompute. Returns the registered digest.
fn dapv_prelude(
    self: @ContractState,
    hand_binding: felt252,
    hand_id_bytes: Span<u8>,
    hand_id: u64,
    players: Span<ContractAddress>,
    deltas: Span<i128>,
) -> felt252 {
    assert_settle_common(self, hand_binding, players, deltas);
    assert!(
        bytes_to_felt(hand_id_bytes) == hand_binding,
        "Batch domain not bound to hand_binding"
    );
    let registered_digest = read_registered_digest(self, hand_binding);
    let computed = compute_settlement_digest(hand_id, players, deltas);
    assert!(computed == registered_digest, "Settlement digest mismatch");
    registered_digest
}

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        /// Authorized operators (Phase 1: control G registration).
        provers: Map<ContractAddress, bool>,
        /// Vault contract holding chip balances.
        vault_address: ContractAddress,
        /// Registered bindings: binding → (settlement_digest, g_attestation,
        /// registered flag as 1).
        bindings: Map<felt252, (felt252, felt252, felt252)>,
        /// Completeness hardening: registered expected bucket counts,
        /// packed (see `pack_expected_counts`); 0 = unconstrained.
        expected_packed: Map<felt252, felt252>,
        /// Settled bindings (replay protection).
        settled_bindings: Map<felt252, bool>,
        /// Part A Phase 1: claim escrow helper receiving winners' pots.
        claim_helper: ContractAddress,
        /// (hand_binding, seat_index) → claim commitment
        /// `poseidon(pk_lo, pk_hi, hand_binding, amount_lo, amount_hi)`.
        claim_cms: Map<(felt252, u32), felt252>,
        /// (hand_binding, seat_index) → claimable amount.
        claim_amounts: Map<(felt252, u32), u256>,
        /// (hand_binding, seat_index) → consumed flag (anti double-claim).
        claims_consumed: Map<(felt252, u32), bool>,
        /// P2-M3：钉死的 settlement_private 电路 program hash（fact 绑定根）。
        circuit_program_hash: felt252,
        /// P2-M3：已登记的证明 fact（fact-registry 过渡形态）。
        settlement_facts: Map<felt252, bool>,
        /// P2-M3：v2 手的金额藏在 cm 中（consume_claim 走隐藏模式）。
        amounts_hidden: Map<felt252, bool>,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        HandRegistered: HandRegistered,
        DualProofSettled: DualProofSettled,
        ProverSet: ProverSet,
        ClaimHelperSet: ClaimHelperSet,
        DualProofSettledPrivate: DualProofSettledPrivate,
        ClaimConsumed: ClaimConsumed,
        SettlementFactRegistered: SettlementFactRegistered,
        DualProofSettledPrivateV2: DualProofSettledPrivateV2,
    }

    #[derive(Drop, starknet::Event)]
    struct ClaimHelperSet {
        helper: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct DualProofSettledPrivate {
        hand_binding: felt252,
        settlement_digest: felt252,
        participant_count: u32,
        total_winnings: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ClaimConsumed {
        hand_binding: felt252,
        seat_index: u32,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct SettlementFactRegistered {
        fact: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct DualProofSettledPrivateV2 {
        hand_binding: felt252,
        settlement_digest: felt252,
        participant_count: u32,
        total_winnings: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct HandRegistered {
        hand_binding: felt252,
        settlement_digest: felt252,
        g_attestation: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct DualProofSettled {
        hand_binding: felt252,
        settlement_digest: felt252,
        participant_count: u32,
        p_proofs_verified: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct ProverSet {
        prover: ContractAddress,
        authorized: bool,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        vault_address: ContractAddress,
        initial_prover: ContractAddress,
    ) {
        self.ownable.initializer(owner);
        self.vault_address.write(vault_address);
        if !initial_prover.is_zero() {
            self.provers.write(initial_prover, true);
        }
    }

    #[abi(embed_v0)]
    impl IPokerDualSettlementImpl of super::IPokerDualSettlement<ContractState> {
        fn register_hand(
            ref self: ContractState,
            hand_binding: felt252,
            settlement_digest: felt252,
            g_attestation: felt252,
            expected_n_reveal: felt252,
            expected_n_leave: felt252,
            expected_n_recon: felt252,
        ) {
            let caller = starknet::get_caller_address();
            assert!(self.provers.read(caller), "Caller not authorized prover");
            assert!(hand_binding != 0, "Zero binding");
            write_registration(
                ref self,
                hand_binding,
                settlement_digest,
                g_attestation,
                expected_n_reveal,
                expected_n_leave,
                expected_n_recon,
            );
        }

        fn verify_and_settle_dapv_stark(
            ref self: ContractState,
            hand_binding: felt252,
            hand_id_bytes: Span<u8>,
            hand_id: u64,
            players: Span<ContractAddress>,
            deltas: Span<i128>,
            p_batch: Span<felt252>,
        ) {
            let registered_digest =
                dapv_prelude(@self, hand_binding, hand_id_bytes, hand_id, players, deltas);

            assert!(p_batch.len() >= 1_u32, "Empty batch");
            let n_own: u32 = (*p_batch.at(0)).try_into().expect('n_own fits u32');
            assert!(
                n_own == players.len(),
                "Every participant needs an endorsement"
            );

            // Completeness hardening (pk binding): the ownership bucket pks
            // must be pairwise DISTINCT — without this, one player's
            // endorsement could be repeated to pad `n_own` up to
            // players.len(). O(n²) compares on pk_x; n_own < 10 so this is
            // trivial cost. NOTE: full pk↔player-address binding needs a
            // player→pk registry which does not exist yet (known seam —
            // deliberately not invented here). Cursors advance by 5 (one
            // own-entry stride) instead of recomputing 5+5*i per compare.
            let own_end: u32 = 5 + 5 * n_own;
            // audit C1：ownership 去重循环读取 [5, own_end) 前先钉住长度，
            // 否则构造端 batch_words 缺词时 Span::at 越界 panic → 结算交易
            // 持续 revert（该手链上结算丢失）。
            assert!(p_batch.len() >= own_end, "batch too short for ownership");
            let mut a_off: u32 = 5;
            while a_off < own_end {
                let mut b_off: u32 = a_off + 5;
                while b_off < own_end {
                    assert!(
                        *p_batch.at(a_off) != *p_batch.at(b_off),
                        "Duplicate ownership pk"
                    );
                    b_off += 5;
                }
                a_off += 5;
            }

            // Completeness hardening (expected bucket counts): when the
            // registrar pinned non-zero expected counts, the submitted
            // batch header must match. The three counts are stored and
            // compared as ONE packed felt (n_reveal + n_leave·2^64 +
            // n_recon·2^128 — counts are < 2^64), both to keep the storage
            // read scalar and the comparison a single felt equality; an
            // all-zero packed value = unconstrained (legacy default, keeps
            // existing registrations working).
            let expected_packed = self.expected_packed.read(hand_binding);
            let header_packed = *p_batch.at(2)
                + *p_batch.at(3) * EXPECTED_PACK_SHIFT
                + *p_batch.at(4) * EXPECTED_PACK_SHIFT2;
            assert!(
                expected_packed == 0 || header_packed == expected_packed,
                "Bucket counts != registered expectation"
            );

            assert!(
                verify_hand_batch_stark(hand_binding, p_batch),
                "DAPV STARK batch rejected"
            );

            assert_zero_sum(deltas);

            let vault_addr = self.vault_address.read();
            apply_deltas_through_vault(vault_addr, players, deltas);

            self.settled_bindings.write(hand_binding, true);
            self.emit(
                DualProofSettled {
                    hand_binding,
                    settlement_digest: registered_digest,
                    participant_count: players.len(),
                    p_proofs_verified: n_own,
                },
            );
        }

        /// Proved-mode settlement (see the interface doc for the honest
        /// interim trust model): p_batch stays off-chain; the caller must
        /// be a whitelisted prover and must present exactly the
        /// (p_batch_commitment, p_batch_len) recorded at registration.
        ///
        /// Everything the linear entry checks inside the batch — the ρ-fold
        /// residual, distinct ownership pks, `n_own == players.len()` and
        /// the expected bucket counts stored below — is attested by the
        /// prover OFF-CHAIN; a future STARK fact-registry / SNIP-36
        /// verifier replaces the whitelist with proof verification.
        fn set_prover(ref self: ContractState, prover: ContractAddress) {
            self.ownable.assert_only_owner();
            if !prover.is_zero() {
                self.provers.write(prover, true);
                self.emit(ProverSet { prover, authorized: true });
            }
        }

        fn remove_prover(ref self: ContractState, prover: ContractAddress) {
            self.ownable.assert_only_owner();
            self.provers.write(prover, false);
            self.emit(ProverSet { prover, authorized: false });
        }

        fn is_prover(self: @ContractState, prover: ContractAddress) -> bool {
            self.provers.read(prover)
        }

        fn hand_binding(self: @ContractState, binding: felt252) -> (felt252, felt252, felt252) {
            self.bindings.read(binding)
        }

        fn hand_settled(self: @ContractState, binding: felt252) -> bool {
            self.settled_bindings.read(binding)
        }

        fn vault(self: @ContractState) -> ContractAddress {
            self.vault_address.read()
        }

        fn set_claim_helper(ref self: ContractState, helper: ContractAddress) {
            self.ownable.assert_only_owner();
            self.claim_helper.write(helper);
            self.emit(ClaimHelperSet { helper });
        }

        /// Part A Phase 1 隐私结算（见接口文档）。DAPV 校验逐字复用
        /// `verify_and_settle_dapv_stark` 的路径；派奖按赢家/输家分流。
        fn verify_and_settle_dapv_stark_private(
            ref self: ContractState,
            hand_binding: felt252,
            hand_id_bytes: Span<u8>,
            hand_id: u64,
            players: Span<ContractAddress>,
            deltas: Span<i128>,
            p_batch: Span<felt252>,
        ) {
            let registered_digest =
                dapv_prelude(@self, hand_binding, hand_id_bytes, hand_id, players, deltas);

            assert!(p_batch.len() >= 1_u32, "Empty batch");
            let n_own: u32 = (*p_batch.at(0)).try_into().expect('n_own fits u32');
            assert!(
                n_own == players.len(),
                "Every participant needs an endorsement"
            );
            assert!(
                verify_hand_batch_stark(hand_binding, p_batch),
                "DAPV STARK batch rejected"
            );

            assert_zero_sum(deltas);

            // 派奖分流：输家公开扣款（Phase 1 残余）；赢家进认领托管。
            let vault_addr = self.vault_address.read();
            let helper = self.claim_helper.read();
            assert!(!helper.is_zero(), "Claim helper not set");
            let mut total_winnings: u256 = 0;
            let mut i: u32 = 0;
            while i < players.len() {
                let player = *players.at(i);
                let delta = *deltas.at(i);
                if delta > 0_i128 {
                    // 赢家：公开 chip 余额不动，改为写认领承诺并 funding 托管。
                    let delta_u64: u64 = delta.try_into().expect('win fits u64');
                    let amount: u256 = delta_u64.into();
                    let vault = super::IVaultDispatcherDispatcher { contract_address: vault_addr };
                    let commitment = vault.payout_commitment(player);
                    assert!(commitment != 0, "Payout commitment not registered");
                    // cm = poseidon(commitment, hand_binding, amount_lo, amount_hi)：
                    // 认领方须揭示 commitment 的原像 secret（capability 模型）。
                    let cm = poseidon_hash_span(
                        array![
                            commitment,
                            hand_binding,
                            amount.low.into(),
                            amount.high.into()
                        ]
                        .span(),
                    );
                    self.claim_cms.write((hand_binding, i), cm);
                    self.claim_amounts.write((hand_binding, i), amount);
                    self.claims_consumed.write((hand_binding, i), false);
                    total_winnings += amount;
                } else if delta < 0_i128 {
                    // 输家：公开扣款（Phase 1 已知残余，Phase 2 ZK 消除）。
                    let vault = super::IVaultDispatcherDispatcher { contract_address: vault_addr };
                    vault.apply_settlement(player, delta);
                }
                i += 1;
            }
            assert!(total_winnings > 0_u256, "No winnings to escrow");
            let vault = super::IVaultDispatcherDispatcher { contract_address: vault_addr };
            vault.settlement_fund_escrow(helper, hand_binding, total_winnings);

            self.settled_bindings.write(hand_binding, true);
            self.emit(
                DualProofSettledPrivate {
                    hand_binding,
                    settlement_digest: registered_digest,
                    participant_count: players.len(),
                    total_winnings,
                },
            );
        }

        fn claim_cm(self: @ContractState, hand_binding: felt252, seat_index: u32) -> felt252 {
            self.claim_cms.read((hand_binding, seat_index))
        }

        fn claim_amount(
            self: @ContractState,
            hand_binding: felt252,
            seat_index: u32,
        ) -> u256 {
            self.claim_amounts.read((hand_binding, seat_index))
        }

        fn consume_claim(
            ref self: ContractState,
            hand_binding: felt252,
            seat_index: u32,
            amount: u256,
        ) {
            let caller = starknet::get_caller_address();
            assert!(caller == self.claim_helper.read(), "Only claim helper");
            let expected = self.claim_amounts.read((hand_binding, seat_index));
            assert!(expected == amount, "Claim amount mismatch");
            assert!(
                !self.claims_consumed.read((hand_binding, seat_index)),
                "Claim already consumed"
            );
            self.claims_consumed.write((hand_binding, seat_index), true);
            self.emit(ClaimConsumed { hand_binding, seat_index, amount });
        }

        fn claim_helper(self: @ContractState) -> ContractAddress {
            self.claim_helper.read()
        }

        fn set_circuit_program_hash(ref self: ContractState, program_hash: felt252) {
            self.ownable.assert_only_owner();
            assert!(program_hash != 0, "Zero program hash");
            self.circuit_program_hash.write(program_hash);
        }

        fn register_settlement_fact(ref self: ContractState, fact: felt252) {
            let caller = starknet::get_caller_address();
            assert!(
                caller == self.ownable.owner() || self.provers.read(caller),
                "Caller not authorized"
            );
            assert!(fact != 0, "Zero fact");
            self.settlement_facts.write(fact, true);
            self.emit(SettlementFactRegistered { fact });
        }

        fn circuit_program_hash(self: @ContractState) -> felt252 {
            self.circuit_program_hash.read()
        }

        fn settlement_fact(self: @ContractState, fact: felt252) -> bool {
            self.settlement_facts.read(fact)
        }

        fn amounts_hidden(self: @ContractState, hand_binding: felt252) -> bool {
            self.amounts_hidden.read(hand_binding)
        }

        /// P2-M3：零明文结算（见接口文档）。digest 取注册值，托管金额与
        /// claim_cms 全部来自已证明的公开段。
        fn verify_and_settle_dapv_stark_private_v2(
            ref self: ContractState,
            hand_binding: felt252,
            hand_id: u64,
            segment: Span<felt252>,
        ) {
            assert!(hand_binding != 0, "Zero binding");
            assert!(
                !self.settled_bindings.read(hand_binding),
                "Hand already settled"
            );
            assert!(segment.len() == SETTLEMENT_SEGMENT_LEN, "Segment length mismatch");
            assert!(
                *segment.at(0) == SETTLEMENT_SEGMENT_MAGIC,
                "Segment magic mismatch"
            );
            assert!(*segment.at(1) == hand_id.into(), "Segment hand_id mismatch");
            assert!(*segment.at(4) == hand_binding, "Segment binding mismatch");
            let n: u32 = (*segment.at(3)).try_into().expect('n fits u32');
            assert!(n >= 2_u32 && n <= 8_u32, "Participant count out of range");
            // digest 取 register_aggregate 时的注册值（无明文参与比对）
            let registered_digest = read_registered_digest(@self, hand_binding);
            assert!(*segment.at(2) == registered_digest, "Segment digest mismatch");
            // fact-registry 锚：fact = poseidon([program_hash ++ segment])，
            // 由授权 prover/owner 在 prove-hand 之后登记。
            let program_hash = self.circuit_program_hash.read();
            assert!(program_hash != 0, "Circuit program hash not set");
            let fact = fact_for_segment(program_hash, segment);
            assert!(
                self.settlement_facts.read(fact),
                "Settlement fact not registered"
            );

            let total_u128: u128 = (*segment.at(13)).try_into().expect('total fits u128');
            let total_winnings: u256 = total_u128.into();
            assert!(total_winnings > 0_u256, "No winnings to escrow");
            let vault_addr = self.vault_address.read();
            let helper = self.claim_helper.read();
            assert!(!helper.is_zero(), "Claim helper not set");
            let vault = super::IVaultDispatcherDispatcher { contract_address: vault_addr };
            vault.settlement_fund_escrow(helper, hand_binding, total_winnings);
            let mut i: u32 = 0;
            while i < 8_u32 {
                self.claim_cms.write((hand_binding, i), *segment.at(5 + i));
                i += 1;
            }
            self.amounts_hidden.write(hand_binding, true);
            self.settled_bindings.write(hand_binding, true);
            self.emit(
                DualProofSettledPrivateV2 {
                    hand_binding,
                    settlement_digest: registered_digest,
                    participant_count: n,
                    total_winnings,
                },
            );
        }
    }
}


/// Minimal vault interface consumed by the settlement contract.
#[starknet::interface]
pub trait IVaultDispatcher<TContractState> {
    fn apply_settlement(ref self: TContractState, player: ContractAddress, delta: i128);
    /// Part A Phase 1: read the player's registered payout commitment.
    fn payout_commitment(self: @TContractState, player: ContractAddress) -> felt252;
    /// Part A Phase 1: fund the claim escrow with the winners' pot.
    fn settlement_fund_escrow(
        ref self: TContractState,
        escrow: ContractAddress,
        hand_binding: felt252,
        amount: u256,
    );
}

// ============================================================
// Tests (snforge): mock vault + deploy through the dispatcher so
// register/settle run through the real prover-gate paths.
// ============================================================

// ============================================================
// Tests (snforge): P2-M3 零明文结算 v2 — fact-registry 锚定公开段。
// MockVault 记录 escrow 划转；register 用 prover 授权（test 合约即
// initial_prover）；电路公开段由测试内 Poseidon 复算（与 Cairo 电路
// 及 Rust 参考三方一致）。
// ============================================================

#[cfg(test)]
mod settlement_private_v2_tests {
    use core::hash::HashStateTrait;
    use core::poseidon::PoseidonTrait;
    use starknet::{ContractAddress, get_contract_address};
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};

    use super::mock_vault::IMockVaultDispatcherTrait;
    use super::mock_vault::IMockVaultDispatcher;
    use super::{
        IPokerDualSettlement, IPokerDualSettlementDispatcher,
        IPokerDualSettlementDispatcherTrait,
    };

    const MAGIC: felt252 = 0x5350324d5f4f4b;
    const PROGRAM_HASH: felt252 = 0xabcdef;

    fn deploy_contract(name: ByteArray, calldata: @Array<felt252>) -> ContractAddress {
        let class = declare(name).unwrap().contract_class();
        let (address, _) = class.deploy(calldata).unwrap();
        address
    }

    struct Setup {
        dual: IPokerDualSettlementDispatcher,
        vault: IMockVaultDispatcher,
        hand_binding: felt252,
        digest: felt252,
        segment: Array<felt252>,
        total: felt252,
    }

    /// 部署 mock vault + dual（test 合约为 owner 与 initial_prover），
    /// 注册 binding（digest=0x99..）、钉 program hash，构造诚实公开段并
    /// 登记 fact。`tamper` 可选：覆盖 segment 的 digest 槽。
    fn setup(tamper_digest: bool, with_fact: bool) -> Setup {
        let test_addr = get_contract_address();
        let vault = deploy_contract("MockVault", @array![]);
        let dual_addr = deploy_contract(
            "PokerDualSettlement",
            @array![test_addr.into(), vault.into(), test_addr.into()],
        );
        let dual = IPokerDualSettlementDispatcher { contract_address: dual_addr };
        dual.set_claim_helper(test_addr);
        dual.set_circuit_program_hash(PROGRAM_HASH);

        let hand_binding: felt252 = 0xBBBB;
        let hand_id: u64 = 42;
        let digest: felt252 = 0x9900;
        // 与 register_hand 一致的注册（prover = test_addr）
        dual.register_hand(hand_binding, digest, 0, 0, 0, 0);

        // 公开段：赢家 seat0（+3000），输家 seat1/2，其余零变动
        let mut cms = array![];
        let mut total: felt252 = 0;
        let commitment = 0x21;
        let binding = hand_binding;
        let mut i: u32 = 0;
        while i < 8_u32 {
            let (s, m): (felt252, felt252) = if i == 0 {
                (1, 3000)
            } else if i == 1 {
                (0, 2000)
            } else if i == 2 {
                (0, 1000)
            } else {
                (1, 0)
            };
            i += 1;
            if s == 1 {
                if m != 0 {
                    total += m;
                    let mut ch = PoseidonTrait::new();
                    ch = ch.update(commitment);
                    ch = ch.update(binding);
                    ch = ch.update(m);
                    ch = ch.update(0);
                    cms.append(ch.finalize());
                } else {
                    cms.append(0);
                };
            } else {
                cms.append(0);
            };
        }

        // tamper_digest：segment 的 digest 槽换成 0xDEAD（注册值仍是真 digest）
        let digest_in_segment: felt252 = if tamper_digest { 0xDEAD } else { digest };
        let mut segment = array![MAGIC, hand_id.into(), digest_in_segment, 3, binding];
        let mut w: u32 = 0;
        while w < 8_u32 {
            segment.append(*cms.at(w));
            w += 1;
        };
        segment.append(total);

        if with_fact {
            // fact = poseidon([program_hash ++ segment])（与合约公式一致）
            let mut f = PoseidonTrait::new();
            f = f.update(PROGRAM_HASH);
            let mut w: u32 = 0;
            while w < segment.len() {
                f = f.update(*segment.at(w));
                w += 1;
            }
            dual.register_settlement_fact(f.finalize());
        }

        Setup {
            dual,
            vault: IMockVaultDispatcher { contract_address: vault },
            hand_binding,
            digest,
            segment,
            total,
        }
    }

    #[test]
    fn v2_honest_segment_settles_without_plaintext_calldata() {
        let s = setup(false, true);
        // v2 calldata：只有 (hand_binding, hand_id, segment)——无 players/deltas
        s.dual
            .verify_and_settle_dapv_stark_private_v2(s.hand_binding, 42, s.segment.span());
        assert!(s.dual.hand_settled(s.hand_binding), "hand must be settled");
        // claim_cms 来自公开段（seat0 = 赢家承诺）
        let mut ch = PoseidonTrait::new();
        ch = ch.update(0x21);
        ch = ch.update(s.hand_binding);
        ch = ch.update(3000);
        ch = ch.update(0);
        assert!(s.dual.claim_cm(s.hand_binding, 0) == ch.finalize(), "cm0");
        assert!(s.dual.claim_cm(s.hand_binding, 1) == 0, "non-winner cm must be zero");
        // 托管金额 = 公开段 total_winnings
        let total_u256: u256 = s.total.into();
        assert!(
            s.vault.escrowed_for(s.hand_binding) == total_u256,
            "escrow must equal total_winnings"
        );
    }

    #[test]
    #[should_panic(expected: "Segment digest mismatch")]
    fn v2_tampered_digest_reverts() {
        let s = setup(true, true);
        s.dual
            .verify_and_settle_dapv_stark_private_v2(s.hand_binding, 42, s.segment.span());
    }

    #[test]
    #[should_panic(expected: "Settlement fact not registered")]
    fn v2_missing_fact_reverts() {
        let s = setup(false, false);
        s.dual
            .verify_and_settle_dapv_stark_private_v2(s.hand_binding, 42, s.segment.span());
    }

    #[test]
    #[should_panic(expected: "Hand already settled")]
    fn v2_replay_reverts() {
        let s = setup(false, true);
        s.dual
            .verify_and_settle_dapv_stark_private_v2(s.hand_binding, 42, s.segment.span());
        s.dual
            .verify_and_settle_dapv_stark_private_v2(s.hand_binding, 42, s.segment.span());
    }
}

/// P2-M3 测试用 MockVault：记录 escrow 划转，payout_commitment 返回常数。
#[cfg(test)]
mod mock_vault {
    use starknet::ContractAddress;
    use starknet::storage::{StorageMapReadAccess, StorageMapWriteAccess};

    #[starknet::interface]
    pub trait IMockVault<TContractState> {
        fn payout_commitment(self: @TContractState, player: ContractAddress) -> felt252;
        fn settlement_fund_escrow(
            ref self: TContractState,
            escrow: ContractAddress,
            hand_binding: felt252,
            amount: u256,
        );
        fn apply_settlement(ref self: TContractState, player: ContractAddress, delta: i128);
        fn escrowed_for(self: @TContractState, hand_binding: felt252) -> u256;
    }

    #[starknet::contract]
    pub mod MockVault {
        use starknet::ContractAddress;
        use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};

        #[storage]
        struct Storage {
            escrowed: Map<felt252, u256>,
        }

        #[event]
        #[derive(Drop, starknet::Event)]
        enum Event {
            EscrowFunded: EscrowFunded,
        }

        #[derive(Drop, starknet::Event)]
        struct EscrowFunded {
            escrow: ContractAddress,
            hand_binding: felt252,
            amount: u256,
        }

        #[constructor]
        fn constructor(ref self: ContractState) {}

        #[abi(embed_v0)]
        impl IMockVaultImpl of super::IMockVault<ContractState> {
            fn payout_commitment(self: @ContractState, player: ContractAddress) -> felt252 {
                0x1234
            }

            fn settlement_fund_escrow(
                ref self: ContractState,
                escrow: ContractAddress,
                hand_binding: felt252,
                amount: u256,
            ) {
                let current = self.escrowed.read(hand_binding);
                self.escrowed.write(hand_binding, current + amount);
                self.emit(EscrowFunded { escrow, hand_binding, amount });
            }

            fn apply_settlement(
                ref self: ContractState,
                player: ContractAddress,
                delta: i128,
            ) {
            }

            fn escrowed_for(self: @ContractState, hand_binding: felt252) -> u256 {
                self.escrowed.read(hand_binding)
            }
        }
    }
}
