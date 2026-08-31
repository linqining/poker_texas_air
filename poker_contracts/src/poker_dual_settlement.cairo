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
}

#[starknet::contract]
pub mod PokerDualSettlement {
    use openzeppelin::access::ownable::OwnableComponent;
    use starknet::ContractAddress;
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use super::super::dual::hand_batch_stark::verify_hand_batch_stark;
    use super::IVaultDispatcherDispatcherTrait;

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
    }
}

/// Minimal vault interface consumed by the settlement contract.
#[starknet::interface]
pub trait IVaultDispatcher<TContractState> {
    fn apply_settlement(ref self: TContractState, player: ContractAddress, delta: i128);
}

// ============================================================
// Tests (snforge): mock vault + deploy through the dispatcher so
// register/settle run through the real prover-gate paths.
// ============================================================
