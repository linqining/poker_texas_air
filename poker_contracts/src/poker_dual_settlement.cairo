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

    /// Proved-mode registration (authorized prover only): same as
    /// `register_hand`, plus the commitment binding the off-chain-verified
    /// hand-batch to exactly this registration.
    ///
    /// `p_batch_commitment` —
    /// `poseidon(hand_binding, poseidon(p_batch words))` (Rust:
    /// `dual_settle::compute_p_batch_commitment`). The proved settle entry
    /// refuses any commitment other than the registered one, so a
    /// whitelisted prover can only attest the exact batch the server
    /// registered.
    /// `p_batch_len` — word count of the attested batch (recorded for the
    /// prover tooling / observability; checked at settle time).
    fn register_hand_proved(
        ref self: TContractState,
        hand_binding: felt252,
        settlement_digest: felt252,
        g_attestation: felt252,
        p_batch_commitment: felt252,
        p_batch_len: felt252,
        expected_n_reveal: felt252,
        expected_n_leave: felt252,
        expected_n_recon: felt252,
    );

    /// Verify all P proofs on-chain and settle the hand.
    ///
    /// `p_proof_payloads` — concatenated per-player proof payloads; each is
    /// `kind: u8`-prefixed by convention and parsed by the verifier
    /// (`sigma_verifier::verify_p_proof`). Ownership proofs are verified
    /// directly; shuffle/fold/reveal kinds are fail-closed until the Garaga
    /// upgrade.
    /// Verify all P proofs on-chain and settle the hand.
    ///
    /// Generic per-proof framing: for each proof `i`, `p_proof_kinds[i]` is
    /// the verifier discriminant (ownership = 1, fold DLEQ = 3, reveal
    /// tokens = 4), `p_proof_lens[i]` the limb count of that proof, and the
    /// limbs are packed back-to-back in `p_proof_limbs`. Every proof is
    /// checked by the EC_OP builtin-backed verifier with `protocol_name`
    /// replayed into the Keccak transcript; BG shuffle (kind 2) is
    /// fail-closed pending its on-chain wiring (§4.2).
    fn verify_and_settle(
        ref self: TContractState,
        protocol_name: Span<u8>,
        hand_binding: felt252,
        hand_id: u64,
        players: Span<ContractAddress>,
        deltas: Span<i128>,
        p_proof_kinds: Span<felt252>,
        p_proof_lens: Span<felt252>,
        p_proof_limbs: Span<u256>,
    );

    /// DAPV settlement (DUAL_PROOF_PROTOCOL.md v2.8 / DAPV_SOUNDNESS.md):
    /// the whole P layer is folded into ONE residual check
    /// `L == Σ ρⁱ·Lᵢ == O` on-chain (`dual::hand_batch::verify_hand_batch`),
    /// instead of one verifier call per proof.
    ///
    /// `hand_id_bytes` — the 32 big-endian bytes of `hand_binding`; the
    /// batch's transcript domain and ρ derive from it, binding every folded
    /// proof to exactly this registered hand instance (replay protection:
    /// §9-L2 via the hand-prefixed ownership challenge, §8 for the fold).
    /// `p_batch` — the hand-batch payload layout documented on
    /// `verify_hand_batch` ([n_own, n_reveal, n_fold, proofs…], u256 words).
    /// Every settling participant must appear as an ownership endorsement
    /// (`n_own == players.len()`).
    fn verify_and_settle_dapv(
        ref self: TContractState,
        hand_binding: felt252,
        hand_id_bytes: Span<u8>,
        hand_id: u64,
        players: Span<ContractAddress>,
        deltas: Span<i128>,
        p_batch: Span<u256>,
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

    /// Proved-mode settlement: the hand-batch does NOT go on-chain. The
    /// call carries only the batch commitment registered in
    /// `register_hand_proved`, and settlement is accepted **if the caller
    /// is a whitelisted prover** (`provers` map).
    ///
    /// INTERIM TRUST MODEL — stated honestly: this is a prover-attestation
    /// model, not a proof model. Until a STARK fact-registry / SNIP-36
    /// verifier is wired in, the on-chain check is exactly:
    ///   (a) the usual binding/digest/zero-sum/bounds checks below, and
    ///   (b) the submitted (p_batch_commitment, p_batch_len) equals the
    ///       pair recorded at registration, and
    ///   (c) the caller is a whitelisted prover.
    /// The prover is trusted to have verified off-chain everything the
    /// linear entry verifies on-chain: the ρ-fold residual
    /// `L == O`, distinct ownership pks, `n_own == players.len()`, and the
    /// registered expected bucket counts ([n_reveal, n_leave, n_recon] are
    /// stored here at registration and checked by the prover, NOT on-chain
    /// — the header words are in the off-chain batch). Full pk↔player
    /// binding additionally needs a player→pk registry which does not
    /// exist yet (known seam, not invented here).
    fn verify_and_settle_dapv_proved(
        ref self: TContractState,
        hand_binding: felt252,
        hand_id_bytes: Span<u8>,
        hand_id: u64,
        players: Span<ContractAddress>,
        deltas: Span<i128>,
        p_batch_commitment: felt252,
        p_batch_len: felt252,
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
    use super::super::dual::secp256k1_verifier::{verify_p_proof, PROOF_KIND_OWNERSHIP};
    use super::super::dual::hand_batch::verify_hand_batch;
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
        /// Proved-mode registration: binding → (p_batch_commitment,
        /// p_batch_len) recorded by `register_hand_proved`. A
        /// proved-registered binding settles ONLY through
        /// `verify_and_settle_dapv_proved`.
        proved_bindings: Map<felt252, (felt252, felt252)>,
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
        DualProofSettledProved: DualProofSettledProved,
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

    /// Proved-mode settlement: the batch itself never went on-chain — this
    /// event records the commitment (+ word count) a whitelisted prover
    /// attested, which is the only on-chain trace of the P layer.
    #[derive(Drop, starknet::Event)]
    struct DualProofSettledProved {
        hand_binding: felt252,
        settlement_digest: felt252,
        participant_count: u32,
        p_batch_commitment: felt252,
        p_batch_len: felt252,
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

        fn register_hand_proved(
            ref self: ContractState,
            hand_binding: felt252,
            settlement_digest: felt252,
            g_attestation: felt252,
            p_batch_commitment: felt252,
            p_batch_len: felt252,
            expected_n_reveal: felt252,
            expected_n_leave: felt252,
            expected_n_recon: felt252,
        ) {
            let caller = starknet::get_caller_address();
            assert!(self.provers.read(caller), "Caller not authorized prover");
            assert!(hand_binding != 0, "Zero binding");
            // A vacuous zero commitment would let any later call settle
            // "the registered batch" without binding anything (zero tuple
            // = the storage default = "not registered for proved").
            assert!(
                p_batch_commitment != 0 && p_batch_len != 0,
                "Zero p_batch commitment/length"
            );
            self.proved_bindings
                .write(hand_binding, (p_batch_commitment, p_batch_len));
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

        fn verify_and_settle(
            ref self: ContractState,
            protocol_name: Span<u8>,
            hand_binding: felt252,
            hand_id: u64,
            players: Span<ContractAddress>,
            deltas: Span<i128>,
            p_proof_kinds: Span<felt252>,
            p_proof_lens: Span<felt252>,
            p_proof_limbs: Span<u256>,
        ) {
            assert_settle_common(@self, hand_binding, players, deltas);

            // (a) The binding must have been registered (G Phase 1).
            let registered_digest = read_registered_digest(@self, hand_binding);

            // (b) Recompute the settlement commitment over the asserted
            // players/deltas (settlement_hash.cairo layout) and require an
            // exact match with the registered digest.
            // hand_id is folded into the binding upstream; the settlement
            // digest domain tag keeps the two encodings distinct.
            let computed = compute_settlement_digest(hand_id, players, deltas);
            assert!(computed == registered_digest, "Settlement digest mismatch");

            // (c) On-chain P verification: every proof must verify, with the
            // transcript protocol name replayed into each challenge.
            assert!(
                p_proof_kinds.len() == p_proof_lens.len(),
                "P kinds/lens mismatch"
            );
            let mut verified: u32 = 0;
            let mut limb_cursor: u32 = 0;
            let mut k = 0_u32;
            while k < p_proof_kinds.len() {
                let kind_felt = *p_proof_kinds.at(k);
                let kind: u8 = kind_felt.try_into().expect('kind fits u8');
                let len_felt = *p_proof_lens.at(k);
                let len_u32: u32 = len_felt.try_into().expect('len fits u32');
                let mut limbs: Array<u256> = array![];
                let mut j = 0_u32;
                while j < len_u32 {
                    limbs.append(*p_proof_limbs.at(limb_cursor + j));
                    j += 1;
                }
                assert!(
                    verify_p_proof(kind, protocol_name, limbs.span()),
                    "P proof verification failed"
                );
                verified += 1;
                limb_cursor += len_u32;
                k += 1;
            }
            // Every listed player must have had a proof verified.
            assert!(verified == players.len(), "Proof count mismatch");

            // (d) Zero-sum.
            let zero: i128 = 0_i128;
            let mut sum: i128 = 0_i128;
            let mut d = 0_u32;
            while d < deltas.len() {
                sum += *deltas.at(d);
                d += 1;
            }
            assert!(sum == zero, "Settlement not zero-sum");

            // Apply per-player net deltas through the vault.
            let vault_addr = self.vault_address.read();
            let mut m = 0_u32;
            while m < players.len() {
                let player = *players.at(m);
                let delta = *deltas.at(m);
                let vault = super::IVaultDispatcherDispatcher { contract_address: vault_addr };
                vault.apply_settlement(player, delta);
                m += 1;
            }

            self.settled_bindings.write(hand_binding, true);
            self.emit(
                DualProofSettled {
                    hand_binding,
                    settlement_digest: registered_digest,
                    participant_count: players.len(),
                    p_proofs_verified: verified,
                },
            );
        }

        fn verify_and_settle_dapv(
            ref self: ContractState,
            hand_binding: felt252,
            hand_id_bytes: Span<u8>,
            hand_id: u64,
            players: Span<ContractAddress>,
            deltas: Span<i128>,
            p_batch: Span<u256>,
        ) {
            // (a)+(b) shared DAPV prelude: bounds/replay, batch-domain
            // binding, registration read, settlement-digest recompute.
            let registered_digest =
                dapv_prelude(@self, hand_binding, hand_id_bytes, hand_id, players, deltas);

            // (b) Recompute the settlement commitment (same layout as
            // verify_and_settle / settlement_hash.cairo) and require an
            // exact match with the registered digest.
            let computed = compute_settlement_digest(hand_id, players, deltas);
            assert!(computed == registered_digest, "Settlement digest mismatch");

            // (c) DAPV: every settling participant must have endorsed via an
            // ownership proof inside the batch, and the whole P layer must
            // fold to L == O under the hand-bound rho.
            assert!(p_batch.len() >= 1_u32, "Empty batch");
            let n_own_f = *p_batch.at(0);
            let n_own: u32 = n_own_f.try_into().expect('n_own fits u32');
            assert!(
                n_own == players.len(),
                "Every participant needs an endorsement"
            );
            assert!(
                verify_hand_batch(hand_id_bytes, p_batch),
                "DAPV batch rejected"
            );

            // (d) Zero-sum.
            assert_zero_sum(deltas);

            // Apply per-player net deltas through the vault.
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

        /// Plan D STARK-curve settlement: same binding/digest/zero-sum
        /// checks as `verify_and_settle_dapv`; the P layer folds through
        /// `hand_batch_stark` on the EC_OP builtin. Accepts ownership-only
        /// batches with felt252-range payload words.
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
        fn verify_and_settle_dapv_proved(
            ref self: ContractState,
            hand_binding: felt252,
            hand_id_bytes: Span<u8>,
            hand_id: u64,
            players: Span<ContractAddress>,
            deltas: Span<i128>,
            p_batch_commitment: felt252,
            p_batch_len: felt252,
        ) {
            // The attestation IS the whitelisted caller (interim model).
            let caller = starknet::get_caller_address();
            assert!(self.provers.read(caller), "Caller not authorized prover");

            // Shared DAPV prelude (bounds/replay, batch-domain binding,
            // registration read, settlement-digest recompute).
            let registered_digest =
                dapv_prelude(@self, hand_binding, hand_id_bytes, hand_id, players, deltas);

            // Bind the attested batch to exactly the registered one. The
            // commitment itself CANNOT be recomputed on-chain (the words
            // are not here — that is the point of proved mode), so this is
            // an equality check against `register_hand_proved`'s record;
            // commitment == 0 also catches "not registered for proved".
            let (reg_commitment, reg_len) = self.proved_bindings.read(hand_binding);
            assert!(
                reg_commitment != 0
                    && reg_commitment == p_batch_commitment
                    && reg_len == p_batch_len,
                "Proved commitment/length mismatch (or not registered)"
            );

            // Same settlement-digest recompute as the linear entries: the
            // prover's attestation cannot back a different payout.
            let computed = compute_settlement_digest(hand_id, players, deltas);
            assert!(computed == registered_digest, "Settlement digest mismatch");

            assert_zero_sum(deltas);

            let vault_addr = self.vault_address.read();
            apply_deltas_through_vault(vault_addr, players, deltas);

            self.settled_bindings.write(hand_binding, true);
            self.emit(
                DualProofSettledProved {
                    hand_binding,
                    settlement_digest: registered_digest,
                    participant_count: players.len(),
                    p_batch_commitment,
                    p_batch_len,
                },
            );
        }

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

#[cfg(target: 'test')]
mod mock_vault {
    use starknet::ContractAddress;

    #[starknet::interface]
    pub trait IMockVault<TContractState> {
        fn apply_settlement(ref self: TContractState, player: ContractAddress, delta: i128);
        fn net_delta(self: @TContractState, player: ContractAddress) -> i128;
    }

    /// Minimal stand-in exposing the `apply_settlement` selector the
    /// settlement contract dispatches into; records per-player net deltas.
    #[starknet::contract]
    pub mod MockVault {
        use starknet::{ContractAddress, storage::Map};
        use starknet::storage::{StorageMapReadAccess, StorageMapWriteAccess};

        #[storage]
        struct Storage {
            net: Map<ContractAddress, i128>,
        }

        #[abi(embed_v0)]
        impl MockVaultImpl of super::IMockVault<ContractState> {
            fn apply_settlement(ref self: ContractState, player: ContractAddress, delta: i128) {
                let current = self.net.read(player);
                self.net.write(player, current + delta);
            }

            fn net_delta(self: @ContractState, player: ContractAddress) -> i128 {
                self.net.read(player)
            }
        }
    }
}

#[cfg(target: 'test')]
mod dapv_settlement_tests {
    use core::array::{ArrayTrait, SpanTrait};
    use core::byte_array::ByteArray;
    use core::poseidon::poseidon_hash_span;
    use starknet::{ContractAddress, get_contract_address};
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};

    use crate::dual::hand_batch_stark::tests::{HAND_BINDING, payload};
    use super::mock_vault::{IMockVaultDispatcher, IMockVaultDispatcherTrait};
    use super::{IPokerDualSettlementDispatcher, IPokerDualSettlementDispatcherTrait};

    #[derive(Drop)]
    struct Setup {
        dual: ContractAddress,
        vault: ContractAddress,
        p1: ContractAddress,
        p2: ContractAddress,
    }

    fn deploy_contract(name: ByteArray, calldata: @Array<felt252>) -> ContractAddress {
        let class = declare(name).unwrap().contract_class();
        let (address, _) = class.deploy(calldata).unwrap();
        address
    }

    /// Deploy mock vault + PokerDualSettlement with the test contract as
    /// both owner and whitelisted prover (dispatcher calls then exercise
    /// the real register/settle gates).
    fn setup() -> Setup {
        let test_addr = get_contract_address();
        let vault = deploy_contract("MockVault", @array![]);
        let dual = deploy_contract(
            "PokerDualSettlement",
            @array![test_addr.into(), vault.into(), test_addr.into()],
        );
        Setup {
            dual,
            vault,
            p1: 0x1111.try_into().unwrap(),
            p2: 0x2222.try_into().unwrap(),
        }
    }

    /// The 32 big-endian bytes of HAND_BINDING (0x02 followed by 31×0x5b):
    /// `bytes_to_felt` of these must equal the registered binding.
    fn hand_id_bytes() -> Array<u8> {
        let mut b: Array<u8> = array![0x02];
        let mut i: u32 = 0;
        while i < 31 {
            b.append(0x5b);
            i += 1;
        }
        b
    }

    fn players(s: @Setup) -> Array<ContractAddress> {
        array![*s.p1, *s.p2]
    }

    fn deltas() -> Array<i128> {
        array![100, -100]
    }

    /// Poseidon over the same (hand_id, players, deltas) layout the
    /// contract recomputes at settle time.
    fn settlement_digest(hand_id: u64, players: Span<ContractAddress>, deltas: Span<i128>) -> felt252 {
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

    /// n_own=2 batch whose two ownership entries are the SAME endorsement:
    /// each equation is individually honest so the ρ-fold still hits the
    /// identity — only the distinctness hardening can reject it.
    fn duplicated_pk_payload() -> Array<felt252> {
        let base = payload();
        let mut out: Array<felt252> = array![2, 0, 0, 0, 0];
        let mut round: u32 = 0;
        while round < 2 {
            let mut i: u32 = 0;
            while i < 5 {
                out.append(*base.at(5 + i));
                i += 1;
            }
            round += 1;
        }
        out
    }

    #[test]
    fn linear_stark_settle_accepts_honest_batch() {
        let s = setup();
        let dual = IPokerDualSettlementDispatcher { contract_address: s.dual };
        let players = players(@s);
        let deltas = deltas();
        let digest = settlement_digest(7, players.span(), deltas.span());

        dual.register_hand(HAND_BINDING, digest, 777, 0, 0, 0);
        dual.verify_and_settle_dapv_stark(
            HAND_BINDING,
            hand_id_bytes().span(),
            7,
            players.span(),
            deltas.span(),
            payload().span(),
        );

        assert!(dual.hand_settled(HAND_BINDING), "hand must be settled");
        let vault = IMockVaultDispatcher { contract_address: s.vault };
        assert!(vault.net_delta(s.p1) == 100, "p1 delta applied");
        assert!(vault.net_delta(s.p2) == -100, "p2 delta applied");
        let (digest_out, g_out, flag) = dual.hand_binding(HAND_BINDING);
        assert!(digest_out == digest && g_out == 777 && flag == 1, "registration record");
    }

    #[test]
    #[should_panic(expected: "Bucket counts != registered expectation")]
    fn linear_settle_rejects_wrong_expected_bucket_count() {
        let s = setup();
        let dual = IPokerDualSettlementDispatcher { contract_address: s.dual };
        let players = players(@s);
        let deltas = deltas();
        let digest = settlement_digest(7, players.span(), deltas.span());
        // Payload header has n_reveal = 0; registration pinned 1.
        dual.register_hand(HAND_BINDING, digest, 777, 1, 0, 0);
        dual.verify_and_settle_dapv_stark(
            HAND_BINDING,
            hand_id_bytes().span(),
            7,
            players.span(),
            deltas.span(),
            payload().span(),
        );
    }

    #[test]
    #[should_panic(expected: "Duplicate ownership pk")]
    fn linear_settle_rejects_duplicate_ownership_pks() {
        let s = setup();
        let dual = IPokerDualSettlementDispatcher { contract_address: s.dual };
        let players = players(@s);
        let deltas = deltas();
        let digest = settlement_digest(7, players.span(), deltas.span());
        dual.register_hand(HAND_BINDING, digest, 777, 0, 0, 0);
        dual.verify_and_settle_dapv_stark(
            HAND_BINDING,
            hand_id_bytes().span(),
            7,
            players.span(),
            deltas.span(),
            duplicated_pk_payload().span(),
        );
    }

    #[test]
    fn proved_settle_accepts_whitelisted_prover_with_registered_commitment() {
        let s = setup();
        let dual = IPokerDualSettlementDispatcher { contract_address: s.dual };
        let players = players(@s);
        let deltas = deltas();
        let digest = settlement_digest(7, players.span(), deltas.span());
        let batch = payload();
        let commitment = poseidon_hash_span(batch.span());
        let batch_len: felt252 = batch.len().into();

        dual.register_hand_proved(HAND_BINDING, digest, 777, commitment, batch_len, 0, 0, 0);
        dual.verify_and_settle_dapv_proved(
            HAND_BINDING,
            hand_id_bytes().span(),
            7,
            players.span(),
            deltas.span(),
            commitment,
            batch_len,
        );

        assert!(dual.hand_settled(HAND_BINDING), "hand must be settled");
        let vault = IMockVaultDispatcher { contract_address: s.vault };
        assert!(vault.net_delta(s.p1) == 100, "p1 delta applied");
        assert!(vault.net_delta(s.p2) == -100, "p2 delta applied");
    }

    #[test]
    #[should_panic(expected: "Proved commitment/length mismatch (or not registered)")]
    fn proved_settle_rejects_wrong_commitment() {
        let s = setup();
        let dual = IPokerDualSettlementDispatcher { contract_address: s.dual };
        let players = players(@s);
        let deltas = deltas();
        let digest = settlement_digest(7, players.span(), deltas.span());
        let batch_len: felt252 = payload().len().into();
        dual.register_hand_proved(HAND_BINDING, digest, 777, 555, batch_len, 0, 0, 0);
        dual.verify_and_settle_dapv_proved(
            HAND_BINDING,
            hand_id_bytes().span(),
            7,
            players.span(),
            deltas.span(),
            556, // not the registered commitment
            batch_len,
        );
    }

    #[test]
    #[should_panic(expected: "Proved commitment/length mismatch (or not registered)")]
    fn proved_settle_rejects_wrong_batch_length() {
        let s = setup();
        let dual = IPokerDualSettlementDispatcher { contract_address: s.dual };
        let players = players(@s);
        let deltas = deltas();
        let digest = settlement_digest(7, players.span(), deltas.span());
        let batch_len: felt252 = payload().len().into();
        dual.register_hand_proved(HAND_BINDING, digest, 777, 555, batch_len, 0, 0, 0);
        dual.verify_and_settle_dapv_proved(
            HAND_BINDING,
            hand_id_bytes().span(),
            7,
            players.span(),
            deltas.span(),
            555,
            batch_len + 1, // not the registered length
        );
    }

    #[test]
    #[should_panic(expected: "Caller not authorized prover")]
    fn proved_settle_rejects_non_whitelisted_caller() {
        let s = setup();
        let test_addr = get_contract_address();
        let dual = IPokerDualSettlementDispatcher { contract_address: s.dual };
        let players = players(@s);
        let deltas = deltas();
        let digest = settlement_digest(7, players.span(), deltas.span());
        let batch_len: felt252 = payload().len().into();
        dual.register_hand_proved(HAND_BINDING, digest, 777, 555, batch_len, 0, 0, 0);
        // Owner (the test contract) drops itself from the whitelist.
        dual.remove_prover(test_addr);
        dual.verify_and_settle_dapv_proved(
            HAND_BINDING,
            hand_id_bytes().span(),
            7,
            players.span(),
            deltas.span(),
            555,
            batch_len,
        );
    }

    #[test]
    #[should_panic(expected: "Hand already settled")]
    fn proved_settle_rejects_double_settle() {
        let s = setup();
        let dual = IPokerDualSettlementDispatcher { contract_address: s.dual };
        let players = players(@s);
        let deltas = deltas();
        let digest = settlement_digest(7, players.span(), deltas.span());
        let batch_len: felt252 = payload().len().into();
        dual.register_hand_proved(HAND_BINDING, digest, 777, 555, batch_len, 0, 0, 0);
        dual.verify_and_settle_dapv_proved(
            HAND_BINDING, hand_id_bytes().span(), 7, players.span(), deltas.span(), 555,
            batch_len,
        );
        dual.verify_and_settle_dapv_proved(
            HAND_BINDING, hand_id_bytes().span(), 7, players.span(), deltas.span(), 555,
            batch_len,
        );
    }
}
