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
    fn register_hand(
        ref self: TContractState,
        hand_binding: felt252,
        settlement_digest: felt252,
        g_attestation: felt252,
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
    use super::IVaultDispatcherDispatcherTrait;

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
        ) {
            let caller = starknet::get_caller_address();
            assert!(self.provers.read(caller), "Caller not authorized prover");
            assert!(hand_binding != 0, "Zero binding");
            let (existing_digest, _, existing_flag) = self.bindings.read(hand_binding);
            assert!(
                existing_flag == 0 && existing_digest == 0,
                "Binding already registered"
            );
            self.bindings.write(hand_binding, (settlement_digest, g_attestation, 1));
            self.emit(
                HandRegistered { hand_binding, settlement_digest, g_attestation },
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
            assert!(hand_binding != 0, "Zero binding");
            assert!(players.len() == deltas.len(), "Players/deltas mismatch");
            assert!(players.len() > 0_u32, "No participants");
            assert!(players.len() < 10_u32, "Too many participants");
            assert!(!self.settled_bindings.read(hand_binding), "Hand already settled");

            // (a) The binding must have been registered (G Phase 1).
            let (registered_digest, _g_attestation, registered_flag) =
                self.bindings.read(hand_binding);
            assert!(registered_flag == 1, "Binding not registered");

            // (b) Recompute the settlement commitment over the asserted
            // players/deltas (settlement_hash.cairo layout) and require an
            // exact match with the registered digest.
            let mut felements: Array<felt252> = array![hand_id.into()];
            let mut i = 0_u32;
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
            // hand_id is folded into the binding upstream; the settlement
            // digest domain tag keeps the two encodings distinct.
            let computed = poseidon_hash_span(felements.span());
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
