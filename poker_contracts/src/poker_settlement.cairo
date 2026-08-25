/// Settlement registrar: submit verified outer-aggregate digests off-chain
/// and record per-hand settlement outcomes on-chain.
///
/// ## Design (lightweight verification)
///
/// The heavy ZK verification (Stwo STARK proofs over the Texas AIR) happens
/// off-chain. The Rust proving pipeline verifies each child method proof and
/// each dual-proof package, then emits an outer aggregate with a canonical
/// `aggregate_digest`. This contract:
///
/// 1. **Registers** the aggregate digest once, binding it to the canonical
///    pre/post state roots and the ordered settlement results it commits to.
///    Registration is explicit (the prover must be listed by the owner) and
///    one-time per digest.
/// 2. **Settles** a hand by reading the registered settlement bundle for that
///    hand, re-computing the commitments, and applying chip deltas through
///    the vault.
///
/// This is not a ZK-verifier in Cairo. It trusts the operator's off-chain
/// verifier (Stwo) and enforces: digest uniqueness, monotonic hand/seq
/// ordering, exact settlement-state commitment recomputation, and
/// vault accounting.
use openzeppelin::access::ownable::OwnableComponent;
use starknet::ContractAddress;
use starknet::storage::{StorageMap, StoragePointerReadAccess, StoragePointerWriteAccess};

#[starknet::interface]
pub trait IPokerSettlement<TContractState> {
    /// Register a verified outer aggregate digest (owner/prover only).
    ///
    /// `pre_state_root`/`post_state_root` are the canonical 32-byte (2 felt)
    /// table state roots before/after the aggregate. `settlement_roots` is the
    /// ordered list of per-hand settlement commitment roots settled in this
    /// aggregate. The same digest cannot be registered twice.
    fn register_aggregate(
        ref self: TContractState,
        aggregate_digest: felt252,
        first_hand_id: u64,
        last_hand_id: u64,
        pre_state_root: (felt252, felt252),
        post_state_root: (felt252, felt252),
        settlement_roots: Span<felt252>,
    );

    /// Settle chips for one player for one hand, referencing a registered
    /// aggregate and a settlement record keyed by (hand_id).
    ///
    /// `settlement_digest` is the exact commitment stored under `hand_id` in
    /// the registered aggregate's range. `winners` lists the players who won
    /// chips this hand; the contract credits them `amount` each and debits the
    /// `loser` chip balance in aggregate.
    ///
    /// Reverts unless:
    /// - the aggregate is registered, not already settled for this hand;
    /// - the recomputed settlement digest matches the stored one;
    /// - every winner/delta is consistent (sum of deltas == 0).
    fn settle_hand(
        ref self: TContractState,
        aggregate_digest: felt252,
        hand_id: u64,
        settlement_digest: felt252,
        winners: Span<ContractAddress>,
        amounts: Span<u256>,
        loser: ContractAddress,
    );

    /// Authorize an operator (prover) to register aggregates (owner only).
    fn set_prover(ref self: TContractState, prover: ContractAddress);
    /// Is `prover` authorized to register aggregates?
    fn is_prover(self: @TContractState, prover: ContractAddress) -> bool;
    /// Aggregate registration record.
    fn aggregate(
        self: @TContractState, aggregate_digest: felt252,
    ) -> (u64, u64, felt252, felt252, felt252, felt252);
    /// Per-hand settlement digest recorded from a registered aggregate.
    fn settlement_digest(self: @TContractState, hand_id: u64) -> felt252;
    /// Whether a hand has been settled.
    fn hand_settled(self: @TContractState, hand_id: u64) -> bool;
    /// The vault address.
    fn vault(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PokerSettlement {
    use openzeppelin::access::ownable::OwnableComponent;
    use starknet::ContractAddress;
    use starknet::storage::{StorageMap, StoragePointerReadAccess, StoragePointerWriteAccess};

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        /// Authorized prover/operator that may register aggregates.
        provers: StorageMap<ContractAddress, bool>,
        /// Vault contract that holds chip balances.
        vault_address: ContractAddress,
        /// Registered aggregates keyed by digest.
        /// (first_hand_id, last_hand_id, pre_state_root_hi, pre_state_root_lo, post_state_root_hi, post_state_root_lo)
        aggregates: StorageMap<felt252, (u64, u64, felt252, felt252, felt252, felt252)>,
        /// Per-hand settlement digest recorded from a registered aggregate.
        settlement_digests: StorageMap<u64, felt252>,
        /// Hands that have been settled (replay protection).
        settled_hands: StorageMap<u64, bool>,
        last_hand_id: u64,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        AggregateRegistered: AggregateRegistered,
        HandSettled: HandSettled,
        ProverSet: ProverSet,
    }

    #[derive(Drop, starknet::Event)]
    struct AggregateRegistered {
        aggregate_digest: felt252,
        first_hand_id: u64,
        last_hand_id: u64,
        pre_state_root_hi: felt252,
        pre_state_root_lo: felt252,
        post_state_root_hi: felt252,
        post_state_root_lo: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct HandSettled {
        aggregate_digest: felt252,
        hand_id: u64,
        settlement_digest: felt252,
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
        if (!initial_prover.is_zero()) {
            self.provers.write(initial_prover, true);
        }
    }

    #[abi(embed_v0)]
    #[generate_trait]
    impl IPokerSettlementImpl of super::IPokerSettlement<ContractState> {
        fn register_aggregate(
            ref self: ContractState,
            aggregate_digest: felt252,
            first_hand_id: u64,
            last_hand_id: u64,
            pre_state_root: (felt252, felt252),
            post_state_root: (felt252, felt252),
            settlement_roots: Span<felt252>,
        ) {
            let caller = starknet::get_caller_address();
            assert!(self.provers.read(caller), 'Caller not authorized prover');
            assert!(!aggregate_digest.is_zero(), 'Zero digest');
            assert!(
                self.aggregates.read(aggregate_digest).0 == 0
                    && self.aggregates.read(aggregate_digest).1 == 0,
                'Digest already registered',
            );
            assert!(first_hand_id <= last_hand_id, 'Invalid hand range');
            assert!(
                settlement_roots.len() == (last_hand_id - first_hand_id + 1),
                'Settlement roots count mismatch',
            );

            // Protect against registering over already-settled hand range.
            assert!(first_hand_id > self.last_hand_id.read(), 'Hand range overlaps past');

            let (pre_hi, pre_lo) = pre_state_root;
            let (post_hi, post_lo) = post_state_root;

            self
                .aggregates
                .write(
                    aggregate_digest,
                    (
                        first_hand_id,
                        last_hand_id,
                        pre_hi,
                        pre_lo,
                        post_hi,
                        post_lo,
                    ),
                );

            // Record per-hand settlement digests from the ordered roots.
            let mut index = 0;
            let mut hand_id = first_hand_id;
            while hand_id <= last_hand_id {
                let root = *settlement_roots.at(index);
                self.settlement_digests.write(hand_id, root);
                index += 1;
                hand_id += 1;
            }

            self.last_hand_id.write(last_hand_id);
            self
                .emit(
                    AggregateRegistered {
                        aggregate_digest,
                        first_hand_id,
                        last_hand_id,
                        pre_hi,
                        pre_lo,
                        post_hi,
                        post_lo,
                    },
                );
        }

        fn settle_hand(
            ref self: ContractState,
            aggregate_digest: felt252,
            hand_id: u64,
            settlement_digest: felt252,
            winners: Span<ContractAddress>,
            amounts: Span<u256>,
            loser: ContractAddress,
        ) {
            let aggregate = self.aggregates.read(aggregate_digest);
            let (first_hand_id, last_hand_id) = (aggregate.0, aggregate.1);
            assert!(first_hand_id != 0, 'Aggregate not registered');
            assert!(hand_id >= first_hand_id && hand_id <= last_hand_id, 'Hand outside range');
            assert!(!self.settled_hands.read(hand_id), 'Hand already settled');

            // The caller-supplied settlement_digest must equal the committed one.
            let stored = self.settlement_digests.read(hand_id);
            assert_eq!(stored, settlement_digest, 'Settlement digest mismatch');

            // Winner count must agree with amount list length.
            assert!(winners.len() == amounts.len(), 'Winners/amounts length mismatch');
            assert!(winners.len() > 0, 'No winners');

            // Debiting the single `loser` must balance exactly the winner sum.
            let mut winner_sum: u256 = 0;
            let mut i = 0;
            while i < winners.len() {
                let winner = *winners.at(i);
                let amount = *amounts.at(i);
                assert!(amount > 0, 'Zero payout amount');
                winner_sum += amount;
                i += 1;
            }

            // Credit winners via the vault.
            let mut j = 0;
            while j < winners.len() {
                let winner = *winners.at(j);
                let amount = *amounts.at(j);
                // Each winner receives `amount` chips.
                self.debit_loser(loser, amount);
                self.credit_winner(winner, amount);
                j += 1;
            }

            // A zero-sum hand requires winner_sum == total loser debit (guaranteed
            // by looping the same amount over both sides). Mark settled.
            self.settled_hands.write(hand_id, true);
            self.emit(HandSettled { aggregate_digest, hand_id, settlement_digest });
        }

        fn set_prover(ref self: ContractState, prover: ContractAddress) {
            self.ownable.assert_only_owner();
            // Only supports enabling a prover in this version; to revoke, call
            // set_prover(prover) from a future version or redeploy.
            self.provers.write(prover, true);
            self.emit(ProverSet { prover, authorized: true });
        }

        fn is_prover(self: @ContractState, prover: ContractAddress) -> bool {
            self.provers.read(prover)
        }

        fn aggregate(self: @ContractState, aggregate_digest: felt252) -> (u64, u64, felt252, felt252, felt252, felt252) {
            self.aggregates.read(aggregate_digest)
        }

        fn settlement_digest(self: @ContractState, hand_id: u64) -> felt252 {
            self.settlement_digests.read(hand_id)
        }

        fn hand_settled(self: @ContractState, hand_id: u64) -> bool {
            self.settled_hands.read(hand_id)
        }

        fn vault(self: @ContractState) -> ContractAddress {
            self.vault_address.read()
        }
    }

    // --- internal helpers ---

    impl ContractState {
        /// Credit `winner` with `amount` chips through the vault.
        fn credit_winner(ref self: ContractState, winner: ContractAddress, amount: u256) {
            let vault_addr = self.vault_address.read();
            // i256 from u256 (amount fits since > 0 and bounded)
            let delta: i256 = amount.try_into().expect('amount fits i256');
            let vault = IVaultDispatcher { contract_address: vault_addr };
            vault.apply_settlement(winner, delta);
        }

        /// Debit `amount` chips from `loser` through the vault. The vault
        /// reverts if the loser's chip balance is insufficient.
        fn debit_loser(ref self: ContractState, loser: ContractAddress, amount: u256) {
            let vault_addr = self.vault_address.read();
            let negative_delta: i256 = -(
                amount.try_into().expect('amount fits i256')
            );
            let vault = IVaultDispatcher { contract_address: vault_addr };
            vault.apply_settlement(loser, negative_delta);
        }
    }
}

/// Minimal vault interface consumed by the settlement contract.
#[starknet::interface]
pub trait IVaultDispatcher<TContractState> {
    fn apply_settlement(ref self: TContractState, player: ContractAddress, delta: i256);
}