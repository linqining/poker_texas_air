/// Chip Vault: deposit STRK20 → chip balance, withdraw chip → STRK20.
///
/// The vault maintains per-player chip balances that the settlement contract
/// updates after each verified hand.
///
/// ## Security
///
/// - Only the settlement contract may call `apply_settlement`; it is the sole
///   path that moves chips between players for hands.
/// - `withdraw()` is permissionless but only up to the caller's chip balance.
/// - Pausing halts new deposits and withdrawals (settlement application is
///   also gated in this deployment for simplicity).
use openzeppelin::access::ownable::OwnableComponent;
use openzeppelin::security::pausable::PausableComponent;
use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
use starknet::ContractAddress;
use starknet::storage::{
    Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
    StoragePointerWriteAccess,
};

#[starknet::interface]
pub trait IPokerVault<TContractState> {
    /// Deposit STRK20 tokens and credit chip balance 1:1.
    fn deposit(ref self: TContractState, amount: u256);
    /// Deposit STRK20 tokens credited to `player` (caller pays, 1:1).
    ///
    /// Permissionless by design: the STRK20 privacy-pool anonymizer calls this
    /// inside a private transaction, so the on-chain payer is the anonymizer
    /// (funded by the pool) while the chips land on the game player. Anyone
    /// may also gift chips to another player through the same path.
    fn deposit_for(ref self: TContractState, player: ContractAddress, amount: u256);
    /// Withdraw up to `amount` chips as STRK20 tokens.
    fn withdraw(ref self: TContractState, amount: u256);

    /// Plan D P2.2 (unshield): burn `player`'s chips without any token
    /// movement. Only the authorized helper (PokerVaultAnonymizer) may call
    /// it; the STRK conservation happens inside the privacy pool (the pool
    /// transfers the user's burned input note to the helper, which returns
    /// it to the pool as the recipient's output note).
    fn burn_chips(ref self: TContractState, player: ContractAddress, amount: u256);

    /// Owner-gated: authorize the helper contract allowed to call
    /// `burn_chips` (the PokerVaultAnonymizer deployment).
    fn set_authorized_helper(ref self: TContractState, helper: ContractAddress);
    /// Read chip balance of a player.
    fn chip_balance(self: @TContractState, player: ContractAddress) -> u256;
    /// Token (STRK20) address.
    fn token(self: @TContractState) -> ContractAddress;
    /// Total chips in circulation.
    fn total_chips(self: @TContractState) -> u256;
    /// Apply a net chip delta to a player (settlement contract only).
    /// `delta > 0` credits chips, `delta < 0` debits, `delta == 0` is a no-op.
    fn apply_settlement(ref self: TContractState, player: ContractAddress, delta: i128);
    /// Set the settlement contract address (owner only).
    fn set_settlement_contract(ref self: TContractState, settlement_contract: ContractAddress);
    /// Emergency pause (owner only).
    fn pause(ref self: TContractState);
    /// Emergency unpause (owner only).
    fn unpause(ref self: TContractState);
    /// Whether the vault is paused.
    fn paused(self: @TContractState) -> bool;
}

#[starknet::contract]
pub mod PokerVault {
    use core::num::traits::Zero;
    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::security::pausable::PausableComponent;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use starknet::ContractAddress;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: PausableComponent, storage: pausable, event: PausableEvent);

    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl PausableImpl = PausableComponent::PausableImpl<ContractState>;
    impl PausableInternalImpl = PausableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        /// STRK20 token contract address.
        token_address: ContractAddress,
        /// Per-player chip balance (1 chip = 1 smallest STRK20 unit).
        chip_balances: Map<ContractAddress, u256>,
        /// Total chips in circulation.
        total_chips: u256,
        /// Settlement contract authorized to call apply_settlement.
        settlement_contract: ContractAddress,
        /// Helper contract authorized to call burn_chips (PokerVaultAnonymizer).
        authorized_helper: ContractAddress,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        pausable: PausableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        PausableEvent: PausableComponent::Event,
        Deposit: Deposit,
        Withdraw: Withdraw,
        ChipCredited: ChipCredited,
        ChipDebited: ChipDebited,
        SettlementContractSet: SettlementContractSet,
        AuthorizedHelperSet: AuthorizedHelperSet,
    }

    #[derive(Drop, starknet::Event)]
    struct AuthorizedHelperSet {
        helper: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct Deposit {
        player: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct Withdraw {
        player: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ChipCredited {
        player: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ChipDebited {
        player: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct SettlementContractSet {
        settlement_contract: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        token_address: ContractAddress,
        settlement_contract: ContractAddress,
    ) {
        self.ownable.initializer(owner);
        self.token_address.write(token_address);
        self.settlement_contract.write(settlement_contract);
        self.authorized_helper.write(starknet::get_contract_address());
    }

    #[abi(embed_v0)]
    impl IPokerVaultImpl of super::IPokerVault<ContractState> {
        fn deposit(ref self: ContractState, amount: u256) {
            self.pausable.assert_not_paused();
            assert!(amount > 0_u256, "Amount must be > 0");
            let caller = starknet::get_caller_address();
            self.pull_and_credit(caller, amount);
        }

        fn deposit_for(ref self: ContractState, player: ContractAddress, amount: u256) {
            self.pausable.assert_not_paused();
            assert!(amount > 0_u256, "Amount must be > 0");
            assert!(!player.is_zero(), "Player must be set");
            self.pull_and_credit(player, amount);
        }

        fn withdraw(ref self: ContractState, amount: u256) {
            self.pausable.assert_not_paused();
            assert!(amount > 0_u256, "Amount must be > 0");
            let caller = starknet::get_caller_address();

            let current = self.chip_balances.read(caller);
            assert!(current >= amount, "Insufficient chip balance");

            self.chip_balances.write(caller, current - amount);
            self.total_chips.write(self.total_chips.read() - amount);

            let token = self.token_address.read();
            let dispatcher = IERC20Dispatcher { contract_address: token };
            let ok = dispatcher.transfer(caller, amount);
            assert!(ok, "Token transfer failed");

            self.emit(Withdraw { player: caller, amount });
        }

        fn burn_chips(ref self: ContractState, player: ContractAddress, amount: u256) {
            self.pausable.assert_not_paused();
            assert!(
                starknet::get_caller_address() == self.authorized_helper.read(),
                "Only the authorized helper"
            );
            assert!(amount > 0_u256, "Amount must be > 0");
            assert!(!player.is_zero(), "Player must be set");

            let current = self.chip_balances.read(player);
            assert!(current >= amount, "Insufficient chip balance");
            self.chip_balances.write(player, current - amount);
            self.total_chips.write(self.total_chips.read() - amount);
            self.emit(ChipDebited { player, amount });
        }

        fn set_authorized_helper(ref self: ContractState, helper: ContractAddress) {
            self.ownable.assert_only_owner();
            self.authorized_helper.write(helper);
            self.emit(AuthorizedHelperSet { helper });
        }

        fn chip_balance(self: @ContractState, player: ContractAddress) -> u256 {
            self.chip_balances.read(player)
        }

        fn token(self: @ContractState) -> ContractAddress {
            self.token_address.read()
        }

        fn total_chips(self: @ContractState) -> u256 {
            self.total_chips.read()
        }

        fn apply_settlement(ref self: ContractState, player: ContractAddress, delta: i128) {
            let caller = starknet::get_caller_address();
            assert!(
                caller == self.settlement_contract.read(), "Only settlement contract",
            );

            if delta > 0_i128 {
                let delta_u64: u64 = delta.try_into().expect('delta positive fits u64');
                let amount: u256 = delta_u64.into();
                let current = self.chip_balances.read(player);
                self.chip_balances.write(player, current + amount);
                self.total_chips.write(self.total_chips.read() + amount);
                self.emit(ChipCredited { player, amount });
            } else if delta < 0_i128 {
                let abs_delta = -delta;
                let abs_delta_u64: u64 = abs_delta.try_into().expect('abs delta fits u64');
                let amount: u256 = abs_delta_u64.into();
                let current = self.chip_balances.read(player);
                assert!(current >= amount, "Insufficient chip balance");
                self.chip_balances.write(player, current - amount);
                self.total_chips.write(self.total_chips.read() - amount);
                self.emit(ChipDebited { player, amount });
            }
            // delta == 0: no-op.
        }

        fn set_settlement_contract(
            ref self: ContractState, settlement_contract: ContractAddress,
        ) {
            self.ownable.assert_only_owner();
            self.settlement_contract.write(settlement_contract);
            self.emit(SettlementContractSet { settlement_contract });
        }

        fn pause(ref self: ContractState) {
            self.ownable.assert_only_owner();
            self.pausable.pause();
        }

        fn unpause(ref self: ContractState) {
            self.ownable.assert_only_owner();
            self.pausable.unpause();
        }

        fn paused(self: @ContractState) -> bool {
            self.pausable.is_paused()
        }
    }

    /// Shared deposit path: pull STRK20 from the caller (caller must have
    /// approved the vault) and credit `player` 1:1. Used by both `deposit`
    /// (self-credit) and `deposit_for` (anonymizer / gifting credit).
    #[generate_trait]
    impl VaultInternalImpl of VaultInternalTrait {
        fn pull_and_credit(
            ref self: ContractState, player: ContractAddress, amount: u256,
        ) {
            let caller = starknet::get_caller_address();
            let token = self.token_address.read();

            let dispatcher = IERC20Dispatcher { contract_address: token };
            let ok = dispatcher
                .transfer_from(caller, starknet::get_contract_address(), amount);
            assert!(ok, "Token transfer failed");

            let current = self.chip_balances.read(player);
            self.chip_balances.write(player, current + amount);
            self.total_chips.write(self.total_chips.read() + amount);
            self.emit(Deposit { player, amount });
        }
    }
}