/// Chip Vault: deposit STRK20 → chip balance, withdraw chip → STRK20.
///
/// The vault maintains per-player chip balances that are updated by the
/// settlement contract after each verified hand. Players deposit STRK20 to
/// receive chip credit, and withdraw chips back to STRK20.
///
/// ## Security
///
/// - `withdraw()`: trust off-chain system + settlement contract to verify
///   the player's chip balance before release. The vault only allows
///   withdrawal up to the player's recorded chip balance.
/// - `settlement_contract`: the only address that can debit/credit chip
///   balances via `apply_settlement()`.
/// - `pause`/`unpause`: emergency stop for withdrawals.
use openzeppelin::access::ownable::OwnableComponent;
use openzeppelin::security::pausable::PausableComponent;
use starknet::ContractAddress;

#[starknet::interface]
pub trait IPokerVault<TContractState> {
    /// Deposit STRK20 tokens and credit chip balance 1:1.
    fn deposit(ref self: TContractState, amount: u256);
    /// Withdraw up to `amount` chips as STRK20 tokens.
    fn withdraw(ref self: TContractState, amount: u256);
    /// Read chip balance of a player.
    fn chip_balance(self: @TContractState, player: ContractAddress) -> u256;
    /// Read the STRK20 token address.
    fn token(self: @TContractState) -> ContractAddress;
    /// Read the total chips in circulation.
    fn total_chips(self: @TContractState) -> u256;
    /// Apply settlement results (called by settlement contract only).
    fn apply_settlement(
        ref self: TContractState,
        player: ContractAddress,
        delta: i256,
    );
    /// Set the settlement contract address (owner only).
    fn set_settlement_contract(
        ref self: TContractState, settlement_contract: ContractAddress,
    );
    /// Emergency pause (owner only).
    fn pause(ref self: TContractState);
    /// Emergency unpause (owner only).
    fn unpause(ref self: TContractState);
    /// Paused state.
    fn paused(self: @TContractState) -> bool;
}

#[starknet::contract]
pub mod PokerVault {
    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::security::pausable::PausableComponent;
    use starknet::ContractAddress;
    use starknet::storage::{
        StorageMap, StoragePointerReadAccess, StoragePointerWriteAccess,
    };

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: PausableComponent, storage: pausable, event: PausableEvent);

    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl PausableMixinImpl = PausableComponent::PausableMixinImpl<ContractState>;
    impl PausableInternalImpl = PausableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        /// STRK20 token contract address.
        token_address: ContractAddress,
        /// Per-player chip balance (1 chip = 1 smallest STRK20 unit).
        chip_balances: StorageMap<ContractAddress, u256>,
        /// Total chips in circulation.
        total_chips: u256,
        /// Settlement contract authorized to call apply_settlement.
        settlement_contract: ContractAddress,
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

    const CHIP_DECIMALS: u8 = 18;

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        token_address: ContractAddress,
        settlement_contract: ContractAddress,
    ) {
        self.ownable.initializer(owner);
        self.pausable.initializer();
        self.token_address.write(token_address);
        self.settlement_contract.write(settlement_contract);
    }

    #[abi(embed_v0)]
    #[generate_trait]
    impl IPokerVaultImpl of super::IPokerVault<ContractState> {
        fn deposit(ref self: ContractState, amount: u256) {
            // Player deposits STRK20 tokens; vault mints chip balance 1:1.
            let caller = starknet::get_caller_address();
            let token = self.token_address.read();

            // Transfer STRK20 from caller to this vault.
            // Requires caller to have approved this vault for `amount`.
            let success = starknet::contract_address_to_felt252(token)
                .into_();
            // Use the ERC20 transfer_from interface
            assert!(amount > 0, 'Amount must be > 0');

            // Call ERC20 transferFrom on the token contract
            let token_contract = ITokenDispatcher { contract_address: token };
            let success = token_contract.transfer_from(
                caller, starknet::get_contract_address(), amount,
            );
            assert!(success, 'Token transfer failed');

            // Credit chip balance
            let current = self.chip_balances.read(caller);
            self.chip_balances.write(caller, current + amount);
            self.total_chips.write(self.total_chips.read() + amount);

            self.emit(Deposit { player: caller, amount });
        }

        fn withdraw(ref self: ContractState, amount: u256) {
            // Player withdraws chips back to STRK20.
            self.pausable.assert_not_paused();
            let caller = starknet::get_caller_address();
            assert!(amount > 0, 'Amount must be > 0');

            let current = self.chip_balances.read(caller);
            assert!(current >= amount, 'Insufficient chip balance');

            // Debit chip balance
            self.chip_balances.write(caller, current - amount);
            self.total_chips.write(self.total_chips.read() - amount);

            // Transfer STRK20 tokens to caller
            let token = self.token_address.read();
            let token_contract = ITokenDispatcher { contract_address: token };
            let success = token_contract.transfer(caller, amount);
            assert!(success, 'Token transfer failed');

            self.emit(Withdraw { player: caller, amount });
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

        fn apply_settlement(
            ref self: ContractState, player: ContractAddress, delta: i256,
        ) {
            // Only settlement contract can call this.
            let caller = starknet::get_caller_address();
            assert!(
                caller == self.settlement_contract.read(),
                'Only settlement contract',
            );

            if delta > 0 {
                // Player wins chips
                let amount = delta.try_into().expect('delta positive fits u256');
                let current = self.chip_balances.read(player);
                self.chip_balances.write(player, current + amount);
                self.total_chips.write(self.total_chips.read() + amount);
                self.emit(ChipCredited { player, amount });
            } else if delta < 0 {
                // Player loses chips
                let abs_amount = (-delta).try_into().expect('abs delta fits u256');
                let current = self.chip_balances.read(player);
                assert!(current >= abs_amount, 'Insufficient chip balance');
                self.chip_balances.write(player, current - abs_amount);
                self.total_chips.write(self.total_chips.read() - abs_amount);
                self.emit(ChipDebited { player, amount: abs_amount });
            }
            // delta == 0: no-op
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
}

// Minimal ERC20 transferFrom/transfer interface for the vault to call.
#[starknet::interface]
pub trait ITokenDispatcher<TContractState> {
    fn transfer_from(
        ref self: TContractState,
        sender: ContractAddress,
        recipient: ContractAddress,
        amount: u256,
    ) -> bool;
    fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
}