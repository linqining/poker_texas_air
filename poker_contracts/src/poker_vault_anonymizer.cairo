/// STRK20 privacy-pool anonymizer for poker buy-ins (Plan B).
///
/// The STRK20 privacy pool calls `privacy_invoke` on this contract from
/// inside a private transaction (InvokeExternal phase, at most once per tx,
/// entrypoint selected by the protocol's INVOKE_SELECTOR). Before the call
/// the pool has already transferred the user's shielded input tokens to this
/// helper via a plain public transfer — so the helper's balance at call time
/// includes the buy-in funds plus any surplus the user chose to route.
///
/// Flow inside `privacy_invoke(player, amount, change_note_id)`:
///   1. Approve the PokerVault and call `deposit_for(player, amount)` — the
///      vault pulls `amount` STRK from the helper and credits the player's
///      chip balance 1:1. On-chain payer = helper; chip recipient = player.
///   2. Whatever STRK remains in the helper is "change": approve the pool to
///      pull it back and return it as a single `OpenNoteDeposit` (open note,
///      salt = 1, credited to `change_note_id`).
///   3. Return exactly `Span<OpenNoteDeposit>` — empty when there is no
///      change. The pool measures the output by balance delta, so the
///      returned total must equal the helper's remaining balance.
///
/// ## STRK20 integration rules honored
///
/// - Approve (never transfer) the pool to pull outputs.
/// - `ZERO_OUT_AMOUNT`: no zero-amount deposit entries (empty span instead).
/// - u256 → u128 guard on the change amount (pool note amounts are u128).
/// - Per-token temp balance must end exactly zero after the pool pulls.
///
/// Deployment: constructor takes the PokerVault and the STRK20 privacy pool
/// addresses. Only the pool may call `privacy_invoke`.
use starknet::ContractAddress;

/// Open-note deposit entry returned by `privacy_invoke` to the STRK20 pool
/// (shape mandated by the privacy-pool protocol).
#[derive(Copy, Drop, Serde)]
pub struct OpenNoteDeposit {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub amount: u128,
}

/// Minimal vault surface used by the anonymizer (selector-compatible with
/// PokerVault; keeps the helper decoupled from the full vault ABI).
#[starknet::interface]
pub trait IVaultLike<TContractState> {
    fn deposit_for(ref self: TContractState, player: ContractAddress, amount: u256);
    fn token(self: @TContractState) -> ContractAddress;
}

#[starknet::interface]
pub trait IPokerVaultAnonymizer<TContractState> {
    /// Called by the STRK20 privacy pool inside a private transaction.
    /// Converts `amount` of pool-supplied STRK into chips for `player` and
    /// returns the remaining change as one open-note deposit.
    fn privacy_invoke(
        ref self: TContractState,
        player: ContractAddress,
        amount: u256,
        change_note_id: felt252,
    ) -> Span<OpenNoteDeposit>;
}

/// Vault / pool addresses for observability and SDK configuration.
#[starknet::interface]
pub trait IAnonymizerInfo<TContractState> {
    fn vault(self: @TContractState) -> ContractAddress;
    fn pool(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PokerVaultAnonymizer {
    use core::num::traits::Zero;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use starknet::{
        ContractAddress, get_caller_address, get_contract_address,
        storage::{StoragePointerReadAccess, StoragePointerWriteAccess},
    };

    use super::{
        IAnonymizerInfo, IPokerVaultAnonymizer, IVaultLikeDispatcher, IVaultLikeDispatcherTrait,
        OpenNoteDeposit,
    };

    #[storage]
    struct Storage {
        /// PokerVault that converts STRK to chips via deposit_for.
        vault: ContractAddress,
        /// STRK20 privacy pool — the only authorized caller.
        pool: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        BuyInExecuted: BuyInExecuted,
    }

    #[derive(Drop, starknet::Event)]
    struct BuyInExecuted {
        player: ContractAddress,
        amount: u256,
        change: u128,
    }

    #[constructor]
    fn constructor(ref self: ContractState, vault: ContractAddress, pool: ContractAddress) {
        assert!(!vault.is_zero(), "vault required");
        assert!(!pool.is_zero(), "pool required");
        self.vault.write(vault);
        self.pool.write(pool);
    }

    #[abi(embed_v0)]
    impl AnonymizerImpl of super::IPokerVaultAnonymizer<ContractState> {
        fn privacy_invoke(
            ref self: ContractState,
            player: ContractAddress,
            amount: u256,
            change_note_id: felt252,
        ) -> Span<OpenNoteDeposit> {
            let pool = self.pool.read();
            assert!(get_caller_address() == pool, "caller is not the pool");
            assert!(!player.is_zero(), "player required");
            assert!(amount > 0_u256, "amount must be > 0");

            let vault = self.vault.read();
            let vault_dispatcher = IVaultLikeDispatcher { contract_address: vault };
            let token = vault_dispatcher.token();
            let token_dispatcher = IERC20Dispatcher { contract_address: token };
            let self_address = get_contract_address();

            // 1. Buy in: approve the vault, then let it pull `amount` and
            // credit the player's chips 1:1.
            let ok = token_dispatcher.approve(vault, amount);
            assert!(ok, "vault approve failed");
            vault_dispatcher.deposit_for(player, amount);

            // 2. Change = remaining helper balance (pool-funded surplus). The
            // pool pulls it via the approval below and credits the user's
            // `change_note_id`. Pool note amounts are u128, so the change
            // must fit — reject rather than silently truncate.
            let remaining = token_dispatcher.balance_of(self_address);
            if remaining.is_zero() {
                self.emit(BuyInExecuted { player, amount, change: 0 });
                let empty = core::array::ArrayTrait::new();
                return empty.span();
            }
            assert!(remaining.high == 0_u128, "change overflows u128");
            let change: u128 = remaining.low;
            assert!(change_note_id != 0, "change note id required");
            let ok = token_dispatcher.approve(pool, remaining);
            assert!(ok, "pool approve failed");

            self.emit(BuyInExecuted { player, amount, change });

            let mut deposits = core::array::ArrayTrait::new();
            deposits.append(OpenNoteDeposit { note_id: change_note_id, token, amount: change });
            deposits.span()
        }
    }

    /// Vault / pool addresses for observability and SDK configuration.
    #[abi(embed_v0)]
    impl AnonymizerInfoImpl of IAnonymizerInfo<ContractState> {
        fn vault(self: @ContractState) -> ContractAddress {
            self.vault.read()
        }

        fn pool(self: @ContractState) -> ContractAddress {
            self.pool.read()
        }
    }
}

// ============================================================
// Tests (snforge): the test contract acts as the privacy pool.
// ============================================================

#[cfg(test)]
mod mock_token {
    use starknet::ContractAddress;

    #[starknet::interface]
    pub trait IMockToken<TContractState> {
        fn mint(ref self: TContractState, to: ContractAddress, amount: u256);
        fn approve(ref self: TContractState, spender: ContractAddress, amount: u256) -> bool;
        fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
        fn transfer_from(
            ref self: TContractState,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256,
        ) -> bool;
        fn balance_of(self: @TContractState, account: ContractAddress) -> u256;
    }

    /// Minimal ERC-20 stand-in exposing the snake_case selectors the vault
    /// and anonymizer call through IERC20Dispatcher.
    #[starknet::contract]
    pub mod MockToken {
        use starknet::{ContractAddress, get_caller_address};
        use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};

        #[storage]
        struct Storage {
            balances: Map<ContractAddress, u256>,
            allowances: Map<(ContractAddress, ContractAddress), u256>,
        }

        #[abi(embed_v0)]
        impl MockTokenImpl of super::IMockToken<ContractState> {
            fn mint(ref self: ContractState, to: ContractAddress, amount: u256) {
                let current = self.balances.read(to);
                self.balances.write(to, current + amount);
            }

            fn approve(ref self: ContractState, spender: ContractAddress, amount: u256) -> bool {
                let caller = get_caller_address();
                self.allowances.write((caller, spender), amount);
                true
            }

            fn transfer(ref self: ContractState, recipient: ContractAddress, amount: u256) -> bool {
                let caller = get_caller_address();
                let from_balance = self.balances.read(caller);
                assert!(from_balance >= amount, "insufficient balance");
                self.balances.write(caller, from_balance - amount);
                let to_balance = self.balances.read(recipient);
                self.balances.write(recipient, to_balance + amount);
                true
            }

            fn transfer_from(
                ref self: ContractState,
                sender: ContractAddress,
                recipient: ContractAddress,
                amount: u256,
            ) -> bool {
                let spender = get_caller_address();
                let key = (sender, spender);
                let allowed = self.allowances.read(key);
                assert!(allowed >= amount, "insufficient allowance");
                self.allowances.write(key, allowed - amount);
                let from_balance = self.balances.read(sender);
                assert!(from_balance >= amount, "insufficient balance");
                self.balances.write(sender, from_balance - amount);
                let to_balance = self.balances.read(recipient);
                self.balances.write(recipient, to_balance + amount);
                true
            }

            fn balance_of(self: @ContractState, account: ContractAddress) -> u256 {
                self.balances.read(account)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::byte_array::ByteArray;
    use starknet::{ContractAddress, get_contract_address};
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};

    use super::mock_token::{IMockTokenDispatcher, IMockTokenDispatcherTrait};
    use super::{IPokerVaultAnonymizerDispatcher, IPokerVaultAnonymizerDispatcherTrait};
    use crate::poker_vault::{IPokerVaultDispatcher, IPokerVaultDispatcherTrait};

    fn deploy_contract(name: ByteArray, calldata: @Array<felt252>) -> ContractAddress {
        let class = declare(name).unwrap().contract_class();
        let (address, _) = class.deploy(calldata).unwrap();
        address
    }

    struct Setup {
        token: ContractAddress,
        vault: ContractAddress,
        anonymizer: ContractAddress,
        player: ContractAddress,
    }

    /// Deploy token + vault + anonymizer with `pool` as the authorized
    /// caller. No funds minted yet.
    fn setup(pool: ContractAddress) -> Setup {
        let test_addr = get_contract_address();
        let zero: ContractAddress = 0.try_into().unwrap();
        let token = deploy_contract("MockToken", @array![]);
        let vault = deploy_contract(
            "PokerVault",
            @array![test_addr.into(), token.into(), zero.into()],
        );
        let anonymizer = deploy_contract(
            "PokerVaultAnonymizer",
            @array![vault.into(), pool.into()],
        );
        let player: ContractAddress = 1234567.try_into().unwrap();
        Setup { token, vault, anonymizer, player }
    }

    #[test]
    fn deposit_for_credits_player_1to1() {
        let test_addr = get_contract_address();
        let s = setup(test_addr);
        let tok = IMockTokenDispatcher { contract_address: s.token };
        let vault = IPokerVaultDispatcher { contract_address: s.vault };

        tok.mint(test_addr, 1000);
        tok.approve(s.vault, 400);
        vault.deposit_for(s.player, 400);

        assert!(vault.chip_balance(s.player) == 400, "chips not credited");
        assert!(vault.chip_balance(test_addr) == 0, "caller must not gain");
        assert!(vault.total_chips() == 400, "total chips");
    }

    #[test]
    fn privacy_invoke_deposits_and_returns_change() {
        let test_addr = get_contract_address();
        let s = setup(test_addr); // pool == test contract
        let tok = IMockTokenDispatcher { contract_address: s.token };

        // The pool transfers the user's shielded inputs to the helper
        // before privacy_invoke runs.
        tok.mint(test_addr, 1000);
        tok.transfer(s.anonymizer, 1000);

        let anon = IPokerVaultAnonymizerDispatcher { contract_address: s.anonymizer };
        let deposits = anon.privacy_invoke(s.player, 400, 7);

        assert!(deposits.len() == 1, "one change note");
        let change = *deposits.at(0);
        assert!(change.note_id == 7, "note id mismatch");
        assert!(change.token == s.token, "token mismatch");
        assert!(change.amount == 600, "change mismatch");

        let vault = IPokerVaultDispatcher { contract_address: s.vault };
        assert!(vault.chip_balance(s.player) == 400, "chips not credited");
        assert!(tok.balance_of(s.anonymizer) == 600, "helper balance");

        // The pool pulls the change via the approval the helper granted.
        assert!(tok.transfer_from(s.anonymizer, test_addr, 600), "pool pull");
        assert!(tok.balance_of(s.anonymizer) == 0, "helper must be empty");
    }

    #[test]
    fn privacy_invoke_exact_amount_empty_change() {
        let test_addr = get_contract_address();
        let s = setup(test_addr);
        let tok = IMockTokenDispatcher { contract_address: s.token };

        tok.mint(test_addr, 400);
        tok.transfer(s.anonymizer, 400);

        let anon = IPokerVaultAnonymizerDispatcher { contract_address: s.anonymizer };
        let deposits = anon.privacy_invoke(s.player, 400, 0);

        assert!(deposits.len() == 0, "no change expected");
        let vault = IPokerVaultDispatcher { contract_address: s.vault };
        assert!(vault.chip_balance(s.player) == 400, "chips not credited");
        assert!(tok.balance_of(s.anonymizer) == 0, "helper must be empty");
    }

    #[test]
    #[should_panic(expected: "change overflows u128")]
    fn privacy_invoke_rejects_change_over_u128() {
        let test_addr = get_contract_address();
        let s = setup(test_addr);
        let tok = IMockTokenDispatcher { contract_address: s.token };

        // 2^128 + 1 wei remaining as change — pool note amounts are u128.
        let huge: u256 = 340282366920938463463374607431768211457; // 2^128 + 1
        tok.mint(test_addr, huge);
        tok.transfer(s.anonymizer, huge);

        let anon = IPokerVaultAnonymizerDispatcher { contract_address: s.anonymizer };
        anon.privacy_invoke(s.player, 1, 7);
    }

    #[test]
    #[should_panic(expected: "caller is not the pool")]
    fn privacy_invoke_rejects_non_pool_caller() {
        let stranger: ContractAddress = 987654.try_into().unwrap();
        let s = setup(stranger); // pool != test contract
        let anon = IPokerVaultAnonymizerDispatcher { contract_address: s.anonymizer };
        anon.privacy_invoke(s.player, 100, 1);
    }
}
