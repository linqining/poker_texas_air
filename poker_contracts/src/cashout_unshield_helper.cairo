//! #25 全链路私密提现（unshield 方向第二个 anonymizer）。
//!
//! 玩家在 vault 的筹码可以转换为 STRK20 池的 open note（归属由池隐藏），
//! **不经过玩家公开钱包**——提现钱包地址与牌局赢家之间的最后一环被切断
//! （`docs/starknet-plan-b-anonymizer.md` §已知 seam / TODO #25）。
//!
//! 流程（玩家本人发起，两笔链上调用）：
//!   1. `vault.withdraw_to(player → helper, amount)`（vault 侧 unshield helper
//!      信任门放行）：烧筹码，STRK 进入 helper；
//!   2. `helper.chip_to_note(amount, note_id)`（caller = 玩家）：helper 把
//!      STRK approve 给池并返回 `OpenNoteDeposit`——池侧集成应用该 note
//!      （形状与 PokerVaultAnonymizer::privacy_invoke 的返回一致；池的具体
//!      应用入口属 SDK_SEAM，见 plan-b 文档）。
//!
//! 信任/隐私边界（与 plan-b 诚实清单一致）：
//! - open note 金额公开（池边缘设计），归属由池隐藏；
//! - helper 自身的 STRK 余额是所有在途 shield 的合并容量（fungible，
//!   无按人记账）；`chip_to_note` 以 helper 余额 ≥ amount 为上限。

use core::num::traits::Zero;
use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
use starknet::{
    ContractAddress, get_caller_address, get_contract_address,
    storage::{StoragePointerReadAccess, StoragePointerWriteAccess},
};

/// 与 PokerVaultAnonymizer 同形状的 open note（池侧集成复用；
/// 池 note 金额为 u128）。
#[derive(Copy, Drop, Serde)]
pub struct OpenNoteDeposit {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub amount: u128,
}

#[starknet::interface]
pub trait ICashoutUnshieldHelper<TContractState> {
    /// 把调用者在 vault 的 `amount` 筹码转换为池的 `note_id` open note：
    /// vault.withdraw_to(caller → helper) → approve pool → 返回 note 存款。
    fn chip_to_note(
        ref self: TContractState,
        amount: u256,
        note_id: felt252,
    ) -> Span<OpenNoteDeposit>;
    /// View: helper 当前可用于 shield 的 STRK 余额。
    fn shieldable_balance(self: @TContractState) -> u256;
    /// Views for observability / SDK configuration.
    fn vault(self: @TContractState) -> ContractAddress;
    fn pool(self: @TContractState) -> ContractAddress;
}

/// Vault surface used by the helper（withdraw_to 为 #25 新增）。
#[starknet::interface]
pub trait IVaultWithdrawTo<TContractState> {
    fn withdraw_to(
        ref self: TContractState,
        player: ContractAddress,
        recipient: ContractAddress,
        amount: u256,
    );
    fn token(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod CashoutUnshieldHelper {
    use core::num::traits::Zero;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use starknet::{
        ContractAddress, get_caller_address, get_contract_address,
        storage::{StoragePointerReadAccess, StoragePointerWriteAccess},
    };

    use super::{
        IVaultWithdrawTo, IVaultWithdrawToDispatcher, IVaultWithdrawToDispatcherTrait,
        OpenNoteDeposit,
    };

    #[storage]
    struct Storage {
        /// PokerVault holding the player's chips（unshield helper 需在 vault
        /// 侧 `set_unshield_helper` 授权）。
        vault: ContractAddress,
        /// STRK20 privacy pool — note 的最终归属层。
        pool: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ChipToNoteExecuted: ChipToNoteExecuted,
    }

    #[derive(Drop, starknet::Event)]
    struct ChipToNoteExecuted {
        player: ContractAddress,
        amount: u256,
        note_id: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, vault: ContractAddress, pool: ContractAddress) {
        assert!(!vault.is_zero(), "vault required");
        assert!(!pool.is_zero(), "pool required");
        self.vault.write(vault);
        self.pool.write(pool);
    }

    #[abi(embed_v0)]
    pub impl CashoutUnshieldHelperImpl of super::ICashoutUnshieldHelper<ContractState> {
        fn chip_to_note(
            ref self: ContractState,
            amount: u256,
            note_id: felt252,
        ) -> Span<OpenNoteDeposit> {
            let player = get_caller_address();
            assert!(!player.is_zero(), "player required");
            assert!(amount > 0_u256, "amount must be > 0");
            assert!(note_id != 0, "note id required");

            let vault_addr = self.vault.read();
            let pool = self.pool.read();
            let self_address = get_contract_address();

            // 1) 烧玩家筹码，STRK 直接进 helper（vault 侧 unshield 信任门）
            let vault = IVaultWithdrawToDispatcher { contract_address: vault_addr };
            vault.withdraw_to(player, self_address, amount);

            // 2) approve 池并返回 open note 存款（池侧集成应用）
            let token = vault.token();
            let token_dispatcher = IERC20Dispatcher { contract_address: token };
            let balance = token_dispatcher.balance_of(self_address);
            assert!(balance >= amount, "helper balance below shield amount");
            assert!(amount.high == 0_u128, "amount overflows u128");
            let ok = token_dispatcher.approve(pool, amount);
            assert!(ok, "pool approve failed");

            self.emit(ChipToNoteExecuted { player, amount, note_id });

            let mut deposits = core::array::ArrayTrait::new();
            deposits.append(OpenNoteDeposit { note_id, token, amount: amount.low });
            deposits.span()
        }

        fn shieldable_balance(self: @ContractState) -> u256 {
            let vault = IVaultWithdrawToDispatcher { contract_address: self.vault.read() };
            let token_dispatcher = IERC20Dispatcher { contract_address: vault.token() };
            token_dispatcher.balance_of(get_contract_address())
        }

        fn vault(self: @ContractState) -> ContractAddress {
            self.vault.read()
        }

        fn pool(self: @ContractState) -> ContractAddress {
            self.pool.read()
        }
    }
}

#[cfg(test)]
mod tests {
    use core::num::traits::Zero;
    use starknet::{ContractAddress, get_contract_address};
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};

    use super::{ICashoutUnshieldHelperDispatcher, ICashoutUnshieldHelperDispatcherTrait};
    use crate::poker_vault::{IPokerVaultDispatcher, IPokerVaultDispatcherTrait};

    /// 极简 STRK20 stand-in（记账 + 授权，供 approve/balance 断言）。
    #[starknet::interface]
    pub trait ICashoutMockToken<TContractState> {
        fn mint(ref self: TContractState, to: ContractAddress, amount: u256);
        fn balance_of(self: @TContractState, account: ContractAddress) -> u256;
        fn allowance(
            self: @TContractState,
            owner: ContractAddress,
            spender: ContractAddress,
        ) -> u256;
        fn transfer(ref self: TContractState, to: ContractAddress, amount: u256) -> bool;
        fn approve(ref self: TContractState, spender: ContractAddress, amount: u256) -> bool;
        fn transfer_from(
            ref self: TContractState,
            from: ContractAddress,
            to: ContractAddress,
            amount: u256,
        ) -> bool;
    }

    #[starknet::contract]
    pub mod CashoutMockToken {
        use starknet::{ContractAddress, get_caller_address};
        use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};

        #[storage]
        struct Storage {
            balances: Map<ContractAddress, u256>,
            allowances: Map<(ContractAddress, ContractAddress), u256>,
        }

        #[constructor]
        fn constructor(ref self: ContractState) {}

        #[abi(embed_v0)]
        pub impl CashoutMockTokenImpl of super::ICashoutMockToken<ContractState> {
            fn mint(ref self: ContractState, to: ContractAddress, amount: u256) {
                let current = self.balances.read(to);
                self.balances.write(to, current + amount);
            }

            fn balance_of(self: @ContractState, account: ContractAddress) -> u256 {
                self.balances.read(account)
            }

            fn allowance(
                self: @ContractState,
                owner: ContractAddress,
                spender: ContractAddress,
            ) -> u256 {
                self.allowances.read((owner, spender))
            }

            fn transfer(ref self: ContractState, to: ContractAddress, amount: u256) -> bool {
                let caller = get_caller_address();
                let current = self.balances.read(caller);
                assert!(current >= amount, "insufficient token balance");
                self.balances.write(caller, current - amount);
                let to_current = self.balances.read(to);
                self.balances.write(to, to_current + amount);
                true
            }

            fn approve(
                ref self: ContractState,
                spender: ContractAddress,
                amount: u256,
            ) -> bool {
                let caller = get_caller_address();
                self.allowances.write((caller, spender), amount);
                true
            }

            fn transfer_from(
                ref self: ContractState,
                from: ContractAddress,
                to: ContractAddress,
                amount: u256,
            ) -> bool {
                let spender = get_caller_address();
                let allowed = self.allowances.read((from, spender));
                assert!(allowed >= amount, "insufficient allowance");
                self.allowances.write((from, spender), allowed - amount);
                let from_balance = self.balances.read(from);
                assert!(from_balance >= amount, "insufficient balance");
                self.balances.write(from, from_balance - amount);
                let to_balance = self.balances.read(to);
                self.balances.write(to, to_balance + amount);
                true
            }
        }
    }

    fn deploy_contract(name: ByteArray, calldata: @Array<felt252>) -> ContractAddress {
        let class = declare(name).unwrap().contract_class();
        let (address, _) = class.deploy(calldata).unwrap();
        address
    }

    /// 返回 (token, vault, helper, player)；`with_deposit` = 给 player 充
    /// 1000 筹码。测试合约自身即 chip_to_note 的 caller（玩家）。
    fn setup(with_deposit: bool) -> (
        ContractAddress,
        ContractAddress,
        ContractAddress,
        ContractAddress,
        IPokerVaultDispatcher,
        ICashoutUnshieldHelperDispatcher,
    ) {
        let player = get_contract_address();
        let zero: ContractAddress = 0.try_into().unwrap();
        let token = deploy_contract("CashoutMockToken", @array![]);
        let vault = deploy_contract(
            "PokerVault",
            @array![player.into(), token.into(), zero.into()],
        );
        // pool = token 地址仅作占位（测试断言 allowance/余额，不做真实池转移）
        let helper = deploy_contract(
            "CashoutUnshieldHelper",
            @array![vault.into(), token.into()],
        );
        println!("ADDR token={token:?} vault={vault:?} helper={helper:?}");
        let vault_dispatcher = IPokerVaultDispatcher { contract_address: vault };
        vault_dispatcher.set_unshield_helper(helper);
        if with_deposit {
            // deposit_for 是 pull 模式：player（测试合约）先持有并 approve vault
            let token_d = ICashoutMockTokenDispatcher { contract_address: token };
            token_d.mint(player, 1000);
            token_d.approve(vault, 1000);
            vault_dispatcher.deposit_for(player, 1000);
        }
        (
            token,
            vault,
            helper,
            player,
            vault_dispatcher,
            ICashoutUnshieldHelperDispatcher { contract_address: helper },
        )
    }

    #[test]
    fn chip_to_note_burns_chips_and_approves_pool() {
        let (token, _vault, helper, player, vault_d, helper_d) = setup(true);
        let token_d = ICashoutMockTokenDispatcher { contract_address: token };

        // caller（测试合约）即筹码所有者：deposit 1000 → shield 600
        let deposits = helper_d.chip_to_note(600, 7);

        assert!(deposits.len() == 1, "one open note deposit");
        let note = *deposits.at(0);
        assert!(note.note_id == 7, "note id mismatch");
        assert!(note.token == token, "token mismatch");
        assert!(note.amount == 600_u128, "note amount mismatch");

        // 筹码已烧 600（剩余 400）；helper 持有 600 STRK 并已 approve 给池
        //（池 pull 后即成为赢家的 open note——池侧集成见 SDK_SEAM）
        assert!(vault_d.chip_balance(player) == 400, "chips must be burned");
        assert!(token_d.balance_of(helper) == 600, "helper holds pre-pull funds");
        assert!(
            token_d.allowance(helper, token) == 600_u256,
            "pool approval must equal note amount"
        );
    }

    #[test]
    #[should_panic(expected: "Insufficient chip balance")]
    fn player_without_chips_reverted() {
        let (_, _, _, _, _, helper_d) = setup(false);
        // caller 无筹码 → vault.withdraw_to 余额断言失败
        helper_d.chip_to_note(600, 7);
    }

    #[test]
    #[should_panic(expected: "Only the unshield helper")]
    fn vault_withdraw_to_rejects_non_helper() {
        let (_, vault, _, _, _, _) = setup(true);
        // 任何人直接调 vault.withdraw_to（绕过 helper）都会被信任门拒绝
        let anyone: ContractAddress = 0x8888.try_into().unwrap();
        IPokerVaultDispatcher { contract_address: vault }.withdraw_to(anyone, anyone, 100);
    }
}
