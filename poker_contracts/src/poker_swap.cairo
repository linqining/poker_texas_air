/// Fixed-rate bidirectional STRK <-> pSTRK exchanger (1 STRK = SWAP_RATE pSTRK).
///
/// Both directions at the same fixed rate:
/// - `swap_strk_to_pstrk`: STRK in  -> rate * STRK out in pSTRK (contract
///   accumulates STRK, needs pSTRK liquidity);
/// - `swap_pstrk_to_strk`: pSTRK in -> pSTRK / rate out in STRK (needs STRK
///   liquidity; pstrk_amount must divide evenly by rate).
///
/// This is the standard fixed-rate "two-reserve treasury" exchanger (no AMM
/// pricing): the owner seeds both reserves (`fund_pstrk` / `fund_strk`) and
/// sweeps accumulated tokens (`sweep_strk` / `sweep_pstrk`). Incoming tokens
/// from either direction are held as the opposite reserve automatically.
///
/// The canonical STRK fee-token address is identical on mainnet, Sepolia
/// and starknet-devnet predeploys, so it is hardcoded (same convention as
/// starkware-libs/starknet-privacy demo).
use starknet::ContractAddress;

/// Canonical STRK token (fee token) — same address across networks.
pub const STRK_ADDRESS: felt252 =
    0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d;

#[starknet::interface]
pub trait IPokerSwap<TContractState> {
    /// STRK -> pSTRK at `rate` (caller must have approved this contract for STRK).
    fn swap_strk_to_pstrk(ref self: TContractState, strk_amount: u256);
    /// pSTRK -> STRK at `rate` (approve for pSTRK; pstrk_amount % rate == 0).
    fn swap_pstrk_to_strk(ref self: TContractState, pstrk_amount: u256);
    /// 旧入口，等价 swap_strk_to_pstrk（保留兼容）。
    fn swap(ref self: TContractState, strk_amount: u256);
    /// Owner: withdraw accumulated STRK proceeds.
    fn sweep_strk(ref self: TContractState, recipient: ContractAddress, amount: u256);
    /// Owner: withdraw accumulated pSTRK (e.g. from reverse swaps).
    fn sweep_pstrk(ref self: TContractState, recipient: ContractAddress, amount: u256);
    /// Owner: deposit pSTRK liquidity (transfer_from owner; approve first).
    fn fund_pstrk(ref self: TContractState, amount: u256);
    /// Owner: deposit STRK liquidity (transfer_from owner; approve first).
    fn fund_strk(ref self: TContractState, amount: u256);
    /// pSTRK liquidity held by this contract.
    fn pstrk_liquidity(self: @TContractState) -> u256;
    /// STRK liquidity held by this contract.
    fn strk_balance(self: @TContractState) -> u256;
    /// pSTRK per STRK.
    fn rate(self: @TContractState) -> u256;
}

#[starknet::contract]
pub mod PokerSwap {
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ContractAddress, get_caller_address, get_contract_address};

    pub const STRK_ADDRESS: felt252 =
        0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d;
    /// 1 STRK = 1000 pSTRK (both 18 decimals).
    pub const SWAP_RATE: u256 = 1000;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        pstrk_address: ContractAddress,
        rate: u256,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Swapped: Swapped,
        ReverseSwapped: ReverseSwapped,
        StrkSwept: StrkSwept,
        PstrkSwept: PstrkSwept,
        PstrkFunded: PstrkFunded,
        StrkFunded: StrkFunded,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Swapped {
        pub swapper: ContractAddress,
        pub strk_amount: u256,
        pub pstrk_amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ReverseSwapped {
        pub swapper: ContractAddress,
        pub pstrk_amount: u256,
        pub strk_amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct StrkSwept {
        pub recipient: ContractAddress,
        pub amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PstrkSwept {
        pub recipient: ContractAddress,
        pub amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PstrkFunded {
        pub amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct StrkFunded {
        pub amount: u256,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        pstrk_address: ContractAddress,
    ) {
        self.owner.write(owner);
        self.pstrk_address.write(pstrk_address);
        self.rate.write(SWAP_RATE);
    }

    #[abi(embed_v0)]
    impl IPokerSwapImpl of super::IPokerSwap<ContractState> {
        fn swap_strk_to_pstrk(ref self: ContractState, strk_amount: u256) {
            assert!(strk_amount > 0_u256, "Amount must be > 0");
            let caller = get_caller_address();
            let this = get_contract_address();

            let strk = IERC20Dispatcher { contract_address: STRK_ADDRESS.try_into().unwrap() };
            let ok = strk.transfer_from(caller, this, strk_amount);
            assert!(ok, "STRK transfer_from failed (approve first)");

            let pstrk_amount = strk_amount * self.rate.read();
            let pstrk = IERC20Dispatcher { contract_address: self.pstrk_address.read() };
            let ok = pstrk.transfer(caller, pstrk_amount);
            assert!(ok, "pSTRK transfer failed (liquidity)");

            self.emit(Event::Swapped(Swapped { swapper: caller, strk_amount, pstrk_amount }));
        }

        fn swap_pstrk_to_strk(ref self: ContractState, pstrk_amount: u256) {
            let rate = self.rate.read();
            assert!(pstrk_amount > 0_u256, "Amount must be > 0");
            // 固定汇率反向兑换要求整除，避免零头损失
            assert!(pstrk_amount % rate == 0_u256, "amount must divide by rate");
            let caller = get_caller_address();
            let this = get_contract_address();

            let pstrk = IERC20Dispatcher { contract_address: self.pstrk_address.read() };
            let ok = pstrk.transfer_from(caller, this, pstrk_amount);
            assert!(ok, "pSTRK transfer_from failed (approve first)");

            let strk_amount = pstrk_amount / rate;
            let strk = IERC20Dispatcher { contract_address: STRK_ADDRESS.try_into().unwrap() };
            let ok = strk.transfer(caller, strk_amount);
            assert!(ok, "STRK transfer failed (liquidity)");

            self.emit(Event::ReverseSwapped(ReverseSwapped {
                swapper: caller, pstrk_amount, strk_amount,
            }));
        }

        fn swap(ref self: ContractState, strk_amount: u256) {
            self.swap_strk_to_pstrk(strk_amount);
        }

        fn sweep_strk(ref self: ContractState, recipient: ContractAddress, amount: u256) {
            assert!(get_caller_address() == self.owner.read(), "caller is not owner");
            let strk = IERC20Dispatcher { contract_address: STRK_ADDRESS.try_into().unwrap() };
            let ok = strk.transfer(recipient, amount);
            assert!(ok, "STRK sweep failed");
            self.emit(Event::StrkSwept(StrkSwept { recipient, amount }));
        }

        fn sweep_pstrk(ref self: ContractState, recipient: ContractAddress, amount: u256) {
            assert!(get_caller_address() == self.owner.read(), "caller is not owner");
            let pstrk = IERC20Dispatcher { contract_address: self.pstrk_address.read() };
            let ok = pstrk.transfer(recipient, amount);
            assert!(ok, "pSTRK sweep failed");
            self.emit(Event::PstrkSwept(PstrkSwept { recipient, amount }));
        }

        fn fund_strk(ref self: ContractState, amount: u256) {
            let owner = self.owner.read();
            assert!(get_caller_address() == owner, "caller is not owner");
            let strk = IERC20Dispatcher { contract_address: STRK_ADDRESS.try_into().unwrap() };
            let ok = strk.transfer_from(owner, get_contract_address(), amount);
            assert!(ok, "STRK transfer_from failed (approve first)");
            self.emit(Event::StrkFunded(StrkFunded { amount }));
        }

        fn fund_pstrk(ref self: ContractState, amount: u256) {
            let owner = self.owner.read();
            assert!(get_caller_address() == owner, "caller is not owner");
            let pstrk = IERC20Dispatcher { contract_address: self.pstrk_address.read() };
            let ok = pstrk.transfer_from(owner, get_contract_address(), amount);
            assert!(ok, "pSTRK transfer_from failed (approve first)");
            self.emit(Event::PstrkFunded(PstrkFunded { amount }));
        }

        fn pstrk_liquidity(self: @ContractState) -> u256 {
            let pstrk = IERC20Dispatcher { contract_address: self.pstrk_address.read() };
            pstrk.balance_of(get_contract_address())
        }

        fn strk_balance(self: @ContractState) -> u256 {
            let strk = IERC20Dispatcher { contract_address: STRK_ADDRESS.try_into().unwrap() };
            strk.balance_of(get_contract_address())
        }

        fn rate(self: @ContractState) -> u256 {
            self.rate.read()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::STRK_ADDRESS;
    use super::PokerSwap::SWAP_RATE;
    use super::super::poker_token::{IPokerTokenExtensionDispatcher, IPokerTokenExtensionDispatcherTrait};
    use super::IPokerSwapDispatcher;
    use super::IPokerSwapDispatcherTrait;
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
    use starknet::{ContractAddress, get_contract_address};

    /// 最小 mock STRK（IERC20 子集），部署在规范 STRK 地址上供 PokerSwap 使用。
    #[starknet::interface]
    pub trait IMockStrk<TContractState> {
        fn mint(ref self: TContractState, to: ContractAddress, amount: u256);
        fn approve(ref self: TContractState, spender: ContractAddress, amount: u256) -> bool;
        fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
        fn transfer_from(
            ref self: TContractState, from: ContractAddress, recipient: ContractAddress, amount: u256,
        ) -> bool;
        fn balance_of(self: @TContractState, account: ContractAddress) -> u256;
    }

    #[starknet::contract]
    pub mod MockStrk {
        use starknet::{ContractAddress, get_caller_address};
        use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};

        #[storage]
        struct Storage {
            balances: Map<ContractAddress, u256>,
            allowances: Map<(ContractAddress, ContractAddress), u256>,
        }

        #[abi(embed_v0)]
        impl MockStrkImpl of super::IMockStrk<ContractState> {
            fn mint(ref self: ContractState, to: ContractAddress, amount: u256) {
                self.balances.write(to, self.balances.read(to) + amount);
            }
            fn approve(ref self: ContractState, spender: ContractAddress, amount: u256) -> bool {
                self.allowances.write((get_caller_address(), spender), amount);
                true
            }
            fn transfer(ref self: ContractState, recipient: ContractAddress, amount: u256) -> bool {
                let caller = get_caller_address();
                let bal = self.balances.read(caller);
                assert!(bal >= amount, "insufficient balance");
                self.balances.write(caller, bal - amount);
                self.balances.write(recipient, self.balances.read(recipient) + amount);
                true
            }
            fn transfer_from(
                ref self: ContractState, from: ContractAddress, recipient: ContractAddress, amount: u256,
            ) -> bool {
                let spender = get_caller_address();
                let allowance = self.allowances.read((from, spender));
                assert!(allowance >= amount, "insufficient allowance");
                let bal = self.balances.read(from);
                assert!(bal >= amount, "insufficient balance");
                self.allowances.write((from, spender), allowance - amount);
                self.balances.write(from, bal - amount);
                self.balances.write(recipient, self.balances.read(recipient) + amount);
                true
            }
            fn balance_of(self: @ContractState, account: ContractAddress) -> u256 {
                self.balances.read(account)
            }
        }
    }

    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    fn strk_address() -> ContractAddress {
        STRK_ADDRESS.try_into().unwrap()
    }

    /// 返回 (swap dispatcher, pstrk 地址)。测试合约自身即 owner/swapper。
    fn setup() -> (IPokerSwapDispatcher, ContractAddress) {
        let this = get_contract_address();

        let mock_strk_class = declare("MockStrk").unwrap().contract_class();
        let _ = mock_strk_class.deploy_at(@array![], strk_address()).unwrap();

        let pstrk_class = declare("PokerToken").unwrap().contract_class();
        let mut pstrk_calldata = array![this.into()];
        let name: ByteArray = "PokerSTRK";
        let symbol: ByteArray = "pSTRK";
        Serde::serialize(@name, ref pstrk_calldata);
        Serde::serialize(@symbol, ref pstrk_calldata);
        pstrk_calldata.append(0);
        pstrk_calldata.append(0);
        let (pstrk, _) = pstrk_class.deploy(@pstrk_calldata).unwrap();

        let swap_class = declare("PokerSwap").unwrap().contract_class();
        let (swap, _) = swap_class.deploy(@array![this.into(), pstrk.into()]).unwrap();
        (IPokerSwapDispatcher { contract_address: swap }, pstrk)
    }

    const ONE_STRK: u256 = 1_000_000_000_000_000_000;

    #[test]
    fn swap_one_strk_yields_rate_pstrk() {
        let (swap_dispatcher, pstrk_addr) = setup();
        let this = get_contract_address();
        let swap_addr = swap_dispatcher.contract_address;

        // owner 铸 pSTRK 流动性并注入 swap
        let pstrk_ext = IPokerTokenExtensionDispatcher { contract_address: pstrk_addr };
        pstrk_ext.mint(this, ONE_STRK * SWAP_RATE);
        let pstrk_erc20 = IERC20Dispatcher { contract_address: pstrk_addr };
        let _ = pstrk_erc20.approve(swap_addr, ONE_STRK * SWAP_RATE);
        swap_dispatcher.fund_pstrk(ONE_STRK * SWAP_RATE);
        assert!(swap_dispatcher.pstrk_liquidity() == ONE_STRK * SWAP_RATE, "liquidity funded");

        // 准备 STRK，批准后兑换
        let mock_strk = IMockStrkDispatcher { contract_address: strk_address() };
        mock_strk.mint(this, ONE_STRK);
        let _ = mock_strk.approve(swap_addr, ONE_STRK);
        swap_dispatcher.swap(ONE_STRK);

        assert!(pstrk_erc20.balance_of(this) == ONE_STRK * SWAP_RATE, "swapper pSTRK");
        assert!(swap_dispatcher.strk_balance() == ONE_STRK, "swap holds STRK");
        assert!(swap_dispatcher.pstrk_liquidity() == 0, "liquidity drained");
    }

    #[test]
    fn reverse_swap_round_trips() {
        let (swap_dispatcher, pstrk_addr) = setup();
        let this = get_contract_address();
        let swap_addr = swap_dispatcher.contract_address;
        let mock_strk = IMockStrkDispatcher { contract_address: strk_address() };
        let pstrk_erc20 = IERC20Dispatcher { contract_address: pstrk_addr };

        // 双侧储备：pSTRK 1000 + STRK 1（fund 与 swap 各自消耗 allowance，多批一些）
        let pstrk_ext = IPokerTokenExtensionDispatcher { contract_address: pstrk_addr };
        pstrk_ext.mint(this, ONE_STRK * SWAP_RATE);
        let _ = pstrk_erc20.approve(swap_addr, ONE_STRK * SWAP_RATE);
        swap_dispatcher.fund_pstrk(ONE_STRK * SWAP_RATE);
        mock_strk.mint(this, 2 * ONE_STRK);
        let _ = mock_strk.approve(swap_addr, 2 * ONE_STRK);
        swap_dispatcher.fund_strk(ONE_STRK);

        // 正向：1 STRK -> 1000 pSTRK
        swap_dispatcher.swap_strk_to_pstrk(ONE_STRK);
        assert!(pstrk_erc20.balance_of(this) == ONE_STRK * SWAP_RATE, "forward out");

        // 反向：1000 pSTRK -> 1 STRK
        let _ = pstrk_erc20.approve(swap_addr, ONE_STRK * SWAP_RATE);
        swap_dispatcher.swap_pstrk_to_strk(ONE_STRK * SWAP_RATE);
        assert!(mock_strk.balance_of(this) == ONE_STRK, "reverse out");
        assert!(pstrk_erc20.balance_of(this) == 0, "pSTRK round trip");
        assert!(swap_dispatcher.strk_balance() == ONE_STRK, "strk reserve intact");
    }

    #[test]
    #[should_panic(expected: "amount must divide by rate")]
    fn reverse_swap_rejects_indivisible_amount() {
        let (swap_dispatcher, pstrk_addr) = setup();
        // 1 wei 不整除 rate(1000)：先于任何转账被拒绝
        let pstrk_erc20 = IERC20Dispatcher { contract_address: pstrk_addr };
        let _ = pstrk_erc20.approve(swap_dispatcher.contract_address, 1);
        swap_dispatcher.swap_pstrk_to_strk(1);
    }

    #[test]
    #[should_panic]
    fn swap_reverts_when_liquidity_insufficient() {
        let (swap_dispatcher, _) = setup();
        let this = get_contract_address();

        let mock_strk = IMockStrkDispatcher { contract_address: strk_address() };
        mock_strk.mint(this, ONE_STRK);
        let _ = mock_strk.approve(swap_dispatcher.contract_address, ONE_STRK);
        swap_dispatcher.swap(ONE_STRK);
    }

    #[test]
    fn rate_is_thousand() {
        let (swap_dispatcher, _) = setup();
        assert!(swap_dispatcher.rate() == SWAP_RATE, "rate");
    }
}
