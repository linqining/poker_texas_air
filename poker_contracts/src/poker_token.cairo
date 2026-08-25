/// STRK20 test token for the Poker Texas AIR settlement system.
///
/// Deployed on Sepolia testnet. Uses OpenZeppelin ERC20 component.
/// When the system goes to mainnet, this is replaced by the real STRK token address.
use openzeppelin::access::ownable::OwnableComponent;
use openzeppelin::token::erc20::ERC20Component;
use starknet::ContractAddress;

#[starknet::interface]
pub trait IPokerToken<TContractState> {
    fn name(self: @TContractState) -> ByteArray;
    fn symbol(self: @TContractState) -> ByteArray;
    fn decimals(self: @TContractState) -> u8;
    fn total_supply(self: @TContractState) -> u256;
    fn balance_of(self: @TContractState, account: ContractAddress) -> u256;
    fn allowance(self: @TContractState, owner: ContractAddress, spender: ContractAddress) -> u256;
    fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
    fn transfer_from(
        ref self: TContractState, sender: ContractAddress, recipient: ContractAddress, amount: u256,
    ) -> bool;
    fn approve(ref self: TContractState, spender: ContractAddress, amount: u256) -> bool;
    // Owner-only: mint test tokens.
    fn mint(ref self: TContractState, recipient: ContractAddress, amount: u256);
    /// Owner-only: burn tokens.
    fn burn(ref self: TContractState, account: ContractAddress, amount: u256);
    /// Owner-only: transfer ownership.
    fn transfer_ownership(ref self: TContractState, new_owner: ContractAddress);
    fn owner(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PokerToken {
    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::token::erc20::ERC20Component;
    use starknet::ContractAddress;

    component!(path: ERC20Component, storage: erc20, event: ERC20Event);
    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    // ERC20 ABI
    #[abi(embed_v0)]
    impl ERC20MixinImpl = ERC20Component::ERC20MixinImpl<ContractState>;
    #[abi(embed_v0)]
    impl ERC20MetadataImpl = ERC20Component::ERC20MetadataImpl<ContractState>;

    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;

    impl ERC20InternalImpl = ERC20Component::InternalImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc20: ERC20Component::Storage,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ERC20Event: ERC20Component::Event,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        name: ByteArray,
        symbol: ByteArray,
        initial_supply: u256,
    ) {
        // Initialize ERC20 metadata
        self.erc20.initializer(name, symbol);
        // Initialize Ownable
        self.ownable.initializer(owner);
        // Mint initial supply to owner
        if initial_supply > 0 {
            self.erc20.mint(owner, initial_supply);
        }
    }

    #[abi(embed_v0)]
    #[generate_trait]
    impl IPokerTokenImpl of super::IPokerToken<ContractState> {
        fn name(self: @ContractState) -> ByteArray {
            self.erc20.name()
        }
        fn symbol(self: @ContractState) -> ByteArray {
            self.erc20.symbol()
        }
        fn decimals(self: @ContractState) -> u8 {
            self.erc20.decimals()
        }
        fn total_supply(self: @ContractState) -> u256 {
            self.erc20.total_supply()
        }
        fn balance_of(self: @ContractState, account: ContractAddress) -> u256 {
            self.erc20.balance_of(account)
        }
        fn allowance(
            self: @ContractState, owner: ContractAddress, spender: ContractAddress,
        ) -> u256 {
            self.erc20.allowance(owner, spender)
        }
        fn transfer(
            ref self: ContractState, recipient: ContractAddress, amount: u256,
        ) -> bool {
            self.erc20.transfer(recipient, amount)
        }
        fn transfer_from(
            ref self: ContractState,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256,
        ) -> bool {
            self.erc20.transfer_from(sender, recipient, amount)
        }
        fn approve(ref self: ContractState, spender: ContractAddress, amount: u256) -> bool {
            self.erc20.approve(spender, amount)
        }
        fn mint(ref self: ContractState, recipient: ContractAddress, amount: u256) {
            self.ownable.assert_only_owner();
            self.erc20.mint(recipient, amount);
        }
        fn burn(ref self: ContractState, account: ContractAddress, amount: u256) {
            self.ownable.assert_only_owner();
            self.erc20.burn(account, amount);
        }
        fn transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
            self.ownable.transfer_ownership(new_owner);
        }
        fn owner(self: @ContractState) -> ContractAddress {
            self.ownable.owner()
        }
    }
}