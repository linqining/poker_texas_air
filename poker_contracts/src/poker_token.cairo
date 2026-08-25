/// STRK20 test token for the Poker Texas AIR settlement system.
///
/// Deployed on Sepolia testnet. Uses the OpenZeppelin ERC20 + Ownable
/// components. The ERC20 standard entry points (name, symbol, decimals,
/// total_supply, balance_of, allowance, transfer, transfer_from, approve)
/// are provided by the embedded OZ ERC20 impl. On mainnet this is replaced
/// by the canonical STRK token address.
use openzeppelin::access::ownable::OwnableComponent;
use openzeppelin::token::erc20::{ERC20Component, ERC20HooksEmptyImpl};
use starknet::ContractAddress;

/// Owner-only extension interface: mint/burn test tokens.
#[starknet::interface]
pub trait IPokerTokenExtension<TContractState> {
    fn mint(ref self: TContractState, recipient: ContractAddress, amount: u256);
    fn burn(ref self: TContractState, account: ContractAddress, amount: u256);
}

#[starknet::contract]
pub mod PokerToken {
    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::token::erc20::{ERC20Component, ERC20HooksEmptyImpl};
    use starknet::ContractAddress;

    component!(path: ERC20Component, storage: erc20, event: ERC20Event);
    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl ERC20Impl = ERC20Component::ERC20Impl<ContractState>;
    #[abi(embed_v0)]
    impl ERC20MetadataImpl = ERC20Component::ERC20MetadataImpl<ContractState>;
    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableImpl<ContractState>;

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
        self.erc20.initializer(name, symbol);
        self.ownable.initializer(owner);
        if initial_supply > 0 {
            self.erc20.mint(owner, initial_supply);
        }
    }

    #[abi(embed_v0)]
    impl IPokerTokenExtensionImpl of super::IPokerTokenExtension<ContractState> {
        fn mint(ref self: ContractState, recipient: ContractAddress, amount: u256) {
            self.ownable.assert_only_owner();
            self.erc20.mint(recipient, amount);
        }
        fn burn(ref self: ContractState, account: ContractAddress, amount: u256) {
            self.ownable.assert_only_owner();
            self.erc20.burn(account, amount);
        }
    }
}