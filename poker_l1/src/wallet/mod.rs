//! Frictionless wallet helpers.
//!
//! Wallets present one aggregated ZCN balance while the chain keeps immutable native-coin UTXOs.
//! These helpers perform deterministic input selection and transaction assembly; consensus
//! execution remains authoritative for ownership, amount, replay, and double-spend checks.

use serde::{Deserialize, Serialize};

use crate::Address;
use crate::ChainId;
use crate::economics::auto_select_native_coins;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::executor::TransferArgs;
use crate::storage::ObjectDb;
use crate::transaction::{ContractCall, Gas, RouteHint, TxLane, TxRequest};
use crate::vm::contracts::texas_poker::dispatch::required_funding;
use crate::vm::precompile::reserved;

/// Result of automatically funding an unsigned Texas Poker transaction request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundedTexasTxRequest {
    /// Unsigned request with deterministic native-coin IDs filled into `inputs`.
    pub request: TxRequest,
    /// Amount that the selected Texas method will lock into the table vault.
    pub required: u64,
    /// Sum of all selected native-coin inputs.
    pub selected_total: u64,
    /// Change that execution will create for the caller.
    pub change: u64,
}

/// Wallet result for an automatically selected native ZCN transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundedTransferTxRequest {
    /// Unsigned Public-lane transfer request ready for signing.
    pub request: TxRequest,
    /// Sum of the selected sender UTXOs.
    pub selected_total: u64,
    /// Deterministic change amount that execution returns to the sender.
    pub change: u64,
}

/// Build a frictionless native ZCN transfer by aggregating and selecting sender UTXOs.
///
/// The wallet exposes one balance and never asks the caller to manage coin object IDs manually.
/// Execution revalidates ownership and creates the exact recipient output plus sender change.
pub fn build_native_transfer_tx_request(
    object_db: &ObjectDb,
    owner: Address,
    recipient: Address,
    amount: u64,
    chain_id: ChainId,
    nonce: u64,
) -> PokerL1Result<FundedTransferTxRequest> {
    let selection = auto_select_native_coins(object_db, owner, amount)?;
    let request = TxRequest {
        inputs: selection.input_ids,
        outputs: vec![],
        contract_call: Some(ContractCall {
            contract_id: reserved::transfer_contract_id(),
            method_selector: [0u8; 32],
            args: borsh::to_vec(&TransferArgs { recipient, amount })?,
        }),
        gas: Gas::zero(),
        lane_hint: TxLane::Public,
        route_hint: RouteHint::AnyValidator,
        chain_id,
        nonce,
        gameturn_nonce: None,
        is_fallback: false,
    };
    Ok(FundedTransferTxRequest {
        request,
        selected_total: selection.total,
        change: selection.total - amount,
    })
}

/// Automatically fund an unsigned Texas Poker request from an owner's native-coin UTXOs.
///
/// The caller supplies business arguments such as buy-in, addon, or rebuy amount. This builder:
/// - decodes the amount from the canonical Texas selector mapping;
/// - deterministically selects native coins;
/// - fills `TxRequest.inputs`;
/// - normalizes the request to the gas-free assigned-validator GameTurn lane.
///
/// Change is deliberately not added to `outputs`: the executor creates the signed transaction's
/// deterministic change object after revalidating the selected inputs.
pub fn build_funded_texas_tx_request(
    object_db: &ObjectDb,
    owner: Address,
    mut request: TxRequest,
) -> PokerL1Result<FundedTexasTxRequest> {
    if !request.inputs.is_empty() {
        return Err(PokerL1Error::Other(
            "funded Texas wallet builder requires an empty inputs list".into(),
        ));
    }
    let contract_call = request.contract_call.as_ref().ok_or_else(|| {
        PokerL1Error::Other("funded Texas wallet builder requires a contract call".into())
    })?;
    if contract_call.contract_id != reserved::texas_poker_contract_id() {
        return Err(PokerL1Error::Other(
            "funded Texas wallet builder received a non-Texas contract".into(),
        ));
    }
    let required = required_funding(&contract_call.method_selector, &contract_call.args)?
        .ok_or_else(|| {
            PokerL1Error::Other(
                "Texas method does not consume native-coin funding; use a normal TxRequest".into(),
            )
        })?;
    let selection = auto_select_native_coins(object_db, owner, required)?;

    request.inputs = selection.input_ids;
    request.gas = Gas::zero();
    request.lane_hint = TxLane::GameTurn;
    request.route_hint = RouteHint::AssignedValidator;

    Ok(FundedTexasTxRequest {
        request,
        required,
        selected_total: selection.total,
        change: selection.total - required,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_CHAIN_ID;
    use crate::economics::native_coin_object;
    use crate::vm::contracts::texas_poker::dispatch::{AddonArgs, SeatIndexArgs, selectors};

    fn request(method_selector: [u8; 32], args: Vec<u8>) -> TxRequest {
        TxRequest {
            inputs: vec![],
            outputs: vec![],
            contract_call: Some(ContractCall {
                contract_id: reserved::texas_poker_contract_id(),
                method_selector,
                args,
            }),
            gas: Gas::new(99_999, 7),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: Some(3),
            is_fallback: false,
        }
    }

    #[test]
    fn builder_selects_inputs_and_normalizes_gas_free_gameturn_routing() {
        let owner = [0x33; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        let first = native_coin_object(owner, 70, 1).unwrap();
        let second = native_coin_object(owner, 50, 2).unwrap();
        db.create(first.clone()).unwrap();
        db.create(second.clone()).unwrap();
        let args = borsh::to_vec(&AddonArgs {
            seat_index: 1,
            amount: 100,
        })
        .unwrap();

        let funded =
            build_funded_texas_tx_request(&db, owner, request(selectors::addon(), args)).unwrap();

        assert_eq!(funded.request.inputs, vec![first.id, second.id]);
        assert_eq!(funded.required, 100);
        assert_eq!(funded.selected_total, 120);
        assert_eq!(funded.change, 20);
        assert_eq!(funded.request.gas, Gas::zero());
        assert_eq!(funded.request.lane_hint, TxLane::GameTurn);
        assert_eq!(funded.request.route_hint, RouteHint::AssignedValidator);
        assert!(
            db.read(&first.id).is_ok(),
            "wallet selection must not spend"
        );
        assert!(
            db.read(&second.id).is_ok(),
            "wallet selection must not spend"
        );
        assert!(funded.request.outputs.is_empty());
    }

    #[test]
    fn builder_rejects_non_funding_methods_and_existing_inputs() {
        let owner = [0x33; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        let coin = native_coin_object(owner, 100, 1).unwrap();
        db.create(coin.clone()).unwrap();

        let fold_args = borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).unwrap();
        assert!(
            build_funded_texas_tx_request(&db, owner, request(selectors::fold(), fold_args))
                .is_err()
        );

        let addon_args = borsh::to_vec(&AddonArgs {
            seat_index: 1,
            amount: 100,
        })
        .unwrap();
        let mut with_input = request(selectors::addon(), addon_args);
        with_input.inputs.push(coin.id);
        assert!(build_funded_texas_tx_request(&db, owner, with_input).is_err());
    }

    #[test]
    fn transfer_builder_hides_utxo_selection_and_reports_change() {
        let owner = [0x41; 20];
        let recipient = [0x42; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        let first = native_coin_object(owner, 70, 1).unwrap();
        let second = native_coin_object(owner, 50, 2).unwrap();
        db.create(first.clone()).unwrap();
        db.create(second.clone()).unwrap();

        let funded =
            build_native_transfer_tx_request(&db, owner, recipient, 100, DEFAULT_CHAIN_ID, 7)
                .unwrap();

        assert_eq!(funded.request.inputs, vec![first.id, second.id]);
        assert_eq!(funded.selected_total, 120);
        assert_eq!(funded.change, 20);
        assert_eq!(funded.request.gas, Gas::zero());
        assert_eq!(funded.request.lane_hint, TxLane::Public);
        assert_eq!(funded.request.nonce, 7);
        let call = funded.request.contract_call.unwrap();
        assert_eq!(call.contract_id, reserved::transfer_contract_id());
        assert_eq!(
            borsh::from_slice::<TransferArgs>(&call.args).unwrap(),
            TransferArgs {
                recipient,
                amount: 100,
            }
        );
    }
}
