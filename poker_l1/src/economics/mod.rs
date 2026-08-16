//! Native ZCN economic objects.
//!
//! The first production-facing asset model is an immutable owned-coin UTXO:
//! a [`NativeCoin`] object may be created by an authorised system path and may
//! only be spent by deleting the whole object and creating new coin objects.
//! Generic object outputs are not allowed to mint this reserved object type.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID, Ownership};
use crate::storage::object_db::ObjectMutation;
use crate::storage::{ObjectBackend, ObjectDb};
use crate::vm::contracts::texas_poker::types::{TableContextOpenings, TexasPokerTable};
use crate::vm::contracts::texas_poker::{
    TEXAS_POKER_GOVERNANCE_OBJECT_TYPE, TEXAS_POKER_METADATA_OBJECT_TYPE,
    TEXAS_POKER_RULES_OBJECT_TYPE, TEXAS_POKER_TABLE_OBJECT_TYPE,
};
use crate::{Address, ChainId, Hash};

/// Reserved object type for the native ZCN coin.
pub const NATIVE_COIN_OBJECT_TYPE: &str = "0x2::zcn::Coin";

/// Reserved object type for the native ZCN supply controller.
pub const TREASURY_CAP_OBJECT_TYPE: &str = "0x2::zcn::TreasuryCap";

/// Protocol-owned address namespace. No user key is allowed to act as this address.
pub const TREASURY_SYSTEM_ADDRESS: Address = [0u8; 20];

/// Singleton system object that commits to the native ZCN monetary supply.
pub const TREASURY_CAP_OBJECT_ID: ObjectID = ObjectID::new(TREASURY_SYSTEM_ADDRESS, u64::MAX);

/// Reserved system object type for the chain-wide transaction-fee policy.
pub const FEE_POLICY_OBJECT_TYPE: &str = "0x2::zcn::FeePolicy";

/// Singleton system object that commits the fee rule used by every block execution.
pub const FEE_POLICY_OBJECT_ID: ObjectID = ObjectID::new(TREASURY_SYSTEM_ADDRESS, u64::MAX - 2);

/// Chain-wide resource-credit policy.
///
/// Compute metering and block gas limits apply in every mode.  This policy is consensus state,
/// not a node-local launcher preference: changing it changes account nonces/credits and therefore
/// the block's account-root commitment.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Default,
)]
pub enum FeePolicy {
    /// Debit non-transferable legacy resource credits by the metered gas amount.
    Charged,
    /// Charge no resource credit while still validating budgets and advancing account nonces.
    #[default]
    Free,
}

impl FeePolicy {
    /// Return the caller-side resource-credit debit for a measured amount of gas.
    #[must_use]
    pub const fn caller_fee(self, gas_used: u64) -> u64 {
        match self {
            Self::Charged => gas_used,
            Self::Free => 0,
        }
    }
}

/// Serialized contents of the immutable, system-replaceable fee-policy singleton.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct FeePolicyState {
    /// Chain namespace the policy belongs to.
    pub chain_id: ChainId,
    /// Canonical execution policy.
    pub policy: FeePolicy,
}

/// Native ZCN supply state.
///
/// This cap tracks the complete native monetary domain: live UTXOs plus value locked in contract
/// and staking escrow. `Account.balance` is not native ZCN and is deliberately excluded.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct TreasuryCap {
    /// Outstanding native ZCN supply, including value temporarily locked in contract escrow.
    pub total_supply: u64,
    /// Cumulative native ZCN created by authorised mint operations.
    pub total_minted: u64,
    /// Cumulative native ZCN permanently destroyed by authorised burn operations.
    pub total_burned: u64,
    /// Once true, the one-time genesis mint authority can never be reopened.
    pub minting_closed: bool,
    /// Canonical commitment to the genesis allocation used for restart idempotence.
    pub genesis_commitment: Hash,
}

impl TreasuryCap {
    fn empty_open() -> Self {
        Self {
            total_supply: 0,
            total_minted: 0,
            total_burned: 0,
            minting_closed: false,
            genesis_commitment: [0u8; 32],
        }
    }

    fn validate(&self) -> PokerL1Result<()> {
        let expected_supply = self
            .total_minted
            .checked_sub(self.total_burned)
            .ok_or_else(|| {
                PokerL1Error::Other("TreasuryCap burned amount exceeds minted amount".into())
            })?;
        if self.total_supply != expected_supply {
            return Err(PokerL1Error::Other(format!(
                "TreasuryCap invariant violated: supply={} minted={} burned={}",
                self.total_supply, self.total_minted, self.total_burned
            )));
        }
        Ok(())
    }
}

/// Global reconciliation of every currently modelled native ZCN custody domain.
///
/// Seat `pending_addon` balances are accounting subsets of a table's `chip_pool`. A Texas rake is moved to a
/// Treasury-owned native Coin in the same precompile call, so it is counted as a live UTXO rather
/// than table escrow. Legacy [`crate::account::Account::balance`] is a resource credit and is
/// intentionally absent from this report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSupplyReconciliation {
    /// Supply committed by the singleton TreasuryCap.
    pub treasury_total_supply: u64,
    /// Cumulative authorised mint counter.
    pub treasury_total_minted: u64,
    /// Cumulative authorised burn counter.
    pub treasury_total_burned: u64,
    /// Sum of all structurally valid live NativeCoin UTXOs.
    pub live_utxo: u64,
    /// Sum of all validator stake currently held in staking escrow.
    pub staking_escrow: u64,
    /// Sum of `chip_pool` across every persisted Texas Poker table.
    pub texas_table_escrow: u64,
    /// `live_utxo + staking_escrow + texas_table_escrow`.
    pub observed_total: u64,
    /// Signed `observed_total - treasury_total_supply` diagnostic.
    pub delta: i128,
}

impl NativeSupplyReconciliation {
    /// Whether observed custody exactly matches the TreasuryCap supply.
    #[must_use]
    pub const fn is_balanced(&self) -> bool {
        self.delta == 0
    }

    /// Reject a supply mismatch while preserving the detailed report on success.
    pub fn require_balanced(self) -> PokerL1Result<Self> {
        if self.is_balanced() {
            return Ok(self);
        }
        Err(PokerL1Error::Other(format!(
            "native supply reconciliation mismatch: treasury={}, live_utxo={}, staking_escrow={}, texas_table_escrow={}, observed={}, delta={}",
            self.treasury_total_supply,
            self.live_utxo,
            self.staking_escrow,
            self.texas_table_escrow,
            self.observed_total,
            self.delta,
        )))
    }
}

/// Inspect every native ZCN custody domain and return a diagnostic report.
///
/// Structural corruption is fail-closed: malformed TreasuryCap/coin/table data, mutable coin
/// versions, invalid ownership, mismatched embedded table IDs and arithmetic overflow all return
/// an error. A pure supply mismatch is represented by a non-zero [`NativeSupplyReconciliation::delta`].
pub fn audit_native_supply(
    object_db: &ObjectDb,
    staking_escrow: u64,
) -> PokerL1Result<NativeSupplyReconciliation> {
    audit_native_supply_objects(object_db.iter(), staking_escrow)?.ok_or_else(|| {
        PokerL1Error::Other(
            "native supply reconciliation requires an initialized TreasuryCap".into(),
        )
    })
}

fn audit_native_supply_objects<'a>(
    objects: impl IntoIterator<Item = &'a Object>,
    staking_escrow: u64,
) -> PokerL1Result<Option<NativeSupplyReconciliation>> {
    let objects = objects.into_iter().collect::<Vec<_>>();
    let mut cap = None;

    let mut live_utxo = 0u64;
    let mut texas_table_escrow = 0u64;
    for object in &objects {
        if object.id == TREASURY_CAP_OBJECT_ID || object.object_type == TREASURY_CAP_OBJECT_TYPE {
            // Reject duplicate/wrongly-addressed TreasuryCap objects instead of ignoring them.
            let decoded = decode_treasury_cap(object)?;
            if cap.replace(decoded).is_some() {
                return Err(PokerL1Error::Other(
                    "multiple TreasuryCap objects found during native supply reconciliation".into(),
                ));
            }
            continue;
        }

        if is_native_coin_object(object) {
            let owner = match object.owner {
                Ownership::AddressOwned { owner } => owner,
                _ => {
                    return Err(PokerL1Error::Other(format!(
                        "native coin {:?} must be address-owned",
                        object.id
                    )));
                }
            };
            if object.id.creator_address != owner {
                return Err(PokerL1Error::Other(format!(
                    "native coin {:?} creator address does not match owner {:?}",
                    object.id, owner
                )));
            }
            if object.version != 0 {
                return Err(PokerL1Error::Other(format!(
                    "native coin {:?} is mutable/versioned; immutable UTXO version 0 required",
                    object.id
                )));
            }
            live_utxo = live_utxo
                .checked_add(decode_native_coin(object)?.amount)
                .ok_or_else(|| PokerL1Error::Other("live native UTXO sum overflow".into()))?;
            continue;
        }

        if object.object_type == TEXAS_POKER_TABLE_OBJECT_TYPE {
            if object.owner != Ownership::Shared {
                return Err(PokerL1Error::Other(format!(
                    "Texas Poker table {:?} must be shared",
                    object.id
                )));
            }
            use crate::vm::contracts::texas_poker::state_codec::{
                decode_hot_table_state, is_hot_table_state, table_governance_object_id,
                table_metadata_object_id, table_rules_object_id,
            };
            if !is_hot_table_state(&object.data) {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas Poker table {:?} must use hot v30 state during supply reconciliation",
                    object.id
                )));
            }
            let find_opening = |id: ObjectID, expected_type: &str, label: &str| {
                let opening = objects
                    .iter()
                    .copied()
                    .find(|candidate| candidate.id == id)
                    .ok_or(PokerL1Error::ObjectNotFound(id))?;
                if opening.object_type != expected_type || opening.owner != Ownership::Immutable {
                    return Err(PokerL1Error::Serialization(format!(
                        "Texas {label} object has non-canonical type or ownership during supply reconciliation"
                    )));
                }
                Ok(opening)
            };
            let metadata = find_opening(
                table_metadata_object_id(object.id),
                TEXAS_POKER_METADATA_OBJECT_TYPE,
                "metadata",
            )?;
            let rules = find_opening(
                table_rules_object_id(object.id),
                TEXAS_POKER_RULES_OBJECT_TYPE,
                "rules",
            )?;
            let governance = find_opening(
                table_governance_object_id(object.id),
                TEXAS_POKER_GOVERNANCE_OBJECT_TYPE,
                "governance",
            )?;
            let openings = TableContextOpenings {
                metadata: borsh::from_slice(&metadata.data).map_err(|error| {
                    PokerL1Error::Serialization(format!(
                        "decode Texas metadata during supply reconciliation: {error}"
                    ))
                })?,
                rules: borsh::from_slice(&rules.data).map_err(|error| {
                    PokerL1Error::Serialization(format!(
                        "decode Texas rules during supply reconciliation: {error}"
                    ))
                })?,
                governance: borsh::from_slice(&governance.data).map_err(|error| {
                    PokerL1Error::Serialization(format!(
                        "decode Texas governance during supply reconciliation: {error}"
                    ))
                })?,
            };
            let table: TexasPokerTable =
                decode_hot_table_state(&object.data, &openings).map_err(|error| {
                    PokerL1Error::Serialization(format!(
                        "decode TexasPokerTable {:?} during supply reconciliation: {error}",
                        object.id
                    ))
                })?;
            table.validate_state_schema()?;
            if table.id != object.id {
                return Err(PokerL1Error::Other(format!(
                    "Texas Poker table embedded id {:?} does not match object id {:?}",
                    table.id, object.id
                )));
            }
            let pending_addons = table.seats.iter().try_fold(0u64, |sum, seat| {
                sum.checked_add(seat.pending_addon()).ok_or_else(|| {
                    PokerL1Error::Other(format!(
                        "Texas Poker table {:?} pending-addon sum overflow",
                        object.id
                    ))
                })
            })?;
            if pending_addons > table.chip_pool {
                return Err(PokerL1Error::Other(format!(
                    "Texas Poker table {:?} pending addons {} exceed chip_pool {}",
                    object.id, pending_addons, table.chip_pool
                )));
            }
            texas_table_escrow = texas_table_escrow
                .checked_add(table.chip_pool)
                .ok_or_else(|| PokerL1Error::Other("Texas table escrow sum overflow".into()))?;
        }
    }

    let observed_total = live_utxo
        .checked_add(staking_escrow)
        .and_then(|total| total.checked_add(texas_table_escrow))
        .ok_or_else(|| PokerL1Error::Other("observed native supply sum overflow".into()))?;

    let Some(cap) = cap else {
        if observed_total == 0 {
            return Ok(None);
        }
        return Err(PokerL1Error::Other(format!(
            "native value exists without an initialized TreasuryCap: live_utxo={live_utxo}, staking_escrow={staking_escrow}, texas_table_escrow={texas_table_escrow}"
        )));
    };

    Ok(Some(NativeSupplyReconciliation {
        treasury_total_supply: cap.total_supply,
        treasury_total_minted: cap.total_minted,
        treasury_total_burned: cap.total_burned,
        live_utxo,
        staking_escrow,
        texas_table_escrow,
        observed_total,
        delta: i128::from(observed_total) - i128::from(cap.total_supply),
    }))
}

/// Strict global native-supply reconciliation.
///
/// This is the production health gate: unlike [`audit_native_supply`], a non-zero delta is an
/// error rather than a diagnostic-only result.
pub fn reconcile_native_supply(
    object_db: &ObjectDb,
    staking_escrow: u64,
) -> PokerL1Result<NativeSupplyReconciliation> {
    audit_native_supply(object_db, staking_escrow)?.require_balanced()
}

/// Reconcile native supply when Treasury has been initialized.
///
/// A pristine pre-genesis state with no native value is accepted as `None`.
/// Any native UTXO, staking escrow or Texas table escrow without TreasuryCap
/// is rejected instead of being treated as legacy monetary state.
pub fn reconcile_native_supply_if_initialized(
    object_db: &ObjectDb,
    staking_escrow: u64,
) -> PokerL1Result<Option<NativeSupplyReconciliation>> {
    audit_native_supply_objects(object_db.iter(), staking_escrow)?
        .map(NativeSupplyReconciliation::require_balanced)
        .transpose()
}

/// Reconcile an isolated candidate block state before any durable commit.
pub(crate) fn reconcile_native_supply_snapshot_if_initialized(
    snapshot: &crate::storage::ObjectDbSnapshot,
    staking_escrow: u64,
) -> PokerL1Result<Option<NativeSupplyReconciliation>> {
    audit_native_supply_objects(snapshot.iter(), staking_escrow)?
        .map(NativeSupplyReconciliation::require_balanced)
        .transpose()
}

/// Returns true for the singleton TreasuryCap ID or its reserved type tag.
#[must_use]
pub fn is_treasury_cap_object(object: &Object) -> bool {
    object.id == TREASURY_CAP_OBJECT_ID || object.object_type == TREASURY_CAP_OBJECT_TYPE
}

/// Returns true for object types whose creation or mutation is reserved to economics paths.
#[must_use]
pub fn is_reserved_economic_object(object: &Object) -> bool {
    is_native_coin_object(object) || is_treasury_cap_object(object) || is_fee_policy_object(object)
}

fn treasury_cap_object(cap: TreasuryCap, version: u64) -> PokerL1Result<Object> {
    cap.validate()?;
    let data = borsh::to_vec(&cap)
        .map_err(|error| PokerL1Error::Serialization(format!("encode TreasuryCap: {error}")))?;
    let mut object = Object::new(
        TREASURY_CAP_OBJECT_ID,
        Ownership::Shared,
        TREASURY_CAP_OBJECT_TYPE,
        data,
        None,
    );
    object.version = version;
    Ok(object)
}

/// Decode and validate the singleton TreasuryCap object.
pub fn decode_treasury_cap(object: &Object) -> PokerL1Result<TreasuryCap> {
    if object.id != TREASURY_CAP_OBJECT_ID
        || object.object_type != TREASURY_CAP_OBJECT_TYPE
        || object.owner != Ownership::Shared
    {
        return Err(PokerL1Error::Other(
            "invalid TreasuryCap singleton identity, type or ownership".into(),
        ));
    }
    let cap: TreasuryCap = borsh::from_slice(&object.data)
        .map_err(|error| PokerL1Error::Serialization(format!("decode TreasuryCap: {error}")))?;
    cap.validate()?;
    Ok(cap)
}

/// Read the native ZCN TreasuryCap. Absence is only valid before genesis initialisation.
pub fn read_treasury(object_db: &ObjectDb) -> PokerL1Result<Option<TreasuryCap>> {
    match object_db.read(&TREASURY_CAP_OBJECT_ID) {
        Ok(object) => Ok(Some(decode_treasury_cap(&object)?)),
        Err(PokerL1Error::ObjectNotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Construct the canonical fee-policy singleton for genesis or a governed replacement.
pub fn fee_policy_object(
    chain_id: ChainId,
    policy: FeePolicy,
    version: u64,
) -> PokerL1Result<Object> {
    let mut object = Object::new(
        FEE_POLICY_OBJECT_ID,
        Ownership::Immutable,
        FEE_POLICY_OBJECT_TYPE,
        borsh::to_vec(&FeePolicyState { chain_id, policy })?,
        None,
    );
    object.version = version;
    Ok(object)
}

/// Whether an object claims the reserved fee-policy singleton identity or type.
#[must_use]
pub fn is_fee_policy_object(object: &Object) -> bool {
    object.id == FEE_POLICY_OBJECT_ID || object.object_type == FEE_POLICY_OBJECT_TYPE
}

/// Validate the fee-policy singleton shape without binding it to one local chain ID.
///
/// Generic ObjectDb system-object admission needs this form because it is shared by every
/// chain namespace. Node startup and execution use [`decode_fee_policy`] below to additionally
/// bind the decoded state to their configured chain ID.
pub fn validate_fee_policy_object(object: &Object) -> PokerL1Result<FeePolicyState> {
    if object.id != FEE_POLICY_OBJECT_ID
        || object.object_type != FEE_POLICY_OBJECT_TYPE
        || object.owner != Ownership::Immutable
        || object.assigned_validator.is_some()
    {
        return Err(PokerL1Error::Other(
            "invalid fee-policy singleton identity, type or ownership".into(),
        ));
    }
    borsh::from_slice(&object.data)
        .map_err(|error| PokerL1Error::Serialization(format!("decode FeePolicy: {error}")))
}

/// Decode a fee-policy singleton and bind it to the expected chain namespace.
pub fn decode_fee_policy(object: &Object, expected_chain_id: ChainId) -> PokerL1Result<FeePolicy> {
    let state = validate_fee_policy_object(object)?;
    if state.chain_id != expected_chain_id {
        return Err(PokerL1Error::Other(format!(
            "fee-policy chain-id mismatch: expected {expected_chain_id}, got {}",
            state.chain_id
        )));
    }
    Ok(state.policy)
}

/// Read the authoritative fee policy.  Absence is valid only before genesis initialization.
pub fn read_fee_policy(
    object_db: &ObjectDb,
    chain_id: ChainId,
) -> PokerL1Result<Option<FeePolicy>> {
    match object_db.read(&FEE_POLICY_OBJECT_ID) {
        Ok(object) => decode_fee_policy(&object, chain_id).map(Some),
        Err(PokerL1Error::ObjectNotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Initialise an empty, open TreasuryCap without minting any coin.
///
/// Normal node startup uses [`genesis_mint`] so cap creation, coin creation and authority closure
/// occur in one atomic batch. This function exists for explicit genesis builders and tests.
pub fn initialize_treasury(object_db: &mut ObjectDb) -> PokerL1Result<()> {
    if read_treasury(object_db)?.is_some() {
        return Err(PokerL1Error::Other(
            "TreasuryCap is already initialized".into(),
        ));
    }
    if object_db.iter().any(is_native_coin_object) {
        return Err(PokerL1Error::Other(
            "cannot initialize TreasuryCap after native coins already exist".into(),
        ));
    }
    object_db.apply_batch(vec![ObjectMutation::SystemCreate(treasury_cap_object(
        TreasuryCap::empty_open(),
        0,
    )?)])
}

fn canonical_genesis_allocations(
    allocations: &[(Address, u64)],
) -> PokerL1Result<Vec<(Address, u64)>> {
    let mut canonical = allocations.to_vec();
    canonical.sort_by_key(|(owner, _)| *owner);
    for window in canonical.windows(2) {
        if window[0].0 == window[1].0 {
            return Err(PokerL1Error::Other(format!(
                "duplicate genesis allocation address {:?}",
                window[0].0
            )));
        }
    }
    if let Some((owner, _)) = canonical.iter().find(|(_, amount)| *amount == 0) {
        return Err(PokerL1Error::Other(format!(
            "genesis allocation for {owner:?} must be greater than zero"
        )));
    }
    Ok(canonical)
}

fn genesis_allocation_commitment(chain_id: ChainId, allocations: &[(Address, u64)]) -> Hash {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(b"ZCHAIN_GENESIS_NATIVE_ALLOC_V1");
    hasher.update(&chain_id.to_be_bytes());
    for (owner, amount) in allocations {
        hasher.update(owner);
        hasher.update(&amount.to_be_bytes());
    }
    let mut digest = [0u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .expect("output length is fixed");
    digest
}

fn genesis_coin_nonce(chain_id: ChainId, owner: &Address) -> u64 {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(b"ZCHAIN_GENESIS_NATIVE_COIN_V1");
    hasher.update(&chain_id.to_be_bytes());
    hasher.update(owner);
    let mut digest = [0u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .expect("output length is fixed");
    u64::from_be_bytes(digest[..8].try_into().expect("slice length is fixed"))
}

/// Atomically mint the canonical genesis allocation and permanently close minting.
///
/// Reapplying the identical allocation is a no-op. A different allocation after closure is
/// rejected, preventing a restart/configuration change from silently issuing more ZCN.
pub fn genesis_mint(
    object_db: &mut ObjectDb,
    chain_id: ChainId,
    allocations: &[(Address, u64)],
) -> PokerL1Result<usize> {
    genesis_mint_with_system_objects(object_db, chain_id, allocations, Vec::new())
}

/// Atomically mint genesis supply together with other canonical system singletons.
///
/// This is used by the node bootstrap so TreasuryCap, native UTXOs and the
/// validator-set state cannot be separated by a crash between database writes.
pub(crate) fn genesis_mint_with_system_objects(
    object_db: &mut ObjectDb,
    chain_id: ChainId,
    allocations: &[(Address, u64)],
    system_objects: Vec<Object>,
) -> PokerL1Result<usize> {
    let canonical = canonical_genesis_allocations(allocations)?;
    let commitment = genesis_allocation_commitment(chain_id, &canonical);

    let existing = match object_db.read(&TREASURY_CAP_OBJECT_ID) {
        Ok(object) => Some((decode_treasury_cap(&object)?, object.version)),
        Err(PokerL1Error::ObjectNotFound(_)) => None,
        Err(error) => return Err(error),
    };
    if let Some((cap, _)) = existing {
        if cap.minting_closed {
            if cap.genesis_commitment != commitment {
                return Err(PokerL1Error::Other(
                    "genesis mint is closed and allocation commitment differs".into(),
                ));
            }
            for expected in &system_objects {
                let actual = object_db.read(&expected.id).map_err(|error| {
                    PokerL1Error::Other(format!(
                        "genesis system object {:?} is missing after mint closure: {error}",
                        expected.id
                    ))
                })?;
                if &actual != expected {
                    return Err(PokerL1Error::Other(format!(
                        "genesis system object {:?} differs after mint closure",
                        expected.id
                    )));
                }
            }
            return Ok(0);
        }
        if cap.total_supply != 0 || cap.total_minted != 0 || cap.total_burned != 0 {
            return Err(PokerL1Error::Other(
                "open TreasuryCap must be empty before genesis mint".into(),
            ));
        }
    } else if object_db.iter().any(is_native_coin_object) {
        return Err(PokerL1Error::Other(
            "cannot establish genesis supply after untracked native coins already exist".into(),
        ));
    }

    let total = canonical.iter().try_fold(0u64, |sum, (_, amount)| {
        sum.checked_add(*amount)
            .ok_or_else(|| PokerL1Error::Other("genesis native supply overflow".into()))
    })?;
    let cap = TreasuryCap {
        total_supply: total,
        total_minted: total,
        total_burned: 0,
        minting_closed: true,
        genesis_commitment: commitment,
    };
    let cap_version = existing
        .map(|(_, version)| {
            version
                .checked_add(1)
                .ok_or_else(|| PokerL1Error::Other("TreasuryCap object version overflow".into()))
        })
        .transpose()?
        .unwrap_or(0);
    let cap_mutation = if existing.is_some() {
        ObjectMutation::SystemReplace(treasury_cap_object(cap, cap_version)?)
    } else {
        ObjectMutation::SystemCreate(treasury_cap_object(cap, cap_version)?)
    };
    let mut mutations = Vec::with_capacity(canonical.len() + system_objects.len() + 1);
    mutations.push(cap_mutation);
    mutations.extend(system_objects.into_iter().map(ObjectMutation::SystemCreate));
    for (owner, amount) in &canonical {
        mutations.push(ObjectMutation::Create(native_coin_object(
            *owner,
            *amount,
            genesis_coin_nonce(chain_id, owner),
        )?));
    }
    object_db.apply_batch(mutations)?;
    Ok(canonical.len())
}

/// Atomically destroy address-owned native coin UTXOs and reduce total supply.
pub fn burn_native_coins(
    object_db: &mut ObjectDb,
    owner: Address,
    input_ids: &[ObjectID],
) -> PokerL1Result<u64> {
    if input_ids.is_empty() {
        return Err(PokerL1Error::Other(
            "native coin burn requires at least one input".into(),
        ));
    }
    let cap_object = object_db.read(&TREASURY_CAP_OBJECT_ID)?;
    let mut cap = decode_treasury_cap(&cap_object)?;
    let mut seen = std::collections::BTreeSet::new();
    let mut burned = 0u64;
    for id in input_ids {
        if !seen.insert(*id) {
            return Err(PokerL1Error::Other(format!(
                "duplicate native coin burn input {id:?}"
            )));
        }
        let object = object_db.read(id)?;
        if object.owner != (Ownership::AddressOwned { owner }) {
            return Err(PokerL1Error::NotOwner(*id));
        }
        burned = burned
            .checked_add(decode_native_coin(&object)?.amount)
            .ok_or_else(|| PokerL1Error::Other("native coin burn sum overflow".into()))?;
    }
    cap.total_supply = cap
        .total_supply
        .checked_sub(burned)
        .ok_or_else(|| PokerL1Error::Other("native coin burn exceeds TreasuryCap supply".into()))?;
    cap.total_burned = cap
        .total_burned
        .checked_add(burned)
        .ok_or_else(|| PokerL1Error::Other("TreasuryCap burned counter overflow".into()))?;

    let mut mutations = Vec::with_capacity(input_ids.len() + 1);
    for id in input_ids {
        mutations.push(ObjectMutation::Delete(*id));
    }
    mutations.push(ObjectMutation::SystemReplace(treasury_cap_object(
        cap,
        cap_object
            .version
            .checked_add(1)
            .ok_or_else(|| PokerL1Error::Other("TreasuryCap object version overflow".into()))?,
    )?));
    object_db.apply_batch(mutations)?;
    Ok(burned)
}

/// Atomically account for native ZCN destroyed from an escrow balance.
///
/// Unlike [`burn_native_coins`], the value has already left the live UTXO set, so this operation
/// only advances the singleton TreasuryCap counters. Staking slashing uses this path after first
/// computing the corresponding reduction on a cloned validator set.
pub fn burn_escrowed_native(object_db: &mut dyn ObjectBackend, amount: u64) -> PokerL1Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let cap_object = object_db.read(&TREASURY_CAP_OBJECT_ID)?;
    let mut cap = decode_treasury_cap(&cap_object)?;
    cap.total_supply = cap
        .total_supply
        .checked_sub(amount)
        .ok_or_else(|| PokerL1Error::Other("escrow burn exceeds TreasuryCap supply".into()))?;
    cap.total_burned = cap
        .total_burned
        .checked_add(amount)
        .ok_or_else(|| PokerL1Error::Other("TreasuryCap burned counter overflow".into()))?;
    object_db.replace_system_object(treasury_cap_object(
        cap,
        cap_object
            .version
            .checked_add(1)
            .ok_or_else(|| PokerL1Error::Other("TreasuryCap object version overflow".into()))?,
    )?)
}

/// One immutable, address-owned native coin output.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct NativeCoin {
    /// Number of indivisible ZCN base units carried by this output.
    pub amount: u64,
}

impl NativeCoin {
    /// Construct a non-zero native coin value.
    pub fn new(amount: u64) -> PokerL1Result<Self> {
        if amount == 0 {
            return Err(PokerL1Error::Other(
                "native coin amount must be greater than zero".into(),
            ));
        }
        Ok(Self { amount })
    }
}

/// Returns true when an object is a reserved native coin output.
#[must_use]
pub fn is_native_coin_object(object: &Object) -> bool {
    object.object_type == NATIVE_COIN_OBJECT_TYPE
}

/// Decode and structurally validate a native coin object.
pub fn decode_native_coin(object: &Object) -> PokerL1Result<NativeCoin> {
    if !is_native_coin_object(object) {
        return Err(PokerL1Error::Other(format!(
            "object {:?} is not a native ZCN coin",
            object.id
        )));
    }
    let coin: NativeCoin = borsh::from_slice(&object.data)
        .map_err(|error| PokerL1Error::Serialization(format!("decode native ZCN coin: {error}")))?;
    NativeCoin::new(coin.amount)
}

/// Create a native coin object for an authorised genesis/treasury/escrow path.
pub fn native_coin_object(
    owner: Address,
    amount: u64,
    creation_nonce: u64,
) -> PokerL1Result<Object> {
    let coin = NativeCoin::new(amount)?;
    let data = borsh::to_vec(&coin)
        .map_err(|error| PokerL1Error::Serialization(format!("encode native ZCN coin: {error}")))?;
    Ok(Object::new(
        ObjectID::new(owner, creation_nonce),
        Ownership::AddressOwned { owner },
        NATIVE_COIN_OBJECT_TYPE,
        data,
        None,
    ))
}

/// Deterministically derive a coin output nonce from the transaction hash and output index.
#[must_use]
pub fn coin_output_nonce(tx_hash: &Hash, output_index: u32) -> u64 {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(b"ZCHAIN_NATIVE_COIN_OUTPUT_V1");
    hasher.update(tx_hash);
    hasher.update(&output_index.to_be_bytes());
    let mut digest = [0u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .expect("output length is fixed");
    u64::from_be_bytes(digest[..8].try_into().expect("slice length is fixed"))
}

/// Validated native-coin input selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCoinSelection {
    /// Coin object IDs to consume.
    pub input_ids: Vec<ObjectID>,
    /// Sum of all selected coin amounts.
    pub total: u64,
}

/// One native coin owned by an address, as exposed to wallets and RPC clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedNativeCoin {
    /// Immutable coin object ID used as a transaction input.
    pub id: ObjectID,
    /// Number of indivisible ZCN base units carried by the coin.
    pub amount: u64,
}

/// List all live native coins owned by `owner` in stable object-ID order.
///
/// A reserved coin object with malformed data or a non-zero version is treated as state
/// corruption and returned as an error rather than silently omitted from the wallet balance.
pub fn list_owned_native_coins(
    object_db: &ObjectDb,
    owner: Address,
) -> PokerL1Result<Vec<OwnedNativeCoin>> {
    let mut coins = object_db
        .iter()
        .filter(|object| {
            is_native_coin_object(object) && object.owner == (Ownership::AddressOwned { owner })
        })
        .map(|object| {
            if object.version != 0 {
                return Err(PokerL1Error::Other(format!(
                    "native coin {:?} is mutable/versioned; immutable UTXO version 0 required",
                    object.id
                )));
            }
            Ok(OwnedNativeCoin {
                id: object.id,
                amount: decode_native_coin(object)?.amount,
            })
        })
        .collect::<PokerL1Result<Vec<_>>>()?;
    coins.sort_by_key(|coin| coin.id);
    Ok(coins)
}

/// Aggregate an owner's spendable native-coin balance.
pub fn native_coin_balance(object_db: &ObjectDb, owner: Address) -> PokerL1Result<u64> {
    sum_native_coin_balance(&list_owned_native_coins(object_db, owner)?)
}

/// Aggregate a previously listed set of native coins with overflow protection.
pub fn sum_native_coin_balance(coins: &[OwnedNativeCoin]) -> PokerL1Result<u64> {
    coins.iter().try_fold(0u64, |total, coin| {
        total
            .checked_add(coin.amount)
            .ok_or_else(|| PokerL1Error::Other("native coin balance overflow".into()))
    })
}

/// Select native-coin inputs deterministically while minimizing wallet-visible fragmentation.
///
/// Selection order:
/// 1. exact single-coin match;
/// 2. smallest single coin that covers the amount;
/// 3. largest coins first until covered, minimizing the number of consumed inputs.
///
/// Object ID is the stable tie-breaker. The executor remains authoritative and revalidates the
/// selected IDs when the signed transaction is executed.
pub fn select_native_coins_from_candidates(
    coins: &[OwnedNativeCoin],
    required: u64,
) -> PokerL1Result<NativeCoinSelection> {
    if required == 0 {
        return Err(PokerL1Error::Other(
            "native coin spend amount must be greater than zero".into(),
        ));
    }

    let mut seen = std::collections::BTreeSet::new();
    for coin in coins {
        if coin.amount == 0 {
            return Err(PokerL1Error::Other(format!(
                "native coin {:?} has zero amount",
                coin.id
            )));
        }
        if !seen.insert(coin.id) {
            return Err(PokerL1Error::Other(format!(
                "duplicate native coin candidate {:?}",
                coin.id
            )));
        }
    }

    if let Some(coin) = coins
        .iter()
        .filter(|coin| coin.amount == required)
        .min_by_key(|coin| coin.id)
    {
        return Ok(NativeCoinSelection {
            input_ids: vec![coin.id],
            total: coin.amount,
        });
    }

    if let Some(coin) = coins
        .iter()
        .filter(|coin| coin.amount > required)
        .min_by_key(|coin| (coin.amount, coin.id))
    {
        return Ok(NativeCoinSelection {
            input_ids: vec![coin.id],
            total: coin.amount,
        });
    }

    let available = sum_native_coin_balance(coins)?;
    if available < required {
        return Err(PokerL1Error::InsufficientBalance {
            needed: required,
            has: available,
        });
    }

    let mut sorted = coins.to_vec();
    sorted.sort_by(|left, right| {
        right
            .amount
            .cmp(&left.amount)
            .then_with(|| left.id.cmp(&right.id))
    });

    let mut input_ids = Vec::new();
    let mut total = 0u64;
    for coin in sorted {
        input_ids.push(coin.id);
        total = total
            .checked_add(coin.amount)
            .ok_or_else(|| PokerL1Error::Other("native coin selection sum overflow".into()))?;
        if total >= required {
            break;
        }
    }

    Ok(NativeCoinSelection { input_ids, total })
}

/// List and deterministically select an owner's native coin inputs.
pub fn auto_select_native_coins(
    object_db: &ObjectDb,
    owner: Address,
    required: u64,
) -> PokerL1Result<NativeCoinSelection> {
    select_native_coins_from_candidates(&list_owned_native_coins(object_db, owner)?, required)
}

/// Validate that every declared input is a native coin owned by `owner` and covers `required`.
///
/// Coin objects are immutable UTXOs: the economic path deletes every selected input in full and
/// creates a deterministic change output. Mixing arbitrary objects into a funded Texas call is
/// rejected so the signed input set has one unambiguous monetary interpretation.
pub fn select_owned_native_coins(
    object_db: &dyn ObjectBackend,
    input_ids: &[ObjectID],
    owner: Address,
    required: u64,
) -> PokerL1Result<NativeCoinSelection> {
    if required == 0 {
        return Err(PokerL1Error::Other(
            "native coin spend amount must be greater than zero".into(),
        ));
    }
    if input_ids.is_empty() {
        return Err(PokerL1Error::Other(
            "funded call requires at least one native coin input".into(),
        ));
    }

    let mut total = 0u64;
    let mut seen = std::collections::BTreeSet::new();
    for id in input_ids {
        if !seen.insert(*id) {
            return Err(PokerL1Error::Other(format!(
                "duplicate native coin input {id:?}"
            )));
        }
        let object = object_db.read(id)?;
        if object.owner != (Ownership::AddressOwned { owner }) {
            return Err(PokerL1Error::NotOwner(*id));
        }
        if object.version != 0 {
            return Err(PokerL1Error::Other(format!(
                "native coin input {id:?} is mutable/versioned; immutable UTXO version 0 required"
            )));
        }
        let coin = decode_native_coin(&object)?;
        total = total
            .checked_add(coin.amount)
            .ok_or_else(|| PokerL1Error::Other("native coin input sum overflow".into()))?;
    }
    if total < required {
        return Err(PokerL1Error::InsufficientBalance {
            needed: required,
            has: total,
        });
    }
    Ok(NativeCoinSelection {
        input_ids: input_ids.to_vec(),
        total,
    })
}

/// Consume a validated selection and create deterministic change when necessary.
pub fn consume_native_coin_selection(
    object_db: &mut dyn ObjectBackend,
    selection: &NativeCoinSelection,
    owner: Address,
    required: u64,
    tx_hash: &Hash,
    output_index: u32,
) -> PokerL1Result<Option<ObjectID>> {
    let change = selection.total.checked_sub(required).ok_or_else(|| {
        PokerL1Error::Other("native coin selection is smaller than required amount".into())
    })?;
    let change_object = if change == 0 {
        None
    } else {
        Some(native_coin_object(
            owner,
            change,
            coin_output_nonce(tx_hash, output_index),
        )?)
    };

    if let Some(object) = &change_object {
        if object_db.read(&object.id).is_ok() {
            return Err(PokerL1Error::ObjectIDCollision(object.id));
        }
    }
    let change_id = change_object.as_ref().map(|object| object.id);
    object_db.replace_objects(&selection.input_ids, change_object.into_iter().collect())?;
    Ok(change_id)
}

/// Consume native-coin inputs and create an exact recipient output plus deterministic change.
///
/// Output index 0 is always the recipient payment and output index 1 is sender change. Every
/// input and output is validated before the first write, giving direct backends fail-before-write
/// semantics and capture backends a fully discardable transaction log.
pub fn transfer_native_coins(
    object_db: &mut dyn ObjectBackend,
    selection: &NativeCoinSelection,
    sender: Address,
    recipient: Address,
    amount: u64,
    tx_hash: &Hash,
) -> PokerL1Result<(ObjectID, Option<ObjectID>)> {
    if amount == 0 {
        return Err(PokerL1Error::Other(
            "native transfer amount must be greater than zero".into(),
        ));
    }
    let change = selection.total.checked_sub(amount).ok_or_else(|| {
        PokerL1Error::Other("native coin selection is smaller than transfer amount".into())
    })?;

    // Revalidate the supplied selection at the point of consumption. This prevents callers from
    // constructing a selection whose total or ownership differs from the live UTXOs.
    let validated = select_owned_native_coins(object_db, &selection.input_ids, sender, amount)?;
    if validated.total != selection.total {
        return Err(PokerL1Error::Other(format!(
            "native coin selection total mismatch: declared={}, actual={}",
            selection.total, validated.total
        )));
    }

    let recipient_object = native_coin_object(recipient, amount, coin_output_nonce(tx_hash, 0))?;
    let change_object = if change == 0 {
        None
    } else {
        Some(native_coin_object(
            sender,
            change,
            coin_output_nonce(tx_hash, 1),
        )?)
    };

    if change_object
        .as_ref()
        .is_some_and(|object| object.id == recipient_object.id)
    {
        return Err(PokerL1Error::ObjectIDCollision(recipient_object.id));
    }
    for object in std::iter::once(&recipient_object).chain(change_object.iter()) {
        match object_db.read(&object.id) {
            Ok(_) => return Err(PokerL1Error::ObjectIDCollision(object.id)),
            Err(PokerL1Error::ObjectNotFound(_)) => {}
            Err(error) => return Err(error),
        }
    }

    let recipient_id = recipient_object.id;
    let change_id = change_object.as_ref().map(|object| object.id);
    let mut outputs = vec![recipient_object];
    outputs.extend(change_object);
    object_db.replace_objects(&selection.input_ids, outputs)?;
    Ok((recipient_id, change_id))
}

/// Derive a deterministic pseudo-transaction hash for a system-owned native-coin operation.
///
/// The caller supplies a fixed protocol domain. Sorted input IDs make retries deterministic while
/// still producing a distinct output namespace for different consumed UTXOs.
#[must_use]
pub fn system_coin_operation_hash(
    domain: &[u8],
    owner: Address,
    input_ids: &[ObjectID],
    amount: u64,
    sequence: u64,
) -> Hash {
    let mut ids = input_ids.to_vec();
    ids.sort();
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(b"ZCHAIN_SYSTEM_NATIVE_COIN_OP_V1");
    hasher.update(&(domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update(&owner);
    hasher.update(&amount.to_be_bytes());
    hasher.update(&sequence.to_be_bytes());
    for id in ids {
        hasher.update(&id.to_bytes());
    }
    let mut digest = [0u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .expect("output length is fixed");
    digest
}

/// Create one deterministic escrow payout coin.
pub fn create_native_coin_output(
    object_db: &mut dyn ObjectBackend,
    owner: Address,
    amount: u64,
    tx_hash: &Hash,
    output_index: u32,
) -> PokerL1Result<ObjectID> {
    let object = native_coin_object(owner, amount, coin_output_nonce(tx_hash, output_index))?;
    let id = object.id;
    object_db.create(object)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::object_db::ObjectDb;
    use crate::vm::contracts::texas_poker::types::{SeatStatus, TexasPokerTable};
    use blstrs::G1Projective;
    use group::Group;
    use poker_protocol::crypto::types::ECPoint;

    fn live_native_supply(db: &ObjectDb) -> u64 {
        db.iter()
            .filter(|object| is_native_coin_object(object))
            .map(|object| decode_native_coin(object).unwrap().amount)
            .sum()
    }

    fn texas_table_objects(id: ObjectID, chip_pool: u64, addon_pool: u64) -> Vec<Object> {
        use crate::vm::contracts::texas_poker::state_codec::table_storage_objects;
        let mut table = TexasPokerTable::new(id, "reconciliation".into(), [0x77; 20], 6, 50, 100);
        table.chip_pool = chip_pool;
        if addon_pool > 0 {
            table.seats[0].fixture_set_player([0x55; 20]);
            table.seats[0].set_status(SeatStatus::Waiting);
            table.seats[0].fixture_set_pk(ECPoint(G1Projective::generator()));
            table.seats[0].set_pending_addon(addon_pool).unwrap();
        }
        table_storage_objects(&table).unwrap().into_iter().collect()
    }

    #[test]
    fn native_supply_reconciliation_counts_utxo_staking_and_table_escrow_once() {
        let owner = [0x11; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        genesis_mint(&mut db, 7, &[(owner, 1_000)]).unwrap();
        let input = list_owned_native_coins(&db, owner).unwrap()[0];
        let selection = select_owned_native_coins(&db, &[input.id], owner, 300).unwrap();
        consume_native_coin_selection(&mut db, &selection, owner, 300, &[0xCD; 32], 0).unwrap();

        let table_id = ObjectID::new([0x88; 20], 9);
        for object in texas_table_objects(table_id, 200, 50) {
            db.create(object).unwrap();
        }

        let report = reconcile_native_supply(&db, 100).unwrap();
        assert_eq!(report.treasury_total_supply, 1_000);
        assert_eq!(report.live_utxo, 700);
        assert_eq!(report.staking_escrow, 100);
        assert_eq!(report.texas_table_escrow, 200);
        assert_eq!(report.observed_total, 1_000);
        assert_eq!(report.delta, 0);
    }

    #[test]
    fn native_supply_audit_reports_unbacked_table_value_but_strict_reconcile_rejects_it() {
        let mut db = ObjectDb::open_inmemory().unwrap();
        genesis_mint(&mut db, 7, &[([0x11; 20], 1_000)]).unwrap();
        let table_id = ObjectID::new([0x88; 20], 10);
        for object in texas_table_objects(table_id, 25, 0) {
            db.create(object).unwrap();
        }

        let report = audit_native_supply(&db, 0).unwrap();
        assert_eq!(report.delta, 25);
        assert!(reconcile_native_supply(&db, 0).is_err());
    }

    #[test]
    fn pregenesis_reconciliation_allows_only_zero_native_value() {
        let mut db = ObjectDb::open_inmemory().unwrap();
        assert_eq!(
            reconcile_native_supply_if_initialized(&db, 0).unwrap(),
            None
        );

        let table_id = ObjectID::new([0x88; 20], 110);
        for object in texas_table_objects(table_id, 1, 0) {
            db.create(object).unwrap();
        }
        let error = reconcile_native_supply_if_initialized(&db, 0).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("without an initialized TreasuryCap")
        );
    }

    #[test]
    fn candidate_snapshot_reconciliation_rejects_unbacked_table_escrow() {
        let mut db = ObjectDb::open_inmemory().unwrap();
        genesis_mint(&mut db, 7, &[([0x11; 20], 1_000)]).unwrap();
        let root_before = db.state_root();

        let mut snapshot = db.create_snapshot();
        let table_id = ObjectID::new([0x88; 20], 111);
        for object in texas_table_objects(table_id, 1, 0) {
            snapshot.create(object).unwrap();
        }
        assert!(reconcile_native_supply_snapshot_if_initialized(&snapshot, 0).is_err());
        snapshot.discard();

        assert_eq!(db.state_root(), root_before);
        assert!(reconcile_native_supply(&db, 0).unwrap().is_balanced());
    }

    #[test]
    fn native_supply_audit_rejects_malformed_coin_and_table_objects() {
        let mut wrong_owner_db = ObjectDb::open_inmemory().unwrap();
        genesis_mint(&mut wrong_owner_db, 7, &[([0x11; 20], 100)]).unwrap();
        let mut wrong_owner_coin = native_coin_object([0x22; 20], 1, 99).unwrap();
        wrong_owner_coin.owner = Ownership::AddressOwned { owner: [0x33; 20] };
        wrong_owner_db.create(wrong_owner_coin).unwrap();
        assert!(audit_native_supply(&wrong_owner_db, 0).is_err());

        let mut versioned_db = ObjectDb::open_inmemory().unwrap();
        genesis_mint(&mut versioned_db, 7, &[([0x11; 20], 100)]).unwrap();
        let mut versioned_coin = native_coin_object([0x22; 20], 1, 100).unwrap();
        versioned_coin.version = 1;
        versioned_db.create(versioned_coin).unwrap();
        assert!(audit_native_supply(&versioned_db, 0).is_err());

        let mut malformed_table_db = ObjectDb::open_inmemory().unwrap();
        genesis_mint(&mut malformed_table_db, 7, &[([0x11; 20], 100)]).unwrap();
        let table_id = ObjectID::new([0x88; 20], 11);
        let mut objects = texas_table_objects(table_id, 5, 6);
        objects[0].owner = Ownership::AddressOwned { owner: [0x88; 20] };
        for object in objects {
            malformed_table_db.create(object).unwrap();
        }
        assert!(audit_native_supply(&malformed_table_db, 0).is_err());
    }

    #[test]
    fn native_supply_audit_rejects_overflow() {
        let mut db = ObjectDb::open_inmemory().unwrap();
        genesis_mint(&mut db, 7, &[([0x11; 20], u64::MAX)]).unwrap();
        assert!(audit_native_supply(&db, 1).is_err());
    }

    #[test]
    fn genesis_mint_atomically_establishes_closed_supply() {
        let mut db = ObjectDb::open_inmemory().unwrap();
        let allocations = vec![([0x22; 20], 500), ([0x11; 20], 1_000)];

        assert_eq!(genesis_mint(&mut db, 7, &allocations).unwrap(), 2);
        let cap = read_treasury(&db).unwrap().unwrap();
        assert_eq!(cap.total_supply, 1_500);
        assert_eq!(cap.total_minted, 1_500);
        assert_eq!(cap.total_burned, 0);
        assert!(cap.minting_closed);
        assert_eq!(cap.total_supply, cap.total_minted - cap.total_burned);
        assert_eq!(live_native_supply(&db), cap.total_supply);
    }

    #[test]
    fn repeated_genesis_is_idempotent_but_changed_allocation_is_rejected() {
        let mut db = ObjectDb::open_inmemory().unwrap();
        let allocations = vec![([0x11; 20], 1_000), ([0x22; 20], 500)];
        genesis_mint(&mut db, 7, &allocations).unwrap();
        let root = db.state_root();

        let reordered = vec![([0x22; 20], 500), ([0x11; 20], 1_000)];
        assert_eq!(genesis_mint(&mut db, 7, &reordered).unwrap(), 0);
        assert_eq!(db.state_root(), root);
        assert!(genesis_mint(&mut db, 7, &[([0x11; 20], 1_001)]).is_err());
        assert_eq!(db.state_root(), root);
    }

    #[test]
    fn burn_atomically_deletes_coins_and_updates_supply() {
        let owner = [0x11; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        genesis_mint(&mut db, 7, &[(owner, 1_000), ([0x22; 20], 500)]).unwrap();
        let coin = list_owned_native_coins(&db, owner).unwrap()[0];

        assert_eq!(
            burn_native_coins(&mut db, owner, &[coin.id]).unwrap(),
            1_000
        );
        assert!(db.read(&coin.id).is_err());
        let cap = read_treasury(&db).unwrap().unwrap();
        assert_eq!(cap.total_supply, 500);
        assert_eq!(cap.total_minted, 1_500);
        assert_eq!(cap.total_burned, 1_000);
        assert_eq!(cap.total_supply, cap.total_minted - cap.total_burned);
        assert_eq!(live_native_supply(&db), cap.total_supply);
    }

    #[test]
    fn failed_burn_preserves_coin_and_treasury_state() {
        let owner = [0x11; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        genesis_mint(&mut db, 7, &[(owner, 1_000)]).unwrap();
        let coin = list_owned_native_coins(&db, owner).unwrap()[0];
        let root = db.state_root();
        let cap = read_treasury(&db).unwrap().unwrap();

        assert!(burn_native_coins(&mut db, [0x22; 20], &[coin.id]).is_err());
        assert_eq!(db.state_root(), root);
        assert_eq!(read_treasury(&db).unwrap().unwrap(), cap);
        assert_eq!(
            decode_native_coin(&db.read(&coin.id).unwrap())
                .unwrap()
                .amount,
            1_000
        );
    }

    #[test]
    fn genesis_overflow_fails_without_partial_state() {
        let mut db = ObjectDb::open_inmemory().unwrap();
        assert!(genesis_mint(&mut db, 7, &[([0x11; 20], u64::MAX), ([0x22; 20], 1)]).is_err());
        assert!(read_treasury(&db).unwrap().is_none());
        assert_eq!(live_native_supply(&db), 0);
    }

    #[test]
    fn treasury_rejects_generic_mutation_and_deletion() {
        let mut db = ObjectDb::open_inmemory().unwrap();
        genesis_mint(&mut db, 7, &[([0x11; 20], 1_000)]).unwrap();
        let root = db.state_root();

        assert!(
            db.update(&TREASURY_CAP_OBJECT_ID, &[0x44; 20], vec![])
                .is_err()
        );
        assert!(db.delete(&TREASURY_CAP_OBJECT_ID).is_err());
        assert_eq!(db.state_root(), root);
        assert!(read_treasury(&db).unwrap().is_some());
    }

    #[test]
    fn owned_coin_selection_consumes_inputs_and_creates_change() {
        let owner = [0x11; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        let first = native_coin_object(owner, 70, 1).unwrap();
        let second = native_coin_object(owner, 50, 2).unwrap();
        db.create(first.clone()).unwrap();
        db.create(second.clone()).unwrap();

        let selected = select_owned_native_coins(&db, &[first.id, second.id], owner, 100).unwrap();
        let change_id =
            consume_native_coin_selection(&mut db, &selected, owner, 100, &[0xAA; 32], 0)
                .unwrap()
                .unwrap();

        assert!(db.read(&first.id).is_err());
        assert!(db.read(&second.id).is_err());
        let change = decode_native_coin(&db.read(&change_id).unwrap()).unwrap();
        assert_eq!(change.amount, 20);
    }

    #[test]
    fn native_transfer_preserves_value_across_payment_and_change() {
        let sender = [0x11; 20];
        let recipient = [0x22; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        let first = native_coin_object(sender, 70, 1).unwrap();
        let second = native_coin_object(sender, 50, 2).unwrap();
        db.create(first.clone()).unwrap();
        db.create(second.clone()).unwrap();
        let selection =
            select_owned_native_coins(&db, &[first.id, second.id], sender, 100).unwrap();

        let (payment_id, change_id) =
            transfer_native_coins(&mut db, &selection, sender, recipient, 100, &[0xAB; 32])
                .unwrap();

        assert!(db.read(&first.id).is_err());
        assert!(db.read(&second.id).is_err());
        assert_eq!(
            decode_native_coin(&db.read(&payment_id).unwrap())
                .unwrap()
                .amount,
            100
        );
        assert_eq!(
            decode_native_coin(&db.read(&change_id.unwrap()).unwrap())
                .unwrap()
                .amount,
            20
        );
        assert_eq!(native_coin_balance(&db, recipient).unwrap(), 100);
        assert_eq!(native_coin_balance(&db, sender).unwrap(), 20);
    }

    #[test]
    fn escrow_burn_updates_treasury_without_deleting_live_change() {
        let owner = [0x11; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        genesis_mint(&mut db, 7, &[(owner, 1_000)]).unwrap();
        let input = list_owned_native_coins(&db, owner).unwrap()[0];
        let selection = select_owned_native_coins(&db, &[input.id], owner, 250).unwrap();
        consume_native_coin_selection(&mut db, &selection, owner, 250, &[0xBC; 32], 0).unwrap();
        burn_escrowed_native(&mut db, 250).unwrap();

        let cap = read_treasury(&db).unwrap().unwrap();
        assert_eq!(cap.total_supply, 750);
        assert_eq!(cap.total_minted, 1_000);
        assert_eq!(cap.total_burned, 250);
        assert_eq!(native_coin_balance(&db, owner).unwrap(), 750);
    }

    #[test]
    fn wrong_owner_and_duplicate_inputs_are_rejected_without_mutation() {
        let owner = [0x11; 20];
        let other = [0x22; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        let coin = native_coin_object(owner, 70, 1).unwrap();
        db.create(coin.clone()).unwrap();

        assert!(select_owned_native_coins(&db, &[coin.id], other, 50).is_err());
        assert!(select_owned_native_coins(&db, &[coin.id, coin.id], owner, 50).is_err());
        assert!(db.read(&coin.id).is_ok());
    }

    #[test]
    fn wallet_lists_and_aggregates_only_owned_native_coins() {
        let owner = [0x11; 20];
        let other = [0x22; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        db.create(native_coin_object(owner, 30, 3).unwrap())
            .unwrap();
        db.create(native_coin_object(owner, 70, 1).unwrap())
            .unwrap();
        db.create(native_coin_object(other, 900, 2).unwrap())
            .unwrap();
        db.create(Object::new(
            ObjectID::new(owner, 4),
            Ownership::AddressOwned { owner },
            "0x2::example::NotCoin",
            vec![],
            None,
        ))
        .unwrap();

        let coins = list_owned_native_coins(&db, owner).unwrap();
        assert_eq!(coins.len(), 2);
        assert_eq!(coins[0].id.creation_nonce, 1);
        assert_eq!(coins[1].id.creation_nonce, 3);
        assert_eq!(native_coin_balance(&db, owner).unwrap(), 100);
    }

    #[test]
    fn auto_selection_prefers_exact_then_smallest_covering_coin() {
        let owner = [0x11; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        let exact = native_coin_object(owner, 50, 3).unwrap();
        let smallest_cover = native_coin_object(owner, 60, 2).unwrap();
        let large = native_coin_object(owner, 100, 1).unwrap();
        for coin in [&large, &smallest_cover, &exact] {
            db.create(coin.clone()).unwrap();
        }

        let selected = auto_select_native_coins(&db, owner, 50).unwrap();
        assert_eq!(selected.input_ids, vec![exact.id]);
        assert_eq!(selected.total, 50);

        let selected = auto_select_native_coins(&db, owner, 55).unwrap();
        assert_eq!(selected.input_ids, vec![smallest_cover.id]);
        assert_eq!(selected.total, 60);
    }

    #[test]
    fn auto_selection_uses_largest_first_with_stable_ties() {
        let owner = [0x11; 20];
        let coins = vec![
            OwnedNativeCoin {
                id: ObjectID::new(owner, 3),
                amount: 40,
            },
            OwnedNativeCoin {
                id: ObjectID::new(owner, 1),
                amount: 40,
            },
            OwnedNativeCoin {
                id: ObjectID::new(owner, 2),
                amount: 30,
            },
        ];

        let selected = select_native_coins_from_candidates(&coins, 70).unwrap();
        assert_eq!(
            selected.input_ids,
            vec![ObjectID::new(owner, 1), ObjectID::new(owner, 3)]
        );
        assert_eq!(selected.total, 80);
    }

    #[test]
    fn auto_selection_reports_aggregated_insufficient_balance() {
        let owner = [0x11; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        db.create(native_coin_object(owner, 40, 1).unwrap())
            .unwrap();
        db.create(native_coin_object(owner, 30, 2).unwrap())
            .unwrap();

        assert!(matches!(
            auto_select_native_coins(&db, owner, 80),
            Err(PokerL1Error::InsufficientBalance {
                needed: 80,
                has: 70
            })
        ));
    }
}
