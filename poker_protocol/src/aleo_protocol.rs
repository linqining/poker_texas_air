//! Aleo-native BLS12-377 mental-poker messages.
//!
//! The legacy protocol uses BLS12-381 and Move-era transcripts.  It cannot be
//! placed in an Aleo Varuna witness by serializing or hashing its bytes.  This
//! module instead uses the *exact* `snarkvm-console` group and scalar types
//! used by the native settlement circuit: the prime-order Edwards subgroup in
//! Aleo's BLS12-377 environment.  Its proof transcripts deliberately mirror
//! `aleo_varuna_adapter::native::crypto`.
//!
//! These bundles are private witness material for the final Varuna proof.  A
//! browser may send them to the prover over the authenticated action channel;
//! they are not an Aleo transaction ABI and must never be substituted by a
//! commitment of arbitrary bytes.

use std::io::Cursor;

use borsh::{BorshDeserialize, BorshSerialize};
use rand::seq::SliceRandom;
use rand_core::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_256};
use snarkvm_console::{
    network::{MainnetV0, Network},
    prelude::{FromBytes, ToBytes, ToField, Zero},
    types::{Field as ConsoleField, Group as ConsoleGroup, Scalar as ConsoleScalar},
};

/// The native Aleo BLS12-377 Edwards subgroup, shared exactly with the
/// `aleo_varuna_adapter` Varuna witness.
pub type NativeGroup = ConsoleGroup<MainnetV0>;
/// The scalar field corresponding to [`NativeGroup`].
pub type NativeScalar = ConsoleScalar<MainnetV0>;
/// Aleo's base field used by its Poseidon transcript.
pub type NativeField = ConsoleField<MainnetV0>;

/// The byte sizes are consensus-stable for `snarkvm-console` 4.7.3: group and
/// field values are encoded as a canonical x-coordinate/field element, and a
/// scalar is a canonical BLS12-377 scalar. Keeping fixed encodings makes Borsh
/// malformed-input rejection deterministic in WASM and the proving service.
const NATIVE_ELEMENT_BYTES: usize = 32;
pub const ALEO_NATIVE_DECK_SIZE: usize = 52;
/// The fixed native DLEQ statement has one registered-key relation followed
/// by one relation for every card in a complete deck reconstruction.
pub const ALEO_NATIVE_DLEQ_RELATION_COUNT: usize = ALEO_NATIVE_DECK_SIZE + 1;
const INITIAL_DECK_DOMAIN: &str = "zchain.poker.aleo.initial-deck.v1";
const SHOWDOWN_INITIAL_DECK_DOMAIN: &str = "zchain.poker.aleo.initial-deck.v2";
/// Native deck/reveal protocol generation whose plaintext is algebraically
/// bound to canonical card ids. Version 1 remains available for existing hand
/// journals but cannot be used by a showdown settlement proof.
pub const ALEO_SHOWDOWN_DECK_PROTOCOL_VERSION: u8 = 2;

fn borsh_error(message: impl Into<String>) -> borsh::io::Error {
    borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, message.into())
}

fn write_bytes<T: ToBytes, W: borsh::io::Write>(
    value: &T,
    writer: &mut W,
) -> borsh::io::Result<()> {
    let bytes = value
        .to_bytes_le()
        .map_err(|error| borsh_error(format!("encode native Aleo element: {error}")))?;
    if bytes.len() != NATIVE_ELEMENT_BYTES {
        return Err(borsh_error("unexpected native Aleo element byte length"));
    }
    writer.write_all(&bytes)
}

fn read_native_group<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<NativeGroup> {
    let mut bytes = [0u8; NATIVE_ELEMENT_BYTES];
    reader.read_exact(&mut bytes)?;
    NativeGroup::read_le(Cursor::new(bytes))
        .map_err(|error| borsh_error(format!("invalid canonical Aleo group: {error}")))
}

fn read_native_scalar<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<NativeScalar> {
    let mut bytes = [0u8; NATIVE_ELEMENT_BYTES];
    reader.read_exact(&mut bytes)?;
    NativeScalar::read_le(Cursor::new(bytes))
        .map_err(|error| borsh_error(format!("invalid canonical Aleo scalar: {error}")))
}

fn read_native_field<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<NativeField> {
    let mut bytes = [0u8; NATIVE_ELEMENT_BYTES];
    reader.read_exact(&mut bytes)?;
    NativeField::read_le(Cursor::new(bytes))
        .map_err(|error| borsh_error(format!("invalid canonical Aleo field: {error}")))
}

/// Borsh-safe native group wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AleoGroup(pub NativeGroup);

impl AleoGroup {
    pub fn to_hex(self) -> Result<String, String> {
        self.0
            .to_bytes_le()
            .map(hex::encode)
            .map_err(|error| error.to_string())
    }

    pub fn from_hex(value: &str) -> Result<Self, String> {
        let bytes = hex::decode(value).map_err(|error| error.to_string())?;
        if bytes.len() != NATIVE_ELEMENT_BYTES {
            return Err("Aleo group encoding must be exactly 32 bytes".into());
        }
        NativeGroup::read_le(Cursor::new(bytes))
            .map(Self)
            .map_err(|error| format!("invalid canonical Aleo group: {error}"))
    }
}

impl BorshSerialize for AleoGroup {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        write_bytes(&self.0, writer)
    }
}

impl BorshDeserialize for AleoGroup {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        read_native_group(reader).map(Self)
    }
}

/// Borsh-safe native scalar wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AleoScalar(pub NativeScalar);

impl AleoScalar {
    pub fn to_hex(self) -> Result<String, String> {
        self.0
            .to_bytes_le()
            .map(hex::encode)
            .map_err(|error| error.to_string())
    }

    pub fn from_hex(value: &str) -> Result<Self, String> {
        let bytes = hex::decode(value).map_err(|error| error.to_string())?;
        if bytes.len() != NATIVE_ELEMENT_BYTES {
            return Err("Aleo scalar encoding must be exactly 32 bytes".into());
        }
        NativeScalar::read_le(Cursor::new(bytes))
            .map(Self)
            .map_err(|error| format!("invalid canonical Aleo scalar: {error}"))
    }
}

impl BorshSerialize for AleoScalar {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        write_bytes(&self.0, writer)
    }
}

impl BorshDeserialize for AleoScalar {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        read_native_scalar(reader).map(Self)
    }
}

/// Borsh-safe native field wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AleoField(pub NativeField);

impl AleoField {
    pub fn to_hex(self) -> Result<String, String> {
        self.0
            .to_bytes_le()
            .map(hex::encode)
            .map_err(|error| error.to_string())
    }

    pub fn from_hex(value: &str) -> Result<Self, String> {
        let bytes = hex::decode(value).map_err(|error| error.to_string())?;
        if bytes.len() != NATIVE_ELEMENT_BYTES {
            return Err("Aleo field encoding must be exactly 32 bytes".into());
        }
        NativeField::read_le(Cursor::new(bytes))
            .map(Self)
            .map_err(|error| format!("invalid canonical Aleo field: {error}"))
    }
}

impl BorshSerialize for AleoField {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        write_bytes(&self.0, writer)
    }
}

impl BorshDeserialize for AleoField {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        read_native_field(reader).map(Self)
    }
}

/// Exponential ElGamal ciphertext on Aleo's native group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AleoCiphertext {
    pub c1: AleoGroup,
    pub c2: AleoGroup,
}

impl AleoCiphertext {
    pub fn encrypt(plaintext: AleoGroup, public_key: AleoGroup, randomness: AleoScalar) -> Self {
        Self {
            c1: AleoGroup(NativeGroup::generator() * randomness.0),
            c2: AleoGroup(plaintext.0 + public_key.0 * randomness.0),
        }
    }

    pub fn reencrypt(self, public_key: AleoGroup, randomness: AleoScalar) -> Self {
        Self {
            c1: AleoGroup(self.c1.0 + NativeGroup::generator() * randomness.0),
            c2: AleoGroup(self.c2.0 + public_key.0 * randomness.0),
        }
    }

    pub fn valid(self) -> bool {
        !self.c1.0.is_zero() && !self.c2.0.is_zero()
    }
}

/// Context copied exactly into the native Varuna protocol-proof slot. The
/// proving service must derive this from the canonical action row; callers
/// must not invent it from browser state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AleoProtocolContext {
    pub circuit_id: AleoField,
    pub table_id: AleoField,
    pub hand_id: u32,
    pub action_index: u16,
    pub command_digest: AleoField,
}

impl AleoProtocolContext {
    pub fn fields(self) -> [NativeField; 5] {
        [
            self.circuit_id.0,
            self.table_id.0,
            NativeField::from_u32(self.hand_id),
            NativeField::from_u16(self.action_index),
            self.command_digest.0,
        ]
    }
}

const SCHNORR_DOMAIN: &str = "zchain.poker.aleo.schnorr.v1";
const CHAUM_PEDERSEN_DOMAIN: &str = "zchain.poker.aleo.chaum-pedersen.v1";
const SHARED_DLEQ_DOMAIN: &str = "zchain.poker.aleo.shared-dleq.v1";

fn challenge(
    domain: &str,
    context: AleoProtocolContext,
    fields: &[NativeField],
    points: &[NativeGroup],
    scalars: &[NativeScalar],
) -> Result<NativeScalar, String> {
    let mut preimage = Vec::with_capacity(1 + 5 + fields.len() + points.len() + scalars.len());
    preimage.push(NativeField::new_domain_separator(domain));
    preimage.extend(context.fields());
    preimage.extend_from_slice(fields);
    for point in points {
        preimage.push(point.to_field().map_err(|error| error.to_string())?);
    }
    for scalar in scalars {
        preimage.push(scalar.to_field().map_err(|error| error.to_string())?);
    }
    MainnetV0::hash_to_scalar_psd8(&preimage).map_err(|error| error.to_string())
}

fn sample_nonzero_scalar(rng: &mut (impl CryptoRng + RngCore)) -> NativeScalar {
    loop {
        let mut bytes = [0u8; NATIVE_ELEMENT_BYTES];
        rng.fill_bytes(&mut bytes);
        if let Ok(scalar) = NativeScalar::read_le(Cursor::new(bytes)) {
            if !scalar.is_zero() {
                return scalar;
            }
        }
    }
}

/// Deterministically derive a nonzero secret from local wallet-owned material.
/// This never reads or exports an Aleo account private key; callers should use
/// a wallet-backed secret store or a fresh random seed in production.
pub fn derive_secret(seed: &[u8]) -> NativeScalar {
    for counter in 0u32.. {
        let mut hasher = Sha3_256::new();
        hasher.update(b"zchain.poker.aleo.bls12-377.secret.v1");
        hasher.update(seed);
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();
        if let Ok(scalar) = NativeScalar::read_le(Cursor::new(digest.to_vec())) {
            if !scalar.is_zero() {
                return scalar;
            }
        }
    }
    unreachable!("u32 domain-separation counter exhausted")
}

/// Build the deterministic public seed deck for one native protocol hand.
///
/// These points are not converted from the legacy BLS12-381 deck. They are
/// generated directly in Aleo's native BLS12-377 group and are identical in
/// the browser and proving service. Player shuffles replace this public seed
/// deck with privately permuted/rerandomized native ciphertexts.
#[must_use]
pub fn initial_native_deck(table_id: u64, hand_id: u32) -> Vec<AleoCiphertext> {
    (0..ALEO_NATIVE_DECK_SIZE)
        .map(|card_index| {
            let scalar = |component: u8| {
                let mut seed = Vec::with_capacity(INITIAL_DECK_DOMAIN.len() + 8 + 4 + 8 + 1);
                seed.extend_from_slice(INITIAL_DECK_DOMAIN.as_bytes());
                seed.extend_from_slice(&table_id.to_le_bytes());
                seed.extend_from_slice(&hand_id.to_le_bytes());
                seed.extend_from_slice(&(card_index as u64).to_le_bytes());
                seed.push(component);
                derive_secret(&seed)
            };
            AleoCiphertext {
                c1: AleoGroup(NativeGroup::generator() * scalar(0)),
                c2: AleoGroup(NativeGroup::generator() * scalar(1)),
            }
        })
        .collect()
}

/// Canonical one-based card plaintext used by the v2 native deck.
///
/// The public encoding is `G * card_id` for `card_id in 1..=52`. Zero is
/// reserved for fixed-width padding in the outer showdown circuit.
pub fn showdown_card_plaintext(card_id: u8) -> Result<AleoGroup, String> {
    if !(1..=ALEO_NATIVE_DECK_SIZE as u8).contains(&card_id) {
        return Err("Aleo showdown card id must be in one-based 1..=52".into());
    }
    let scalar = NativeScalar::from_field_lossy(&NativeField::from_u64(u64::from(card_id)));
    Ok(AleoGroup(NativeGroup::generator() * scalar))
}

/// Build the version-2 seed deck under the complete hand participant key.
///
/// For deterministic nonzero `r_i`, each card is `(G*r_i,
/// G*card_id + aggregate_public_key*r_i)`. Every subsequent shuffle must
/// rerandomize under the same aggregate key. If every participant supplies
/// `secret_i * c1`, subtracting their token sum from `c2` yields exactly the
/// canonical card plaintext. This is the algebraic link absent from v1.
pub fn initial_native_showdown_deck(
    table_id: u64,
    hand_id: u32,
    aggregate_public_key: AleoGroup,
) -> Result<Vec<AleoCiphertext>, String> {
    if aggregate_public_key.0.is_zero() {
        return Err("Aleo showdown aggregate public key is identity".into());
    }
    (1..=ALEO_NATIVE_DECK_SIZE as u8)
        .map(|card_id| {
            let mut seed = Vec::with_capacity(SHOWDOWN_INITIAL_DECK_DOMAIN.len() + 8 + 4 + 1);
            seed.extend_from_slice(SHOWDOWN_INITIAL_DECK_DOMAIN.as_bytes());
            seed.extend_from_slice(&table_id.to_le_bytes());
            seed.extend_from_slice(&hand_id.to_le_bytes());
            seed.push(card_id);
            let randomness = derive_secret(&seed);
            let plaintext = showdown_card_plaintext(card_id)?;
            Ok(AleoCiphertext {
                c1: AleoGroup(NativeGroup::generator() * randomness),
                c2: AleoGroup(plaintext.0 + aggregate_public_key.0 * randomness),
            })
        })
        .collect()
}

/// Native witness-construction oracle for the v2 decryption equation.
///
/// The terminal/transition R1CS must enforce the same group equation and may
/// not trust this host lookup as proof. Returning a card id here is useful for
/// rejecting malformed journal material before circuit synthesis.
pub fn recover_showdown_card_id(
    ciphertext: AleoCiphertext,
    reveal_tokens: &[AleoGroup],
) -> Result<u8, String> {
    if !ciphertext.valid() || reveal_tokens.is_empty() {
        return Err("Aleo showdown recovery requires a valid card and reveal tokens".into());
    }
    if reveal_tokens.iter().any(|token| token.0.is_zero()) {
        return Err("Aleo showdown reveal token is identity".into());
    }
    let token_sum = reveal_tokens
        .iter()
        .fold(NativeGroup::zero(), |sum, token| sum + token.0);
    let plaintext = ciphertext.c2.0 - token_sum;
    (1..=ALEO_NATIVE_DECK_SIZE as u8)
        .find(|card_id| {
            showdown_card_plaintext(*card_id).is_ok_and(|candidate| candidate.0 == plaintext)
        })
        .ok_or_else(|| "Aleo showdown plaintext is not a canonical card id".into())
}

/// A native Schnorr ownership proof used for joins and shuffle submissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AleoSchnorrProof {
    pub commitment: AleoGroup,
    pub response: AleoScalar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AleoSchnorrBundle {
    pub context: AleoProtocolContext,
    pub public_key: AleoGroup,
    pub proof: AleoSchnorrProof,
}

impl AleoSchnorrBundle {
    pub fn prove(
        context: AleoProtocolContext,
        secret: NativeScalar,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, String> {
        if secret.is_zero() {
            return Err("Aleo Schnorr secret must be nonzero".into());
        }
        let public_key = NativeGroup::generator() * secret;
        let blinding = sample_nonzero_scalar(rng);
        let commitment = NativeGroup::generator() * blinding;
        let challenge = challenge(SCHNORR_DOMAIN, context, &[], &[public_key, commitment], &[])?;
        Ok(Self {
            context,
            public_key: AleoGroup(public_key),
            proof: AleoSchnorrProof {
                commitment: AleoGroup(commitment),
                response: AleoScalar(blinding + challenge * secret),
            },
        })
    }

    pub fn verify(&self) -> bool {
        if self.public_key.0.is_zero() || self.proof.commitment.0.is_zero() {
            return false;
        }
        let Ok(challenge) = challenge(
            SCHNORR_DOMAIN,
            self.context,
            &[],
            &[self.public_key.0, self.proof.commitment.0],
            &[],
        ) else {
            return false;
        };
        NativeGroup::generator() * self.proof.response.0
            == self.proof.commitment.0 + self.public_key.0 * challenge
    }
}

/// Aleo-native equality-of-discrete-log proof for a reveal token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AleoChaumPedersenProof {
    pub commitment_1: AleoGroup,
    pub commitment_2: AleoGroup,
    pub response: AleoScalar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AleoRevealBundle {
    pub context: AleoProtocolContext,
    pub player_public_key: AleoGroup,
    pub encrypted_card: AleoCiphertext,
    pub reveal_token: AleoGroup,
    pub proof: AleoChaumPedersenProof,
}

impl AleoRevealBundle {
    pub fn prove(
        context: AleoProtocolContext,
        secret: NativeScalar,
        encrypted_card: AleoCiphertext,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, String> {
        if secret.is_zero() || !encrypted_card.valid() {
            return Err("invalid Aleo reveal witness".into());
        }
        let player_public_key = NativeGroup::generator() * secret;
        let reveal_token = encrypted_card.c1.0 * secret;
        let blinding = sample_nonzero_scalar(rng);
        let commitment_1 = NativeGroup::generator() * blinding;
        let commitment_2 = encrypted_card.c1.0 * blinding;
        let challenge = challenge(
            CHAUM_PEDERSEN_DOMAIN,
            context,
            &[],
            &[
                NativeGroup::generator(),
                encrypted_card.c1.0,
                player_public_key,
                reveal_token,
                commitment_1,
                commitment_2,
            ],
            &[],
        )?;
        Ok(Self {
            context,
            player_public_key: AleoGroup(player_public_key),
            encrypted_card,
            reveal_token: AleoGroup(reveal_token),
            proof: AleoChaumPedersenProof {
                commitment_1: AleoGroup(commitment_1),
                commitment_2: AleoGroup(commitment_2),
                response: AleoScalar(blinding + challenge * secret),
            },
        })
    }

    pub fn verify(&self) -> bool {
        let points = [
            self.player_public_key.0,
            self.encrypted_card.c1.0,
            self.encrypted_card.c2.0,
            self.reveal_token.0,
            self.proof.commitment_1.0,
            self.proof.commitment_2.0,
        ];
        if points.iter().any(Zero::is_zero) {
            return false;
        }
        let Ok(challenge) = challenge(
            CHAUM_PEDERSEN_DOMAIN,
            self.context,
            &[],
            &[
                NativeGroup::generator(),
                self.encrypted_card.c1.0,
                self.player_public_key.0,
                self.reveal_token.0,
                self.proof.commitment_1.0,
                self.proof.commitment_2.0,
            ],
            &[],
        ) else {
            return false;
        };
        NativeGroup::generator() * self.proof.response.0
            == self.proof.commitment_1.0 + self.player_public_key.0 * challenge
            && self.encrypted_card.c1.0 * self.proof.response.0
                == self.proof.commitment_2.0 + self.reveal_token.0 * challenge
    }
}

pub const ALEO_SHOWDOWN_MAX_REVEAL_ASSIGNMENTS: usize = 18;

/// One assignment proof in a canonical v2 reveal submission batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AleoShowdownRevealItem {
    pub assignment_index: u8,
    pub reveal: AleoRevealBundle,
}

/// A Texas reveal action supplies one token for every assignment pending on
/// the submitting seat. This bundle mirrors that action with a fixed protocol
/// capacity of 18 rather than accepting a single proof attachment.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AleoShowdownRevealBatchBundle {
    pub context: AleoProtocolContext,
    pub player_public_key: AleoGroup,
    pub items: Vec<AleoShowdownRevealItem>,
}

impl AleoShowdownRevealBatchBundle {
    pub fn prove(
        context: AleoProtocolContext,
        secret: NativeScalar,
        assignments: &[(u8, AleoCiphertext)],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, String> {
        if assignments.is_empty() || assignments.len() > ALEO_SHOWDOWN_MAX_REVEAL_ASSIGNMENTS {
            return Err("Aleo showdown reveal batch length is outside 1..=18".into());
        }
        if assignments.iter().any(|(assignment_index, _)| {
            usize::from(*assignment_index) >= ALEO_SHOWDOWN_MAX_REVEAL_ASSIGNMENTS
        }) {
            return Err("Aleo showdown reveal assignment index is outside 0..18".into());
        }
        if assignments.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(
                "Aleo showdown reveal assignment indices must be strictly increasing".into(),
            );
        }
        let player_public_key = AleoGroup(NativeGroup::generator() * secret);
        let items = assignments
            .iter()
            .map(|&(assignment_index, ciphertext)| {
                AleoRevealBundle::prove(context, secret, ciphertext, rng).map(|reveal| {
                    AleoShowdownRevealItem {
                        assignment_index,
                        reveal,
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            context,
            player_public_key,
            items,
        })
    }

    pub fn verify(&self) -> bool {
        !self.player_public_key.0.is_zero()
            && !self.items.is_empty()
            && self.items.len() <= ALEO_SHOWDOWN_MAX_REVEAL_ASSIGNMENTS
            && self.items.iter().all(|item| {
                usize::from(item.assignment_index) < ALEO_SHOWDOWN_MAX_REVEAL_ASSIGNMENTS
            })
            && self
                .items
                .windows(2)
                .all(|pair| pair[0].assignment_index < pair[1].assignment_index)
            && self.items.iter().all(|item| {
                item.reveal.context == self.context
                    && item.reveal.player_public_key == self.player_public_key
                    && item.reveal.verify()
            })
    }
}

/// Same-secret DLEQ proof covering an entire 52-card reconstruction.
///
/// Relation zero anchors the player key (`G * secret = player_public_key`).
/// Relations one through 52 prove that the same player secret generated each
/// reconstruction token from the corresponding encrypted card's first
/// ElGamal component. This exact 53-relation layout matches
/// `aleo_varuna_adapter::native::SharedDleqStatement`.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AleoSharedDleqProof {
    pub commitments: Vec<AleoGroup>,
    pub response: AleoScalar,
    /// Transcript entropy that prevents reusing an otherwise identical DLEQ
    /// proof across actions with an accidentally equal context.
    pub nonce: AleoScalar,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AleoReconstructBundle {
    pub context: AleoProtocolContext,
    /// Entry zero is the generator. Entries one through 52 are the encrypted
    /// cards' `c1` components in the canonical reconstruction order.
    pub bases: Vec<AleoGroup>,
    /// Entry zero is the registered player key. Remaining entries are the
    /// deck reconstruction tokens supplied for the matching bases.
    pub targets: Vec<AleoGroup>,
    pub proof: AleoSharedDleqProof,
}

impl AleoReconstructBundle {
    pub fn prove(
        context: AleoProtocolContext,
        secret: NativeScalar,
        encrypted_cards: &[AleoCiphertext],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, String> {
        if secret.is_zero()
            || encrypted_cards.len() != ALEO_NATIVE_DECK_SIZE
            || encrypted_cards.iter().any(|card| !card.valid())
        {
            return Err(
                "Aleo reconstruction requires a nonzero secret and 52 valid ciphertexts".into(),
            );
        }
        let mut bases = Vec::with_capacity(ALEO_NATIVE_DLEQ_RELATION_COUNT);
        bases.push(AleoGroup(NativeGroup::generator()));
        bases.extend(encrypted_cards.iter().map(|card| card.c1));
        let targets = bases
            .iter()
            .map(|base| AleoGroup(base.0 * secret))
            .collect::<Vec<_>>();
        let blinding = sample_nonzero_scalar(rng);
        let commitments = bases
            .iter()
            .map(|base| AleoGroup(base.0 * blinding))
            .collect::<Vec<_>>();
        let nonce = sample_nonzero_scalar(rng);
        let statement = Self {
            context,
            bases,
            targets,
            proof: AleoSharedDleqProof {
                commitments,
                response: AleoScalar(NativeScalar::zero()),
                nonce: AleoScalar(nonce),
            },
        };
        let challenge = statement.challenge()?;
        Ok(Self {
            proof: AleoSharedDleqProof {
                response: AleoScalar(blinding + challenge * secret),
                ..statement.proof
            },
            ..statement
        })
    }

    fn challenge(&self) -> Result<NativeScalar, String> {
        if self.bases.len() != ALEO_NATIVE_DLEQ_RELATION_COUNT
            || self.targets.len() != ALEO_NATIVE_DLEQ_RELATION_COUNT
            || self.proof.commitments.len() != ALEO_NATIVE_DLEQ_RELATION_COUNT
        {
            return Err("Aleo shared DLEQ relation count is not canonical".into());
        }
        let mut points = Vec::with_capacity(ALEO_NATIVE_DLEQ_RELATION_COUNT * 3);
        for index in 0..ALEO_NATIVE_DLEQ_RELATION_COUNT {
            points.push(self.bases[index].0);
            points.push(self.targets[index].0);
            points.push(self.proof.commitments[index].0);
        }
        challenge(
            SHARED_DLEQ_DOMAIN,
            self.context,
            &[NativeField::from_u8(ALEO_NATIVE_DLEQ_RELATION_COUNT as u8)],
            &points,
            &[self.proof.nonce.0],
        )
    }

    pub fn verify(&self) -> bool {
        if self.bases.len() != ALEO_NATIVE_DLEQ_RELATION_COUNT
            || self.targets.len() != ALEO_NATIVE_DLEQ_RELATION_COUNT
            || self.proof.commitments.len() != ALEO_NATIVE_DLEQ_RELATION_COUNT
            || self.proof.nonce.0.is_zero()
            || self.bases[0].0 != NativeGroup::generator()
            || self
                .bases
                .iter()
                .chain(&self.targets)
                .chain(&self.proof.commitments)
                .any(|point| point.0.is_zero())
        {
            return false;
        }
        let Ok(challenge) = self.challenge() else {
            return false;
        };
        (0..ALEO_NATIVE_DLEQ_RELATION_COUNT).all(|index| {
            self.bases[index].0 * self.proof.response.0
                == self.proof.commitments[index].0 + self.targets[index].0 * challenge
        })
    }
}

/// Direct 52-card shuffle witness. The resulting permutation and
/// rerandomizers are private inputs to the outer Varuna proof; this bundle is
/// verified before witness construction and must be kept off public Socket.IO
/// broadcasts.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AleoShuffleBundle {
    pub context: AleoProtocolContext,
    /// The currently registered shuffler key. The native circuit binds this to
    /// the seat key commitment before it accepts the shuffle relation.
    pub player_public_key: AleoGroup,
    pub input: Vec<AleoCiphertext>,
    pub output: Vec<AleoCiphertext>,
    /// `permutation[output_index]` identifies the input ciphertext.
    pub permutation: Vec<u8>,
    pub rerandomizers: Vec<AleoScalar>,
}

impl AleoShuffleBundle {
    pub fn prove(
        context: AleoProtocolContext,
        player_public_key: AleoGroup,
        input: &[AleoCiphertext],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, String> {
        if input.len() != ALEO_NATIVE_DECK_SIZE || input.iter().any(|card| !card.valid()) {
            return Err("Aleo shuffle requires exactly 52 valid ciphertexts".into());
        }
        if player_public_key.0.is_zero() {
            return Err("Aleo shuffle public key is identity".into());
        }
        let mut permutation = (0..ALEO_NATIVE_DECK_SIZE as u8).collect::<Vec<_>>();
        permutation.shuffle(rng);
        let rerandomizers = (0..ALEO_NATIVE_DECK_SIZE)
            .map(|_| AleoScalar(sample_nonzero_scalar(rng)))
            .collect::<Vec<_>>();
        let output = permutation
            .iter()
            .zip(&rerandomizers)
            .map(|(&index, &rerandomizer)| {
                input[usize::from(index)].reencrypt(player_public_key, rerandomizer)
            })
            .collect();
        Ok(Self {
            context,
            player_public_key,
            input: input.to_vec(),
            output,
            permutation,
            rerandomizers,
        })
    }

    pub fn verify(&self) -> bool {
        if self.input.len() != ALEO_NATIVE_DECK_SIZE
            || self.output.len() != ALEO_NATIVE_DECK_SIZE
            || self.permutation.len() != ALEO_NATIVE_DECK_SIZE
            || self.rerandomizers.len() != ALEO_NATIVE_DECK_SIZE
            || self.player_public_key.0.is_zero()
            || self
                .input
                .iter()
                .chain(&self.output)
                .any(|card| !card.valid())
            || self.rerandomizers.iter().any(|scalar| scalar.0.is_zero())
        {
            return false;
        }
        let mut seen = [false; ALEO_NATIVE_DECK_SIZE];
        self.output
            .iter()
            .enumerate()
            .all(|(output_index, output)| {
                let input_index = usize::from(self.permutation[output_index]);
                if input_index >= ALEO_NATIVE_DECK_SIZE || seen[input_index] {
                    return false;
                }
                seen[input_index] = true;
                *output
                    == self.input[input_index]
                        .reencrypt(self.player_public_key, self.rerandomizers[output_index])
            })
    }
}

/// Version-2 shuffle witness for a deck encrypted under the sum of every
/// participating player's public key.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AleoShowdownShuffleBundle {
    pub context: AleoProtocolContext,
    /// Registered key of the player authorized to submit this action.
    pub shuffler_public_key: AleoGroup,
    /// Hand-wide key used by the v2 seed deck and every rerandomization.
    pub aggregate_public_key: AleoGroup,
    pub input: Vec<AleoCiphertext>,
    pub output: Vec<AleoCiphertext>,
    pub permutation: Vec<u8>,
    pub rerandomizers: Vec<AleoScalar>,
}

impl AleoShowdownShuffleBundle {
    pub fn prove(
        context: AleoProtocolContext,
        shuffler_public_key: AleoGroup,
        aggregate_public_key: AleoGroup,
        input: &[AleoCiphertext],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, String> {
        if input.len() != ALEO_NATIVE_DECK_SIZE || input.iter().any(|card| !card.valid()) {
            return Err("Aleo showdown shuffle requires exactly 52 valid ciphertexts".into());
        }
        if shuffler_public_key.0.is_zero() || aggregate_public_key.0.is_zero() {
            return Err("Aleo showdown shuffle key is identity".into());
        }
        let mut permutation = (0..ALEO_NATIVE_DECK_SIZE as u8).collect::<Vec<_>>();
        permutation.shuffle(rng);
        let rerandomizers = (0..ALEO_NATIVE_DECK_SIZE)
            .map(|_| AleoScalar(sample_nonzero_scalar(rng)))
            .collect::<Vec<_>>();
        let output = permutation
            .iter()
            .zip(&rerandomizers)
            .map(|(&index, &rerandomizer)| {
                input[usize::from(index)].reencrypt(aggregate_public_key, rerandomizer)
            })
            .collect();
        Ok(Self {
            context,
            shuffler_public_key,
            aggregate_public_key,
            input: input.to_vec(),
            output,
            permutation,
            rerandomizers,
        })
    }

    pub fn verify(&self) -> bool {
        if self.input.len() != ALEO_NATIVE_DECK_SIZE
            || self.output.len() != ALEO_NATIVE_DECK_SIZE
            || self.permutation.len() != ALEO_NATIVE_DECK_SIZE
            || self.rerandomizers.len() != ALEO_NATIVE_DECK_SIZE
            || self.shuffler_public_key.0.is_zero()
            || self.aggregate_public_key.0.is_zero()
            || self
                .input
                .iter()
                .chain(&self.output)
                .any(|card| !card.valid())
            || self.rerandomizers.iter().any(|scalar| scalar.0.is_zero())
        {
            return false;
        }
        let mut seen = [false; ALEO_NATIVE_DECK_SIZE];
        self.output
            .iter()
            .enumerate()
            .all(|(output_index, output)| {
                let input_index = usize::from(self.permutation[output_index]);
                if input_index >= ALEO_NATIVE_DECK_SIZE || seen[input_index] {
                    return false;
                }
                seen[input_index] = true;
                *output
                    == self.input[input_index]
                        .reencrypt(self.aggregate_public_key, self.rerandomizers[output_index])
            })
    }
}

/// A direct BLS12-377 player used by the WASM façade and Rust-side vectors.
#[derive(Debug, Clone)]
pub struct AleoProtocolPlayer {
    secret: NativeScalar,
    public_key: NativeGroup,
}

impl AleoProtocolPlayer {
    pub fn from_seed(seed: &[u8]) -> Self {
        let secret = derive_secret(seed);
        Self {
            secret,
            public_key: NativeGroup::generator() * secret,
        }
    }

    pub fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let secret = sample_nonzero_scalar(rng);
        Self {
            secret,
            public_key: NativeGroup::generator() * secret,
        }
    }

    pub fn public_key(&self) -> AleoGroup {
        AleoGroup(self.public_key)
    }

    pub fn secret(&self) -> AleoScalar {
        AleoScalar(self.secret)
    }

    pub fn ownership_proof(
        &self,
        context: AleoProtocolContext,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<AleoSchnorrBundle, String> {
        AleoSchnorrBundle::prove(context, self.secret, rng)
    }

    pub fn reveal(
        &self,
        context: AleoProtocolContext,
        encrypted_card: AleoCiphertext,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<AleoRevealBundle, String> {
        AleoRevealBundle::prove(context, self.secret, encrypted_card, rng)
    }

    pub fn reveal_showdown_batch(
        &self,
        context: AleoProtocolContext,
        assignments: &[(u8, AleoCiphertext)],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<AleoShowdownRevealBatchBundle, String> {
        AleoShowdownRevealBatchBundle::prove(context, self.secret, assignments, rng)
    }

    pub fn shuffle(
        &self,
        context: AleoProtocolContext,
        input: &[AleoCiphertext],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<AleoShuffleBundle, String> {
        AleoShuffleBundle::prove(context, self.public_key(), input, rng)
    }

    pub fn shuffle_showdown(
        &self,
        context: AleoProtocolContext,
        aggregate_public_key: AleoGroup,
        input: &[AleoCiphertext],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<AleoShowdownShuffleBundle, String> {
        AleoShowdownShuffleBundle::prove(
            context,
            self.public_key(),
            aggregate_public_key,
            input,
            rng,
        )
    }

    pub fn reconstruct(
        &self,
        context: AleoProtocolContext,
        encrypted_cards: &[AleoCiphertext],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<AleoReconstructBundle, String> {
        AleoReconstructBundle::prove(context, self.secret, encrypted_cards, rng)
    }
}

/// Tagged browser/prover attachment. The proving service must decode this
/// before the action becomes eligible for a real native settlement.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum AleoProtocolProofBundle {
    Schnorr(AleoSchnorrBundle),
    Reveal(AleoRevealBundle),
    Shuffle(AleoShuffleBundle),
    Reconstruct(AleoReconstructBundle),
    /// Aggregate-key shuffle used only by the v5 showdown protocol.
    ShowdownShuffle(AleoShowdownShuffleBundle),
    /// Fixed-capacity batch matching one v5 Texas reveal submission action.
    ShowdownRevealBatch(AleoShowdownRevealBatchBundle),
}

impl AleoProtocolProofBundle {
    pub fn context(&self) -> AleoProtocolContext {
        match self {
            Self::Schnorr(bundle) => bundle.context,
            Self::Reveal(bundle) => bundle.context,
            Self::Shuffle(bundle) => bundle.context,
            Self::Reconstruct(bundle) => bundle.context,
            Self::ShowdownShuffle(bundle) => bundle.context,
            Self::ShowdownRevealBatch(bundle) => bundle.context,
        }
    }

    pub fn verify(&self) -> bool {
        match self {
            Self::Schnorr(bundle) => bundle.verify(),
            Self::Reveal(bundle) => bundle.verify(),
            Self::Shuffle(bundle) => bundle.verify(),
            Self::Reconstruct(bundle) => bundle.verify(),
            Self::ShowdownShuffle(bundle) => bundle.verify(),
            Self::ShowdownRevealBatch(bundle) => bundle.verify(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn context(action_index: u16) -> AleoProtocolContext {
        AleoProtocolContext {
            circuit_id: AleoField(NativeField::new_domain_separator("test.circuit")),
            table_id: AleoField(NativeField::from_u64(7)),
            hand_id: 3,
            action_index,
            command_digest: AleoField(NativeField::new_domain_separator("test.command")),
        }
    }

    fn deck(player: &AleoProtocolPlayer, rng: &mut OsRng) -> Vec<AleoCiphertext> {
        (0..ALEO_NATIVE_DECK_SIZE)
            .map(|card| {
                let scalar =
                    NativeScalar::from_field_lossy(&NativeField::from_u64(card as u64 + 1));
                let plaintext = AleoGroup(NativeGroup::generator() * scalar);
                AleoCiphertext::encrypt(
                    plaintext,
                    player.public_key(),
                    AleoScalar(sample_nonzero_scalar(rng)),
                )
            })
            .collect()
    }

    #[test]
    fn native_schnorr_bundle_roundtrips_and_rejects_context_tampering() {
        let mut rng = OsRng;
        let player = AleoProtocolPlayer::random(&mut rng);
        let bundle =
            AleoProtocolProofBundle::Schnorr(player.ownership_proof(context(2), &mut rng).unwrap());
        let bytes = borsh::to_vec(&bundle).unwrap();
        let decoded = AleoProtocolProofBundle::try_from_slice(&bytes).unwrap();
        assert!(decoded.verify());
        let AleoProtocolProofBundle::Schnorr(mut altered) = decoded else {
            unreachable!()
        };
        altered.context.action_index += 1;
        assert!(!altered.verify());
    }

    #[test]
    fn native_reveal_and_shuffle_are_native_group_relations() {
        let mut rng = OsRng;
        let player = AleoProtocolPlayer::random(&mut rng);
        let input = deck(&player, &mut rng);
        let reveal = player.reveal(context(4), input[0], &mut rng).unwrap();
        assert!(reveal.verify());
        let shuffle = player.shuffle(context(5), &input, &mut rng).unwrap();
        assert!(shuffle.verify());
        let reconstruct = player.reconstruct(context(6), &input, &mut rng).unwrap();
        assert!(reconstruct.verify());

        let mut changed = shuffle.clone();
        changed.output.swap(0, 1);
        assert!(!changed.verify());
        let mut changed_reconstruct = reconstruct.clone();
        changed_reconstruct.targets[1] = changed_reconstruct.targets[2];
        assert!(!changed_reconstruct.verify());
    }

    #[test]
    fn showdown_v2_seed_decrypts_to_card_ids_after_rerandomization() {
        let mut rng = OsRng;
        let players = std::array::from_fn::<_, 3, _>(|_| AleoProtocolPlayer::random(&mut rng));
        let aggregate_public_key = AleoGroup(
            players
                .iter()
                .fold(NativeGroup::zero(), |sum, player| sum + player.public_key),
        );
        let mut deck = initial_native_showdown_deck(9, 17, aggregate_public_key).unwrap();

        for (index, card) in deck.iter_mut().enumerate() {
            let rerandomizer = sample_nonzero_scalar(&mut rng);
            *card = card.reencrypt(aggregate_public_key, AleoScalar(rerandomizer));
            let tokens = players
                .iter()
                .map(|player| AleoGroup(card.c1.0 * player.secret))
                .collect::<Vec<_>>();
            assert_eq!(
                recover_showdown_card_id(*card, &tokens).unwrap(),
                index as u8 + 1
            );
        }
    }

    #[test]
    fn showdown_v2_rejects_missing_participant_token() {
        let mut rng = OsRng;
        let first = AleoProtocolPlayer::random(&mut rng);
        let second = AleoProtocolPlayer::random(&mut rng);
        let aggregate_public_key = AleoGroup(first.public_key + second.public_key);
        let deck = initial_native_showdown_deck(9, 18, aggregate_public_key).unwrap();
        let incomplete = [AleoGroup(deck[0].c1.0 * first.secret)];
        assert!(recover_showdown_card_id(deck[0], &incomplete).is_err());
    }

    #[test]
    fn showdown_v2_shuffle_preserves_decryptable_permutation() {
        let mut rng = OsRng;
        let players = std::array::from_fn::<_, 3, _>(|_| AleoProtocolPlayer::random(&mut rng));
        let aggregate_public_key = AleoGroup(
            players
                .iter()
                .fold(NativeGroup::zero(), |sum, player| sum + player.public_key),
        );
        let deck = initial_native_showdown_deck(10, 21, aggregate_public_key).unwrap();
        let shuffle = players[0]
            .shuffle_showdown(context(7), aggregate_public_key, &deck, &mut rng)
            .unwrap();
        assert!(shuffle.verify());
        for (output_index, card) in shuffle.output.iter().enumerate() {
            let tokens = players
                .iter()
                .map(|player| AleoGroup(card.c1.0 * player.secret))
                .collect::<Vec<_>>();
            assert_eq!(
                recover_showdown_card_id(*card, &tokens).unwrap(),
                shuffle.permutation[output_index] + 1
            );
        }

        let bytes = borsh::to_vec(&AleoProtocolProofBundle::ShowdownShuffle(shuffle)).unwrap();
        let decoded = AleoProtocolProofBundle::try_from_slice(&bytes).unwrap();
        assert!(decoded.verify());
    }

    #[test]
    fn showdown_v2_reveal_batch_roundtrips_and_rejects_noncanonical_indices() {
        let mut rng = OsRng;
        let first = AleoProtocolPlayer::random(&mut rng);
        let second = AleoProtocolPlayer::random(&mut rng);
        let aggregate_public_key = AleoGroup(first.public_key + second.public_key);
        let deck = initial_native_showdown_deck(11, 22, aggregate_public_key).unwrap();
        let assignments = [(0, deck[3]), (7, deck[19]), (17, deck[51])];
        let bundle = first
            .reveal_showdown_batch(context(8), &assignments, &mut rng)
            .unwrap();
        assert!(bundle.verify());

        let bytes = borsh::to_vec(&AleoProtocolProofBundle::ShowdownRevealBatch(
            bundle.clone(),
        ))
        .unwrap();
        let decoded = AleoProtocolProofBundle::try_from_slice(&bytes).unwrap();
        assert!(decoded.verify());

        let mut out_of_range = bundle.clone();
        out_of_range.items[2].assignment_index = 18;
        assert!(!out_of_range.verify());
        let mut duplicate = bundle;
        duplicate.items[1].assignment_index = duplicate.items[0].assignment_index;
        assert!(!duplicate.verify());
    }
}
