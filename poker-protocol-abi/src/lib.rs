//! Stable byte ABI for poker proof precompiles.
//!
//! The proof transcript context and the call replay scope are deliberately
//! separate. Existing proofs use a fixed transcript label, while `call_context`
//! binds the same proof request to one table/hand/call/seat/state transition.

const SHUFFLE_REQUEST_MAGIC: [u8; 4] = *b"ZKSH";
const RECONSTRUCTION_REQUEST_MAGIC: [u8; 4] = *b"ZKRC";
const RECONSTRUCTION_V3_REQUEST_MAGIC: [u8; 4] = *b"ZKR3";
pub const SHUFFLE_ABI_VERSION: u8 = 2;
pub const RECONSTRUCTION_ABI_VERSION: u8 = 1;
pub const RECONSTRUCTION_V3_ABI_VERSION: u8 = 1;
pub const RECONSTRUCTION_V3_STATEMENT_VERSION: u8 = 3;
pub const MAX_DECK_SIZE: usize = 1024;
pub const MAX_CONTEXT_SIZE: usize = 4096;
pub const MAX_PROOF_SIZE: usize = 1 << 20;
/// Maximum transport size of one V2 package part.  Relation archives contain
/// STARK commitments and can legitimately exceed the legacy 1 MiB proof cap;
/// the cap is still finite to avoid unbounded allocation during decoding.
pub const MAX_RISTRETTO_AIR_V2_PACKAGE_PART_SIZE: usize = 2 * 1024 * 1024 * 1024;
/// Fixed Texas deck cardinality for the Ristretto/AIR protocol epoch.
///
/// Legacy BLS requests remain variable-size because their verifier ABI is
/// shared with non-Texas callers.  The Ristretto route is a distinct protocol:
/// an AIR proof always authenticates the complete ordered 52-card deck.
pub const RISTRETTO_AIR_DECK_SIZE: usize = 52;
/// Number of owner-readable hole cards in one Texas reconstruction request.
pub const RISTRETTO_AIR_RECONSTRUCTION_READABLE_CARDS: usize = 2;
const RISTRETTO_AIR_V2_PACKAGE_MAGIC: [u8; 4] = *b"ZR4A";
const RISTRETTO_AIR_V2_PACKAGE_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CurveId {
    Bls12381G1 = 1,
    Bls12377G1 = 2,
    /// Prime-order Ristretto quotient group over Curve25519.
    ///
    /// This identifier is reserved for the versioned AIR-backed protocol. It
    /// deliberately has a distinct 32-byte point encoding and must never be
    /// decoded as a legacy BLS request.
    Ristretto255 = 3,
}

impl CurveId {
    pub fn point_size(self) -> usize {
        match self {
            Self::Bls12381G1 | Self::Bls12377G1 => 48,
            Self::Ristretto255 => 32,
        }
    }
}

impl TryFrom<u8> for CurveId {
    type Error = AbiError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Bls12381G1),
            2 => Ok(Self::Bls12377G1),
            3 => Ok(Self::Ristretto255),
            _ => Err(AbiError::UnsupportedCurve(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TranscriptId {
    Merlin = 1,
    FiatShamirSha3 = 2,
    /// Poseidon252 transcript reserved for the Ristretto AIR protocol.
    Poseidon252 = 3,
    /// Flock BLAKE3 transcript used by the trustless Ristretto AIR v2 route.
    FlockBlake3 = 4,
}

impl TryFrom<u8> for TranscriptId {
    type Error = AbiError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Merlin),
            2 => Ok(Self::FiatShamirSha3),
            3 => Ok(Self::Poseidon252),
            4 => Ok(Self::FlockBlake3),
            _ => Err(AbiError::UnsupportedTranscript(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ShuffleProofSystem {
    BayerGrothV2 = 2,
    /// Ristretto255 AIR proof whose public statement is encoded by this ABI.
    RistrettoAirV1 = 3,
    /// Ristretto255 AIR v2: fixed 52-card batch verifier schedule.
    RistrettoAirV2 = 4,
}

impl TryFrom<u8> for ShuffleProofSystem {
    type Error = AbiError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(Self::BayerGrothV2),
            3 => Ok(Self::RistrettoAirV1),
            4 => Ok(Self::RistrettoAirV2),
            _ => Err(AbiError::UnsupportedProofSystem(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReconstructionProofSystem {
    BayerGrothOrderedV2 = 2,
    /// Bayer--Groth hidden permutation plus cross-key and per-slot OR proofs.
    BayerGrothSlotOrV3 = 3,
    /// Ristretto255 AIR proof for the corresponding reconstruction relation.
    RistrettoAirV1 = 4,
    /// Ristretto255 AIR v2: fixed-shape, parallel relation composition.
    RistrettoAirV2 = 5,
}

impl TryFrom<u8> for ReconstructionProofSystem {
    type Error = AbiError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(Self::BayerGrothOrderedV2),
            3 => Ok(Self::BayerGrothSlotOrV3),
            4 => Ok(Self::RistrettoAirV1),
            5 => Ok(Self::RistrettoAirV2),
            _ => Err(AbiError::UnsupportedProofSystem(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedCiphertext {
    pub c1: Vec<u8>,
    pub c2: Vec<u8>,
}

/// Single transport object for a Ristretto AIR V2 submission.
///
/// The request is the canonical `ZKR3` statement and `relation_archive` is
/// the server-verifiable AIR archive. Keeping both byte strings in one
/// versioned container prevents request/archive mixups at the network layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RistrettoAirV2SubmissionPackage {
    pub request: Vec<u8>,
    pub relation_archive: Vec<u8>,
}

/// Borrowed view of a `ZR4A` package.  Network handlers can validate the
/// header and hand the two slices to decoders without allocating or copying a
/// potentially multi-megabyte relation archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RistrettoAirV2SubmissionPackageRef<'a> {
    pub request: &'a [u8],
    pub relation_archive: &'a [u8],
}

impl RistrettoAirV2SubmissionPackage {
    pub fn from_parts(request: Vec<u8>, relation_archive: Vec<u8>) -> Self {
        Self {
            request,
            relation_archive,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, AbiError> {
        if self.request.len() > MAX_RISTRETTO_AIR_V2_PACKAGE_PART_SIZE
            || self.relation_archive.len() > MAX_RISTRETTO_AIR_V2_PACKAGE_PART_SIZE
        {
            return Err(AbiError::InvalidProofSize);
        }
        let request_len =
            u32::try_from(self.request.len()).map_err(|_| AbiError::InvalidProofSize)?;
        let archive_len =
            u32::try_from(self.relation_archive.len()).map_err(|_| AbiError::InvalidProofSize)?;
        let mut out =
            Vec::with_capacity(4 + 1 + 8 + self.request.len() + self.relation_archive.len());
        out.extend_from_slice(&RISTRETTO_AIR_V2_PACKAGE_MAGIC);
        out.push(RISTRETTO_AIR_V2_PACKAGE_VERSION);
        out.extend_from_slice(&request_len.to_le_bytes());
        out.extend_from_slice(&archive_len.to_le_bytes());
        out.extend_from_slice(&self.request);
        out.extend_from_slice(&self.relation_archive);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AbiError> {
        let view = Self::decode_ref(bytes)?;
        let package = Self {
            request: view.request.to_vec(),
            relation_archive: view.relation_archive.to_vec(),
        };
        if package.encode()? != bytes {
            return Err(AbiError::TrailingBytes);
        }
        Ok(package)
    }

    pub fn decode_ref(bytes: &[u8]) -> Result<RistrettoAirV2SubmissionPackageRef<'_>, AbiError> {
        if bytes.len() < 13 || bytes[..4] != RISTRETTO_AIR_V2_PACKAGE_MAGIC {
            return Err(AbiError::InvalidMagic);
        }
        if bytes[4] != RISTRETTO_AIR_V2_PACKAGE_VERSION {
            return Err(AbiError::UnsupportedVersion(bytes[4]));
        }
        let request_len = u32::from_le_bytes(bytes[5..9].try_into().unwrap()) as usize;
        let archive_len = u32::from_le_bytes(bytes[9..13].try_into().unwrap()) as usize;
        if request_len > MAX_RISTRETTO_AIR_V2_PACKAGE_PART_SIZE
            || archive_len > MAX_RISTRETTO_AIR_V2_PACKAGE_PART_SIZE
            || bytes.len() != 13 + request_len + archive_len
        {
            return Err(AbiError::InvalidProofSize);
        }
        Ok(RistrettoAirV2SubmissionPackageRef {
            request: &bytes[13..13 + request_len],
            relation_archive: &bytes[13 + request_len..],
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShuffleVerifyRequest {
    pub curve: CurveId,
    pub proof_system: ShuffleProofSystem,
    pub transcript: TranscriptId,
    /// Context passed to the cryptographic Fiat--Shamir transcript.
    pub context: Vec<u8>,
    /// Canonical replay scope (table/hand/call/seat/state/dispatch digest).
    pub call_context: Vec<u8>,
    pub public_key: Vec<u8>,
    pub input: Vec<EncodedCiphertext>,
    pub output: Vec<EncodedCiphertext>,
    pub proof: Vec<u8>,
}

impl ShuffleVerifyRequest {
    pub fn validate(&self) -> Result<(), AbiError> {
        let n = self.input.len();
        validate_common(self.curve, &self.context, &self.call_context, &self.proof)?;
        match (self.curve, self.proof_system, self.transcript) {
            (
                CurveId::Bls12381G1 | CurveId::Bls12377G1,
                ShuffleProofSystem::BayerGrothV2,
                TranscriptId::Merlin | TranscriptId::FiatShamirSha3,
            )
            | (
                CurveId::Ristretto255,
                ShuffleProofSystem::RistrettoAirV1,
                TranscriptId::Poseidon252,
            ) => {}
            (
                CurveId::Ristretto255,
                ShuffleProofSystem::RistrettoAirV2,
                TranscriptId::FlockBlake3,
            ) => {}
            (CurveId::Ristretto255, _, _) => {
                return Err(AbiError::UnsupportedProofSystem(self.proof_system as u8))
            }
            _ => return Err(AbiError::UnsupportedTranscript(self.transcript as u8)),
        }
        if n < 2 || n > MAX_DECK_SIZE || self.output.len() != n {
            return Err(AbiError::InvalidDeckSize);
        }
        if self.curve == CurveId::Ristretto255 && n != RISTRETTO_AIR_DECK_SIZE {
            return Err(AbiError::InvalidDeckSize);
        }
        let point_size = self.curve.point_size();
        if self.public_key.len() != point_size
            || !valid_ciphertexts(&self.input, point_size)
            || !valid_ciphertexts(&self.output, point_size)
        {
            return Err(AbiError::InvalidPointSize);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, AbiError> {
        self.validate()?;
        let n = u16_len(self.input.len(), AbiError::InvalidDeckSize)?;
        let context_len = u16_len(self.context.len(), AbiError::ContextTooLarge)?;
        let call_context_len = u16_len(self.call_context.len(), AbiError::ContextTooLarge)?;
        let proof_len = u32_len(self.proof.len())?;
        let mut out = Vec::new();
        out.extend_from_slice(&SHUFFLE_REQUEST_MAGIC);
        out.extend_from_slice(&[
            SHUFFLE_ABI_VERSION,
            self.curve as u8,
            self.proof_system as u8,
            self.transcript as u8,
            0,
        ]);
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&context_len.to_le_bytes());
        out.extend_from_slice(&call_context_len.to_le_bytes());
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&self.call_context);
        out.extend_from_slice(&self.public_key);
        encode_ciphertexts(&mut out, &self.input);
        encode_ciphertexts(&mut out, &self.output);
        out.extend_from_slice(&proof_len.to_le_bytes());
        out.extend_from_slice(&self.proof);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AbiError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(4)? != SHUFFLE_REQUEST_MAGIC {
            return Err(AbiError::InvalidMagic);
        }
        let version = decoder.u8()?;
        if version != SHUFFLE_ABI_VERSION {
            return Err(AbiError::UnsupportedVersion(version));
        }
        let curve = CurveId::try_from(decoder.u8()?)?;
        let proof_system = ShuffleProofSystem::try_from(decoder.u8()?)?;
        let transcript = TranscriptId::try_from(decoder.u8()?)?;
        require_zero_flags(decoder.u8()?)?;
        let n = decoder.u16()? as usize;
        if !(2..=MAX_DECK_SIZE).contains(&n) {
            return Err(AbiError::InvalidDeckSize);
        }
        let context_len = checked_context_len(decoder.u16()? as usize)?;
        let call_context_len = checked_context_len(decoder.u16()? as usize)?;
        let context = decoder.take(context_len)?.to_vec();
        let call_context = decoder.take(call_context_len)?.to_vec();
        let point_size = curve.point_size();
        let public_key = decoder.take(point_size)?.to_vec();
        let input = decode_ciphertexts(&mut decoder, n, point_size)?;
        let output = decode_ciphertexts(&mut decoder, n, point_size)?;
        let proof = decode_proof(&mut decoder)?;
        decoder.finish()?;
        let request = Self {
            curve,
            proof_system,
            transcript,
            context,
            call_context,
            public_key,
            input,
            output,
            proof,
        };
        request.validate()?;
        Ok(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconstructionVerifyRequest {
    pub curve: CurveId,
    pub proof_system: ReconstructionProofSystem,
    pub transcript: TranscriptId,
    pub context: Vec<u8>,
    pub call_context: Vec<u8>,
    pub cards: Vec<Vec<u8>>,
    pub output_cards: Vec<EncodedCiphertext>,
    pub swap_out_cards: Vec<EncodedCiphertext>,
    pub user_readable_cards: Vec<EncodedCiphertext>,
    pub user_public_key: Vec<u8>,
    pub proof: Vec<u8>,
}

impl ReconstructionVerifyRequest {
    pub fn validate(&self) -> Result<(), AbiError> {
        validate_common(self.curve, &self.context, &self.call_context, &self.proof)?;
        match (self.curve, self.proof_system, self.transcript) {
            (
                CurveId::Bls12381G1 | CurveId::Bls12377G1,
                ReconstructionProofSystem::BayerGrothOrderedV2,
                TranscriptId::Merlin | TranscriptId::FiatShamirSha3,
            ) => {}
            (CurveId::Ristretto255, _, _) => {
                return Err(AbiError::UnsupportedProofSystem(self.proof_system as u8))
            }
            _ => return Err(AbiError::UnsupportedTranscript(self.transcript as u8)),
        }
        let n = self.cards.len();
        let k = self.swap_out_cards.len();
        if n < 2
            || n > MAX_DECK_SIZE
            || self.output_cards.len() != n
            || k == 0
            || k > n
            || self.user_readable_cards.len() != k
        {
            return Err(AbiError::InvalidDeckSize);
        }
        let point_size = self.curve.point_size();
        if self.user_public_key.len() != point_size
            || self.cards.iter().any(|card| card.len() != point_size)
            || !valid_ciphertexts(&self.output_cards, point_size)
            || !valid_ciphertexts(&self.swap_out_cards, point_size)
            || !valid_ciphertexts(&self.user_readable_cards, point_size)
        {
            return Err(AbiError::InvalidPointSize);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, AbiError> {
        self.validate()?;
        let n = u16_len(self.cards.len(), AbiError::InvalidDeckSize)?;
        let k = u16_len(self.swap_out_cards.len(), AbiError::InvalidDeckSize)?;
        let context_len = u16_len(self.context.len(), AbiError::ContextTooLarge)?;
        let call_context_len = u16_len(self.call_context.len(), AbiError::ContextTooLarge)?;
        let proof_len = u32_len(self.proof.len())?;
        let mut out = Vec::new();
        out.extend_from_slice(&RECONSTRUCTION_REQUEST_MAGIC);
        out.extend_from_slice(&[
            RECONSTRUCTION_ABI_VERSION,
            self.curve as u8,
            self.proof_system as u8,
            self.transcript as u8,
            0,
        ]);
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&k.to_le_bytes());
        out.extend_from_slice(&context_len.to_le_bytes());
        out.extend_from_slice(&call_context_len.to_le_bytes());
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&self.call_context);
        out.extend_from_slice(&self.user_public_key);
        for card in &self.cards {
            out.extend_from_slice(card);
        }
        encode_ciphertexts(&mut out, &self.output_cards);
        encode_ciphertexts(&mut out, &self.swap_out_cards);
        encode_ciphertexts(&mut out, &self.user_readable_cards);
        out.extend_from_slice(&proof_len.to_le_bytes());
        out.extend_from_slice(&self.proof);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AbiError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(4)? != RECONSTRUCTION_REQUEST_MAGIC {
            return Err(AbiError::InvalidMagic);
        }
        let version = decoder.u8()?;
        if version != RECONSTRUCTION_ABI_VERSION {
            return Err(AbiError::UnsupportedVersion(version));
        }
        let curve = CurveId::try_from(decoder.u8()?)?;
        let proof_system = ReconstructionProofSystem::try_from(decoder.u8()?)?;
        let transcript = TranscriptId::try_from(decoder.u8()?)?;
        require_zero_flags(decoder.u8()?)?;
        let n = decoder.u16()? as usize;
        let k = decoder.u16()? as usize;
        if n < 2 || n > MAX_DECK_SIZE || k == 0 || k > n {
            return Err(AbiError::InvalidDeckSize);
        }
        let context_len = checked_context_len(decoder.u16()? as usize)?;
        let call_context_len = checked_context_len(decoder.u16()? as usize)?;
        let context = decoder.take(context_len)?.to_vec();
        let call_context = decoder.take(call_context_len)?.to_vec();
        let point_size = curve.point_size();
        let user_public_key = decoder.take(point_size)?.to_vec();
        let cards = (0..n)
            .map(|_| Ok(decoder.take(point_size)?.to_vec()))
            .collect::<Result<Vec<_>, AbiError>>()?;
        let output_cards = decode_ciphertexts(&mut decoder, n, point_size)?;
        let swap_out_cards = decode_ciphertexts(&mut decoder, k, point_size)?;
        let user_readable_cards = decode_ciphertexts(&mut decoder, k, point_size)?;
        let proof = decode_proof(&mut decoder)?;
        decoder.finish()?;
        let request = Self {
            curve,
            proof_system,
            transcript,
            context,
            call_context,
            cards,
            output_cards,
            swap_out_cards,
            user_readable_cards,
            user_public_key,
            proof,
        };
        request.validate()?;
        Ok(request)
    }
}

/// Stable precompile request for reconstruction V3.
///
/// V3 deliberately has its own magic and shape instead of extending the V2
/// request. This lets old decoders fail closed and makes the statement visible
/// to the AIR without exposing the hidden readable-to-slot permutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconstructionV3VerifyRequest {
    pub curve: CurveId,
    pub proof_system: ReconstructionProofSystem,
    pub transcript: TranscriptId,
    /// Domain label used to initialize the proof transcript.
    pub context: Vec<u8>,
    /// Host replay scope, e.g. table/hand/call/seat/state-transition.
    pub call_context: Vec<u8>,
    pub statement_version: u8,
    pub context_digest: [u8; 32],
    pub reconstruction_epoch: u64,
    pub prior_state_digest: [u8; 32],
    pub aggregate_pk: Vec<u8>,
    pub owner_pk: Vec<u8>,
    pub cards: Vec<Vec<u8>>,
    pub user_readable_cards: Vec<EncodedCiphertext>,
    /// Canonical slots; each plaintext is proved to be zero or `-cards[i]`.
    pub contributions: Vec<EncodedCiphertext>,
    pub proof: Vec<u8>,
}

impl ReconstructionV3VerifyRequest {
    pub fn validate(&self) -> Result<(), AbiError> {
        validate_common(self.curve, &self.context, &self.call_context, &self.proof)?;
        match (self.curve, self.proof_system, self.transcript) {
            (
                CurveId::Bls12381G1 | CurveId::Bls12377G1,
                ReconstructionProofSystem::BayerGrothSlotOrV3,
                TranscriptId::Merlin | TranscriptId::FiatShamirSha3,
            )
            | (
                CurveId::Ristretto255,
                ReconstructionProofSystem::RistrettoAirV1,
                TranscriptId::Poseidon252,
            )
            | (
                CurveId::Ristretto255,
                ReconstructionProofSystem::RistrettoAirV2,
                TranscriptId::FlockBlake3,
            ) => {}
            (CurveId::Ristretto255, _, _) => {
                return Err(AbiError::UnsupportedProofSystem(self.proof_system as u8))
            }
            _ => return Err(AbiError::UnsupportedTranscript(self.transcript as u8)),
        }
        if self.statement_version != RECONSTRUCTION_V3_STATEMENT_VERSION {
            return Err(AbiError::UnsupportedVersion(self.statement_version));
        }

        let n = self.cards.len();
        let k = self.user_readable_cards.len();
        if n < 2 || n > MAX_DECK_SIZE || k == 0 || k > n || self.contributions.len() != n {
            return Err(AbiError::InvalidDeckSize);
        }
        if self.curve == CurveId::Ristretto255
            && (n != RISTRETTO_AIR_DECK_SIZE || k != RISTRETTO_AIR_RECONSTRUCTION_READABLE_CARDS)
        {
            return Err(AbiError::InvalidDeckSize);
        }
        let point_size = self.curve.point_size();
        if self.aggregate_pk.len() != point_size
            || self.owner_pk.len() != point_size
            || self.cards.iter().any(|card| card.len() != point_size)
            || !valid_ciphertexts(&self.user_readable_cards, point_size)
            || !valid_ciphertexts(&self.contributions, point_size)
        {
            return Err(AbiError::InvalidPointSize);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, AbiError> {
        self.validate()?;
        let n = u16_len(self.cards.len(), AbiError::InvalidDeckSize)?;
        let k = u16_len(self.user_readable_cards.len(), AbiError::InvalidDeckSize)?;
        let context_len = u16_len(self.context.len(), AbiError::ContextTooLarge)?;
        let call_context_len = u16_len(self.call_context.len(), AbiError::ContextTooLarge)?;
        let proof_len = u32_len(self.proof.len())?;

        let mut out = Vec::new();
        out.extend_from_slice(&RECONSTRUCTION_V3_REQUEST_MAGIC);
        out.extend_from_slice(&[
            RECONSTRUCTION_V3_ABI_VERSION,
            self.curve as u8,
            self.proof_system as u8,
            self.transcript as u8,
            0,
            self.statement_version,
        ]);
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&k.to_le_bytes());
        out.extend_from_slice(&context_len.to_le_bytes());
        out.extend_from_slice(&call_context_len.to_le_bytes());
        out.extend_from_slice(&self.reconstruction_epoch.to_le_bytes());
        out.extend_from_slice(&self.context_digest);
        out.extend_from_slice(&self.prior_state_digest);
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&self.call_context);
        out.extend_from_slice(&self.aggregate_pk);
        out.extend_from_slice(&self.owner_pk);
        for card in &self.cards {
            out.extend_from_slice(card);
        }
        encode_ciphertexts(&mut out, &self.user_readable_cards);
        encode_ciphertexts(&mut out, &self.contributions);
        out.extend_from_slice(&proof_len.to_le_bytes());
        out.extend_from_slice(&self.proof);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AbiError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(4)? != RECONSTRUCTION_V3_REQUEST_MAGIC {
            return Err(AbiError::InvalidMagic);
        }
        let version = decoder.u8()?;
        if version != RECONSTRUCTION_V3_ABI_VERSION {
            return Err(AbiError::UnsupportedVersion(version));
        }
        let curve = CurveId::try_from(decoder.u8()?)?;
        let proof_system = ReconstructionProofSystem::try_from(decoder.u8()?)?;
        let transcript = TranscriptId::try_from(decoder.u8()?)?;
        require_zero_flags(decoder.u8()?)?;
        let statement_version = decoder.u8()?;
        let n = decoder.u16()? as usize;
        let k = decoder.u16()? as usize;
        if n < 2 || n > MAX_DECK_SIZE || k == 0 || k > n {
            return Err(AbiError::InvalidDeckSize);
        }
        let context_len = checked_context_len(decoder.u16()? as usize)?;
        let call_context_len = checked_context_len(decoder.u16()? as usize)?;
        let reconstruction_epoch = decoder.u64()?;
        let mut context_digest = [0u8; 32];
        context_digest.copy_from_slice(decoder.take(32)?);
        let mut prior_state_digest = [0u8; 32];
        prior_state_digest.copy_from_slice(decoder.take(32)?);
        let context = decoder.take(context_len)?.to_vec();
        let call_context = decoder.take(call_context_len)?.to_vec();
        let point_size = curve.point_size();
        let aggregate_pk = decoder.take(point_size)?.to_vec();
        let owner_pk = decoder.take(point_size)?.to_vec();
        let cards = (0..n)
            .map(|_| Ok(decoder.take(point_size)?.to_vec()))
            .collect::<Result<Vec<_>, AbiError>>()?;
        let user_readable_cards = decode_ciphertexts(&mut decoder, k, point_size)?;
        let contributions = decode_ciphertexts(&mut decoder, n, point_size)?;
        let proof = decode_proof(&mut decoder)?;
        decoder.finish()?;

        let request = Self {
            curve,
            proof_system,
            transcript,
            context,
            call_context,
            statement_version,
            context_digest,
            reconstruction_epoch,
            prior_state_digest,
            aggregate_pk,
            owner_pk,
            cards,
            user_readable_cards,
            contributions,
            proof,
        };
        request.validate()?;
        Ok(request)
    }
}

pub trait ShuffleVerifier {
    type Error;
    fn verify(&self, request: &ShuffleVerifyRequest) -> Result<(), Self::Error>;
}

pub trait ReconstructionVerifier {
    type Error;
    fn verify(&self, request: &ReconstructionVerifyRequest) -> Result<(), Self::Error>;
}

pub trait ReconstructionV3Verifier {
    type Error;
    fn verify(&self, request: &ReconstructionV3VerifyRequest) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledShuffleVerifier;

impl ShuffleVerifier for DisabledShuffleVerifier {
    type Error = AbiError;
    fn verify(&self, _request: &ShuffleVerifyRequest) -> Result<(), Self::Error> {
        Err(AbiError::VerifierUnavailable)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledReconstructionVerifier;

impl ReconstructionVerifier for DisabledReconstructionVerifier {
    type Error = AbiError;
    fn verify(&self, _request: &ReconstructionVerifyRequest) -> Result<(), Self::Error> {
        Err(AbiError::VerifierUnavailable)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledReconstructionV3Verifier;

impl ReconstructionV3Verifier for DisabledReconstructionV3Verifier {
    type Error = AbiError;
    fn verify(&self, _request: &ReconstructionV3VerifyRequest) -> Result<(), Self::Error> {
        Err(AbiError::VerifierUnavailable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiError {
    UnexpectedEof,
    InvalidMagic,
    UnsupportedVersion(u8),
    UnsupportedCurve(u8),
    UnsupportedProofSystem(u8),
    UnsupportedTranscript(u8),
    InvalidFlags,
    InvalidDeckSize,
    ContextTooLarge,
    InvalidPointSize,
    InvalidProofSize,
    TrailingBytes,
    VerifierUnavailable,
}

impl std::fmt::Display for AbiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AbiError {}

fn validate_common(
    _curve: CurveId,
    context: &[u8],
    call_context: &[u8],
    proof: &[u8],
) -> Result<(), AbiError> {
    if context.is_empty()
        || context.len() > MAX_CONTEXT_SIZE
        || call_context.is_empty()
        || call_context.len() > MAX_CONTEXT_SIZE
    {
        return Err(AbiError::ContextTooLarge);
    }
    if proof.is_empty() || proof.len() > MAX_PROOF_SIZE {
        return Err(AbiError::InvalidProofSize);
    }
    Ok(())
}

fn valid_ciphertexts(ciphertexts: &[EncodedCiphertext], point_size: usize) -> bool {
    ciphertexts
        .iter()
        .all(|ct| ct.c1.len() == point_size && ct.c2.len() == point_size)
}

fn encode_ciphertexts(out: &mut Vec<u8>, ciphertexts: &[EncodedCiphertext]) {
    for ciphertext in ciphertexts {
        out.extend_from_slice(&ciphertext.c1);
        out.extend_from_slice(&ciphertext.c2);
    }
}

fn decode_ciphertexts(
    decoder: &mut Decoder<'_>,
    n: usize,
    point_size: usize,
) -> Result<Vec<EncodedCiphertext>, AbiError> {
    (0..n)
        .map(|_| {
            Ok(EncodedCiphertext {
                c1: decoder.take(point_size)?.to_vec(),
                c2: decoder.take(point_size)?.to_vec(),
            })
        })
        .collect()
}

fn decode_proof(decoder: &mut Decoder<'_>) -> Result<Vec<u8>, AbiError> {
    let proof_len = decoder.u32()? as usize;
    if proof_len == 0 || proof_len > MAX_PROOF_SIZE {
        return Err(AbiError::InvalidProofSize);
    }
    Ok(decoder.take(proof_len)?.to_vec())
}

fn checked_context_len(len: usize) -> Result<usize, AbiError> {
    if len == 0 || len > MAX_CONTEXT_SIZE {
        Err(AbiError::ContextTooLarge)
    } else {
        Ok(len)
    }
}

fn require_zero_flags(flags: u8) -> Result<(), AbiError> {
    if flags == 0 {
        Ok(())
    } else {
        Err(AbiError::InvalidFlags)
    }
}

fn u16_len(len: usize, error: AbiError) -> Result<u16, AbiError> {
    u16::try_from(len).map_err(|_| error)
}

fn u32_len(len: usize) -> Result<u32, AbiError> {
    u32::try_from(len).map_err(|_| AbiError::InvalidProofSize)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], AbiError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(AbiError::UnexpectedEof)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(AbiError::UnexpectedEof)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, AbiError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, AbiError> {
        let mut encoded = [0u8; 2];
        encoded.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(encoded))
    }

    fn u32(&mut self) -> Result<u32, AbiError> {
        let mut encoded = [0u8; 4];
        encoded.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(encoded))
    }

    fn u64(&mut self) -> Result<u64, AbiError> {
        let mut encoded = [0u8; 8];
        encoded.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(encoded))
    }

    fn finish(&self) -> Result<(), AbiError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(AbiError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ciphertext(byte: u8) -> EncodedCiphertext {
        EncodedCiphertext {
            c1: vec![byte; 48],
            c2: vec![byte.wrapping_add(1); 48],
        }
    }

    fn ristretto_ciphertext(byte: u8) -> EncodedCiphertext {
        EncodedCiphertext {
            c1: vec![byte; 32],
            c2: vec![byte.wrapping_add(1); 32],
        }
    }

    fn shuffle_request() -> ShuffleVerifyRequest {
        ShuffleVerifyRequest {
            curve: CurveId::Bls12377G1,
            proof_system: ShuffleProofSystem::BayerGrothV2,
            transcript: TranscriptId::FiatShamirSha3,
            context: b"zk_shuffle_proof_v2".to_vec(),
            call_context: b"table=1/hand=2/call=3/player=4".to_vec(),
            public_key: vec![7u8; 48],
            input: vec![ciphertext(1), ciphertext(2)],
            output: vec![ciphertext(3), ciphertext(4)],
            proof: vec![9u8; 256],
        }
    }

    #[test]
    fn ristretto_curve_id_has_its_own_canonical_width() {
        assert_eq!(CurveId::Ristretto255.point_size(), 32);
        assert_eq!(CurveId::try_from(3), Ok(CurveId::Ristretto255));

        let request = ShuffleVerifyRequest {
            curve: CurveId::Ristretto255,
            proof_system: ShuffleProofSystem::RistrettoAirV1,
            transcript: TranscriptId::Poseidon252,
            context: b"ristretto-air-v2".to_vec(),
            call_context: b"table=1/hand=2/call=3/epoch=2".to_vec(),
            public_key: vec![7u8; 32],
            input: (0..RISTRETTO_AIR_DECK_SIZE)
                .map(|index| ristretto_ciphertext(index as u8))
                .collect(),
            output: (0..RISTRETTO_AIR_DECK_SIZE)
                .map(|index| ristretto_ciphertext(index as u8 + 80))
                .collect(),
            proof: vec![9u8; 32],
        };
        let encoded = request.encode().expect("Ristretto request shape");
        assert_eq!(ShuffleVerifyRequest::decode(&encoded), Ok(request));
    }

    fn reconstruction_request() -> ReconstructionVerifyRequest {
        ReconstructionVerifyRequest {
            curve: CurveId::Bls12381G1,
            proof_system: ReconstructionProofSystem::BayerGrothOrderedV2,
            transcript: TranscriptId::FiatShamirSha3,
            context: b"zk_reconstruct_proof_v2".to_vec(),
            call_context: b"table=1/hand=2/call=4/player=3".to_vec(),
            cards: vec![vec![1; 48], vec![2; 48]],
            output_cards: vec![ciphertext(3), ciphertext(4)],
            swap_out_cards: vec![ciphertext(5)],
            user_readable_cards: vec![ciphertext(6)],
            user_public_key: vec![7; 48],
            proof: vec![8; 512],
        }
    }

    fn reconstruction_v3_request() -> ReconstructionV3VerifyRequest {
        ReconstructionV3VerifyRequest {
            curve: CurveId::Bls12381G1,
            proof_system: ReconstructionProofSystem::BayerGrothSlotOrV3,
            transcript: TranscriptId::FiatShamirSha3,
            context: b"zk_reconstruct_proof_v3".to_vec(),
            call_context: b"table=1/hand=3/call=4/player=3".to_vec(),
            statement_version: RECONSTRUCTION_V3_STATEMENT_VERSION,
            context_digest: [11; 32],
            reconstruction_epoch: 7,
            prior_state_digest: [12; 32],
            aggregate_pk: vec![7; 48],
            owner_pk: vec![8; 48],
            cards: vec![vec![1; 48], vec![2; 48]],
            user_readable_cards: vec![ciphertext(6)],
            contributions: vec![ciphertext(3), ciphertext(4)],
            proof: vec![9; 1024],
        }
    }

    #[test]
    fn shuffle_roundtrip_is_canonical() {
        let request = shuffle_request();
        let encoded = request.encode().unwrap();
        assert_eq!(ShuffleVerifyRequest::decode(&encoded).unwrap(), request);
    }

    #[test]
    fn reconstruction_roundtrip_is_canonical() {
        let request = reconstruction_request();
        let encoded = request.encode().unwrap();
        assert_eq!(
            ReconstructionVerifyRequest::decode(&encoded).unwrap(),
            request
        );
    }

    #[test]
    fn reconstruction_v3_roundtrip_is_canonical_and_distinct_from_v2() {
        let request = reconstruction_v3_request();
        let encoded = request.encode().unwrap();
        assert_eq!(
            ReconstructionV3VerifyRequest::decode(&encoded).unwrap(),
            request
        );
        assert_eq!(
            ReconstructionVerifyRequest::decode(&encoded).unwrap_err(),
            AbiError::InvalidMagic
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = shuffle_request().encode().unwrap();
        encoded.push(0);
        assert_eq!(
            ShuffleVerifyRequest::decode(&encoded).unwrap_err(),
            AbiError::TrailingBytes
        );
    }

    #[test]
    fn ristretto_air_v2_package_roundtrip_binds_parts() {
        let package = RistrettoAirV2SubmissionPackage::from_parts(vec![1, 2, 3], vec![9; 64]);
        let encoded = package.encode().expect("package encoding");
        assert_eq!(
            RistrettoAirV2SubmissionPackage::decode(&encoded),
            Ok(package.clone())
        );
        let mut altered = encoded.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert_ne!(
            RistrettoAirV2SubmissionPackage::decode(&altered),
            Ok(package)
        );
    }

    #[test]
    fn empty_call_scope_is_rejected() {
        let mut request = shuffle_request();
        request.call_context.clear();
        assert_eq!(request.validate().unwrap_err(), AbiError::ContextTooLarge);
    }

    #[test]
    fn disabled_verifiers_fail_closed() {
        assert_eq!(
            DisabledShuffleVerifier
                .verify(&shuffle_request())
                .unwrap_err(),
            AbiError::VerifierUnavailable
        );
        assert_eq!(
            DisabledReconstructionVerifier
                .verify(&reconstruction_request())
                .unwrap_err(),
            AbiError::VerifierUnavailable
        );
        assert_eq!(
            DisabledReconstructionV3Verifier
                .verify(&reconstruction_v3_request())
                .unwrap_err(),
            AbiError::VerifierUnavailable
        );
    }
}
