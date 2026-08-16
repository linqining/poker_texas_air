#[derive(Debug, Clone, PartialEq)]
pub enum VerificationError {
    InvalidProofAtPosition(usize),
    LengthMismatch,
    PlayerNotFound,
    TooManyCardsReplaced,
    InvalidC2Consistency,
    InvalidPlaintext,
    InvalidSecretKey,
    ReplayDetected,
    InvalidRevealToken,
    InvalidDLEQProof,
    IdentityBasePoint,
    InvalidOperation,
    InvalidCiphertext,
    InvalidCoefficient,
    InvalidInput,
    EntryNotFound,
    ProofVerificationFailed,
    InvalidPublicKey,
    LegacyShuffleProofDisabled,
    UnsupportedShuffleProofVersion,
    InvalidPermutation,
    InvalidRerandomizerCount,
    InvalidCommitmentKey,
    InvalidBayerGrothProof,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProofAtPosition(pos) => write!(f, "Invalid proof at position {pos}"),
            Self::LengthMismatch => write!(f, "Length mismatch"),
            Self::PlayerNotFound => write!(f, "Player not found"),
            Self::TooManyCardsReplaced => write!(f, "Too many cards replaced"),
            Self::InvalidC2Consistency => write!(f, "Invalid c2 consistency"),
            Self::InvalidPlaintext => write!(f, "Invalid plaintext"),
            Self::InvalidSecretKey => write!(f, "Invalid secret key"),
            Self::ReplayDetected => write!(f, "Replay detected"),
            Self::InvalidRevealToken => write!(f, "Invalid reveal token"),
            Self::InvalidDLEQProof => write!(f, "Invalid DLEQ proof"),
            Self::IdentityBasePoint => write!(f, "Identity base point"),
            Self::InvalidOperation => write!(f, "Invalid operation"),
            Self::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            Self::InvalidCoefficient => write!(f, "Invalid coefficient"),
            Self::InvalidInput => write!(f, "Invalid input"),
            Self::EntryNotFound => write!(f, "Entry not found"),
            Self::ProofVerificationFailed => write!(f, "Proof verification failed"),
            Self::InvalidPublicKey => write!(f, "Invalid public key"),
            Self::LegacyShuffleProofDisabled => write!(f, "legacy V1 shuffle proofs are disabled"),
            Self::UnsupportedShuffleProofVersion => write!(f, "unsupported shuffle proof version"),
            Self::InvalidPermutation => write!(f, "invalid shuffle permutation"),
            Self::InvalidRerandomizerCount => write!(f, "invalid rerandomizer count"),
            Self::InvalidCommitmentKey => write!(f, "invalid Bayer-Groth commitment key"),
            Self::InvalidBayerGrothProof => write!(f, "invalid Bayer-Groth shuffle proof"),
        }
    }
}

impl std::error::Error for VerificationError {}
