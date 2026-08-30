use std::fmt;

#[derive(Debug)]
pub enum TableError {
    PlayerNotFound(String),
    SeatEmpty(u32),
    InvalidAction(String),
    InvalidCards(String),
    PhaseError(String),
    ShuffleError(String),
    RevealError(String),
    ReconstructError(String),
    BettingError(String),
    JoinError(JoinError),
    Crypto(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum JoinError {
    PlayerAlreadyInGame,
    InvalidSeatId,
    SeatAlreadyOccupied,
    InvalidPkProof,
    InvalidRemaskProof,
    InvalidShuffleProof,
    Crypto(String),
}

impl fmt::Display for TableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TableError::PlayerNotFound(pk) => write!(f, "Player not found: {}", pk),
            TableError::SeatEmpty(id) => write!(f, "Seat {} is empty", id),
            TableError::InvalidAction(msg) => write!(f, "Invalid action: {}", msg),
            TableError::InvalidCards(msg) => write!(f, "Invalid cards: {}", msg),
            TableError::PhaseError(msg) => write!(f, "Phase error: {}", msg),
            TableError::ShuffleError(msg) => write!(f, "Shuffle error: {}", msg),
            TableError::RevealError(msg) => write!(f, "Reveal error: {}", msg),
            TableError::ReconstructError(msg) => write!(f, "Reconstruct error: {}", msg),
            TableError::BettingError(msg) => write!(f, "Betting error: {}", msg),
            TableError::JoinError(e) => write!(f, "Join error: {}", e),
            TableError::Crypto(msg) => write!(f, "Crypto error: {}", msg),
        }
    }
}

impl fmt::Display for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JoinError::PlayerAlreadyInGame => write!(f, "Player already in game"),
            JoinError::InvalidSeatId => write!(f, "Invalid seat_id"),
            JoinError::SeatAlreadyOccupied => write!(f, "Seat already occupied"),
            JoinError::InvalidPkProof => write!(f, "Invalid PK proof"),
            JoinError::InvalidRemaskProof => write!(f, "Invalid remask proof"),
            JoinError::InvalidShuffleProof => write!(f, "Invalid shuffle proof"),
            JoinError::Crypto(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for TableError {}
impl std::error::Error for JoinError {}

impl From<String> for TableError {
    fn from(s: String) -> Self {
        TableError::Crypto(s)
    }
}

impl From<String> for JoinError {
    fn from(s: String) -> Self {
        JoinError::Crypto(s)
    }
}

impl From<JoinError> for TableError {
    fn from(e: JoinError) -> Self {
        TableError::JoinError(e)
    }
}
