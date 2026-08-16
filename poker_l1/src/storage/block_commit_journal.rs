//! Durable intent log for a block transition spanning independent RocksDB stores.
//!
//! `ObjectDb`, `AccountStore`, and `BlockStore` intentionally use separate databases.  Their
//! individual WriteBatches are atomic, but a machine crash between those batches must not leave a
//! node unable to determine whether it should finish or roll back a finalized block.  This journal
//! is synchronously persisted before any state database is touched and is removed only after all
//! three durable writes have completed.

use std::path::Path;
use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use rocksdb::{ColumnFamilyDescriptor, DB, Options, WriteOptions};

use crate::Hash;
use crate::account::Account;
use crate::block::Block;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::storage::BridgeNonceSnapshot;

const PENDING_CF: &str = "pending_block_commit";
const PENDING_KEY: &[u8] = b"active";

/// A fully validated block transition that has not yet completed every durable store write.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct PendingBlockCommit {
    /// Canonical block to write after state stores reach its committed roots.
    pub block: Block,
    /// Object root before the transition; recovery refuses an unrelated local state.
    pub object_root_before: Hash,
    /// Account root before the transition.
    pub account_root_before: Hash,
    /// Complete pre-transition account state, used to safely retry after an account-only commit.
    pub accounts_before: Vec<Account>,
    /// Complete committed account state, used when ObjectDb was durable before a crash.
    pub accounts_after: Vec<Account>,
    /// Bridge replay-protection state before the transition, if this node has a bridge store.
    pub bridge_nonces_before: Option<BridgeNonceSnapshot>,
    /// Bridge replay-protection state after the transition, if this node has a bridge store.
    pub bridge_nonces_after: Option<BridgeNonceSnapshot>,
}

/// One-record synchronous write-ahead journal.
pub struct BlockCommitJournal {
    db: Arc<DB>,
}

impl BlockCommitJournal {
    /// Open (or create) a durable journal at `path`.
    pub fn open(path: impl AsRef<Path>) -> PokerL1Result<Self> {
        let mut options = Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        let cf = ColumnFamilyDescriptor::new(PENDING_CF, Options::default());
        let db = DB::open_cf_descriptors(&options, path, vec![cf])
            .map_err(|error| PokerL1Error::Rocksdb(error.to_string()))?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Open an isolated temporary journal for in-memory nodes and tests.
    pub fn open_inmemory() -> PokerL1Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "poker_l1_block_commit_journal_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        Self::open(path)
    }

    fn cf(&self) -> &rocksdb::ColumnFamily {
        self.db
            .cf_handle(PENDING_CF)
            .expect("pending journal column family must exist")
    }

    /// Persist an intent before any state-store mutation.
    pub fn prepare(&self, pending: &PendingBlockCommit) -> PokerL1Result<()> {
        let mut write_options = WriteOptions::default();
        write_options.set_sync(true);
        self.db
            .put_cf_opt(
                self.cf(),
                PENDING_KEY,
                borsh::to_vec(pending)?,
                &write_options,
            )
            .map_err(|error| PokerL1Error::Rocksdb(error.to_string()))
    }

    /// Return the single pending transition, if a previous process did not complete it.
    pub fn pending(&self) -> PokerL1Result<Option<PendingBlockCommit>> {
        self.db
            .get_cf(self.cf(), PENDING_KEY)
            .map_err(|error| PokerL1Error::Rocksdb(error.to_string()))?
            .map(|bytes| borsh::from_slice(&bytes).map_err(Into::into))
            .transpose()
    }

    /// Synchronously delete the intent only after every store has reached the final state.
    pub fn clear(&self) -> PokerL1Result<()> {
        let mut write_options = WriteOptions::default();
        write_options.set_sync(true);
        self.db
            .delete_cf_opt(self.cf(), PENDING_KEY, &write_options)
            .map_err(|error| PokerL1Error::Rocksdb(error.to_string()))
    }
}
