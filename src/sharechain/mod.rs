// Copyright 2024 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use async_trait::async_trait;
use minotari_app_grpc::tari_rpc::{NewBlockCoinbase, SubmitBlockRequest};
use tari_common_types::tari_address::TariAddress;
use tari_common_types::types::FixedHash;

use crate::sharechain::{block::Block, error::Error};

/// Maximum number of blocks kept in share chain.
pub const MAX_BLOCKS_COUNT: usize = 80;

/// Number of shares.
pub const SHARE_COUNT: u64 = 100;

// TODO: this should come from configuration instead!
/// The fixed percent of the reward earned by the miner who finds a new block.
pub const MINER_REWARD_SHARE_COUNT: u64 = 10;

pub mod block;
pub mod error;
pub mod in_memory;
pub mod tests;

pub type ShareChainResult<T> = Result<T, Error>;

pub struct SubmitBlockResult {
    pub need_sync: bool,
}

impl SubmitBlockResult {
    pub fn new(need_sync: bool) -> Self {
        Self { need_sync }
    }
}

pub struct ValidateBlockResult {
    pub valid: bool,
    pub need_sync: bool,
}

impl ValidateBlockResult {
    pub fn new(valid: bool, need_sync: bool) -> Self {
        Self { valid, need_sync }
    }
}

pub struct GenerateSharesResult {
    /// Hash generated from shares (coinbases), it can be used to prove that a block contains
    /// a specific set of shares.
    pub hash: FixedHash,
    /// Generated coinbases.
    pub coinbases: Vec<NewBlockCoinbase>,
}

impl GenerateSharesResult {
    pub fn new(hash: FixedHash, coinbases: Vec<NewBlockCoinbase>) -> Self {
        Self {
            hash,
            coinbases,
        }
    }
}

#[async_trait]
pub trait ShareChain {
    /// Adds a new block if valid to chain.
    async fn submit_block(&self, block: &Block) -> ShareChainResult<SubmitBlockResult>;

    /// Add multiple blocks at once.
    /// While this operation runs, no other blocks can be added until it's done.
    async fn submit_blocks(&self, blocks: Vec<Block>, sync: bool) -> ShareChainResult<SubmitBlockResult>;

    /// Returns the tip of height in chain (from original Tari block header)
    async fn tip_height(&self) -> ShareChainResult<u64>;

    /// Generate shares based on the previous blocks.
    async fn generate_shares(&self, miner_wallet_address: &TariAddress, reward: u64) -> GenerateSharesResult;

    /// Return a new block that could be added via `submit_block`.
    async fn new_block(&self, request: &SubmitBlockRequest) -> ShareChainResult<Block>;

    /// Returns blocks from the given height (`from_height`, exclusive).
    async fn blocks(&self, from_height: i64) -> ShareChainResult<Vec<Block>>;
}
