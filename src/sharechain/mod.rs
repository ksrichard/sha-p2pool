// Copyright 2024 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use async_trait::async_trait;
use minotari_app_grpc::tari_rpc::{NewBlockCoinbase, SubmitBlockRequest};

use crate::sharechain::{block::Block, error::Error};

pub const MAX_BLOCKS_COUNT: usize = 80;

pub const SHARE_COUNT: u64 = 100;

pub mod block;
pub mod error;
pub mod in_memory;

pub type ShareChainResult<T> = Result<T, Error>;

#[async_trait]
pub trait ShareChain {
    /// Adds a new block if valid to chain.
    async fn submit_block(&self, block: &Block, network_difficulty: u64) -> ShareChainResult<()>;

    /// Add multiple blocks at once.
    /// While this operation runs, no other blocks can be added until it's done.
    async fn submit_blocks(&self, blocks: Vec<Block>, sync: bool) -> ShareChainResult<()>;

    /// Returns the last block in the chain (tip of chain).
    async fn last_block(&self) -> ShareChainResult<Block>;

    /// Generate shares based on the previous blocks.
    async fn generate_shares(&self, reward: u64) -> Vec<NewBlockCoinbase>;

    /// Return a new block that could be added via `submit_block`.
    async fn new_block(&self, request: &SubmitBlockRequest) -> ShareChainResult<Block>;

    /// Returns all blocks.
    async fn blocks(&self) -> ShareChainResult<Vec<Block>>;

    /// Validates a block.
    async fn validate_block(&self, block: &Block) -> ShareChainResult<bool>;
}
