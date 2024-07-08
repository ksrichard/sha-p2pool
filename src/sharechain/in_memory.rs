// Copyright 2024 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use log::{debug, error, info, warn};
use minotari_app_grpc::tari_rpc::{NewBlockCoinbase, SubmitBlockRequest};
use tari_common_types::tari_address::TariAddress;
use tari_common_types::types::{FixedHash, HashOutput};
use tari_core::blocks::{BlockHeader, BlockHeaderAccumulatedData};
use tari_core::proof_of_work::{AccumulatedDifficulty, AchievedTargetDifficulty, Difficulty, sha3x_difficulty};
use tari_utilities::{ByteArray, epoch_time::EpochTime, hex::Hex};
use tokio::sync::{RwLock, RwLockWriteGuard};

use crate::sharechain::{
    Block,
    error::{BlockConvertError, Error},
    MAX_BLOCKS_COUNT,
    SHARE_COUNT,
    ShareChain,
    ShareChainResult,
};

const LOG_TARGET: &str = "in_memory_share_chain";

pub struct InMemoryShareChain {
    max_blocks_count: usize,
    blocks: Arc<RwLock<Vec<Block>>>,
}

fn genesis_block() -> Block {
    Block::builder(1).build()
}

impl Default for InMemoryShareChain {
    fn default() -> Self {
        Self {
            max_blocks_count: MAX_BLOCKS_COUNT,
            blocks: Arc::new(RwLock::new(vec![genesis_block()])),
        }
    }
}

#[allow(dead_code)]
impl InMemoryShareChain {
    pub fn new(max_blocks_count: usize) -> Self {
        Self {
            max_blocks_count,
            blocks: Arc::new(RwLock::new(vec![genesis_block()])),
        }
    }

    // TODO: division only with integers
    async fn miners_with_shares(&self) -> HashMap<String, f64> {
        let mut result: HashMap<String, f64> = HashMap::new(); // target wallet address -> number of shares
        let blocks_read_lock = self.blocks.read().await;
        blocks_read_lock.iter().for_each(|block| {
            // add main shares
            if let Some(miner_wallet_address) = block.miner_wallet_address() {
                let addr = miner_wallet_address.to_base58();
                if let Some(curr_hash_rate) = result.get(&addr) {
                    result.insert(addr, curr_hash_rate + 1.0);
                } else {
                    result.insert(addr, 1.0);
                }
            }

            // TODO: continue
            // add uncle shares
            for uncle_block in block.uncles() {}
        });

        result
    }

    async fn validate_block(&self,
                            blocks: &mut RwLockWriteGuard<'_, Vec<Block>>,
                            block: &Block,
                            network_difficulty: Option<u64>,
                            sync: bool,
    ) -> ShareChainResult<bool> {
        let last_block = blocks.last();
        // when we sync, the chain is empty, so accept first block immediately
        if last_block.is_none() && sync {
            return Ok(true);
        }
        let last_block = last_block.ok_or_else(|| Error::Empty)?;

        // validate hash
        if block.hash() != block.generate_hash() {
            warn!(target: LOG_TARGET, "❌ Invalid block, hashes do not match");
            return Ok(false);
        }

        // check if we have this block as last
        if last_block == block || last_block.hash() == block.hash() {
            warn!(target: LOG_TARGET, "↩️ This block already added, skip");
            return Ok(false);
        }

        // if last block is genesis, just approve
        if last_block.hash() == genesis_block().hash() {
            return Ok(true);
        }

        // validate original block header
        if let Some(last_block_original_block_header) = last_block.original_block_header() {
            if let Some(new_block_original_block_header) = block.original_block_header() {
                if last_block_original_block_header.hash() == new_block_original_block_header.hash() {
                    warn!(target: LOG_TARGET, "↩️ This block already added, skip");
                    return Ok(false);
                }

                let last_block_difficulty = sha3x_difficulty(new_block_original_block_header)
                    .map_err(Error::BlockDifficultyError)?;
                let new_block_difficulty = sha3x_difficulty(new_block_original_block_header)
                    .map_err(Error::BlockDifficultyError)?;

                // validate against current network difficulty
                if let Some(network_difficulty) = network_difficulty {
                    if new_block_difficulty.as_u64() < network_difficulty {
                        error!(target: LOG_TARGET, "Invalid block, Difficulty mismatch!");
                        return Ok(false);
                    }
                }

                // possible uncle block check
                if last_block_difficulty > new_block_difficulty {
                    // TODO: handle scenario as uncle block
                    warn!(target: LOG_TARGET, "Possible uncle block, new block has lower difficulty - Last: {:?} > {:?}", last_block_difficulty, new_block_difficulty);
                }
            } else {
                error!(target: LOG_TARGET, "No original Tari block header present on new submitted block!");
                return Ok(false);
            }
        } else {
            error!(target: LOG_TARGET, "No original Tari block header present on last block!");
            return Ok(false);
        }

        Ok(true)
    }

    async fn submit_block_with_lock(
        &self,
        blocks: &mut RwLockWriteGuard<'_, Vec<Block>>,
        block: &Block,
        network_difficulty: Option<u64>,
        sync: bool,
    ) -> ShareChainResult<()> {
        let mut block = block.clone();

        let last_block = blocks.last();
        if let Some(last_block) = last_block {
            block.set_height(last_block.height() + 1);
        } else {
            block.set_height(0);
        }

        // validate
        if !self.validate_block(blocks, &block, network_difficulty, sync).await? {
            return Err(Error::InvalidBlock(block.clone()));
        }

        if blocks.len() >= self.max_blocks_count {
            let diff = blocks.len() - self.max_blocks_count;
            blocks.drain(0..diff);
        }

        info!(target: LOG_TARGET, "🆕 New block added: {:?}", block.hash().to_hex());
        blocks.push(block);

        let last_block = blocks.last().ok_or_else(|| Error::Empty)?;
        info!(target: LOG_TARGET, "⬆️  Current height: {:?}", last_block.height());

        Ok(())
    }
}

#[async_trait]
impl ShareChain for InMemoryShareChain {
    async fn submit_block(&self, block: &Block, network_difficulty: u64) -> ShareChainResult<()> {
        let mut blocks_write_lock = self.blocks.write().await;
        self.submit_block_with_lock(&mut blocks_write_lock, block, Some(network_difficulty), false).await
    }

    async fn submit_blocks(&self, blocks: Vec<Block>, sync: bool) -> ShareChainResult<()> {
        let mut blocks_write_lock = self.blocks.write().await;

        if sync {
            blocks_write_lock.clear();
        }

        for block in blocks {
            self.submit_block_with_lock(&mut blocks_write_lock, &block, None, sync)
                .await?;
        }

        Ok(())
    }

    async fn last_block(&self) -> ShareChainResult<Block> {
        let blocks_read_lock = self.blocks.read().await;
        let last_block = blocks_read_lock.last().ok_or_else(|| Error::Empty)?;
        Ok(last_block.clone())
    }

    async fn generate_shares(&self, reward: u64) -> Vec<NewBlockCoinbase> {
        // TODO: include here the sender miner's wallet address with configurable % of reward
        // TODO: and use the rest % of reward to generate other shares
        let mut result = vec![];
        let miners = self.miners_with_shares().await;

        // calculate full hash rate and shares
        miners
            .iter()
            .map(|(addr, rate)| (addr, rate / SHARE_COUNT as f64))
            .filter(|(_, share)| *share > 0.0)
            .for_each(|(addr, share)| {
                let curr_reward = ((reward as f64) * share) as u64;
                debug!(target: LOG_TARGET, "{addr} -> SHARE: {share:?} T, REWARD: {curr_reward:?}");
                result.push(NewBlockCoinbase {
                    address: addr.clone(),
                    value: curr_reward,
                    stealth_payment: true,
                    revealed_value_proof: true,
                    coinbase_extra: vec![],
                });
            });

        result
    }

    async fn new_block(&self, request: &SubmitBlockRequest) -> ShareChainResult<Block> {
        let origin_block_grpc = request
            .block
            .as_ref()
            .ok_or_else(|| BlockConvertError::MissingField("block".to_string()))?;
        let origin_block_header_grpc = origin_block_grpc
            .header
            .as_ref()
            .ok_or_else(|| BlockConvertError::MissingField("header".to_string()))?;
        let origin_block_header = BlockHeader::try_from(origin_block_header_grpc.clone())
            .map_err(BlockConvertError::GrpcBlockHeaderConvert)?;

        let blocks_read_lock = self.blocks.read().await;
        let last_block = blocks_read_lock.last().ok_or_else(|| Error::Empty)?;

        Ok(Block::builder(request.target_difficulty)
            .with_timestamp(EpochTime::now())
            .with_prev_hash(last_block.generate_hash())
            .with_original_block_header(origin_block_header)
            .with_miner_wallet_address(
                TariAddress::from_hex(request.wallet_payment_address.as_str()).map_err(Error::TariAddress)?,
            )
            .build())
    }

    async fn blocks(&self) -> ShareChainResult<Vec<Block>> {
        let blocks_read_lock = self.blocks.read().await;
        Ok(blocks_read_lock.clone())
    }

    async fn validate_block(&self, block: &Block) -> ShareChainResult<bool> {
        let mut blocks_write_lock = self.blocks.write().await;
        self.validate_block(&mut blocks_write_lock, block, None, false).await
    }
}
