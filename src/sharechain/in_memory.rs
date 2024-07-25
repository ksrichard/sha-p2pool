// Copyright 2024 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use std::{collections::HashMap, sync::Arc};
use std::slice::Iter;

use async_trait::async_trait;
use blake2::Blake2b;
use digest::consts::U32;
use log::{debug, info, warn};
use minotari_app_grpc::tari_rpc::{AggregateBody, NewBlockCoinbase, SubmitBlockRequest};
use tari_common_types::tari_address::TariAddress;
use tari_common_types::types::{BlockHash, FixedHash};
use tari_core::blocks::{BlockHeader, BlocksHashDomain};
use tari_core::consensus::DomainSeparatedConsensusHasher;
use tari_core::proof_of_work::{Difficulty, DifficultyError, sha3x_difficulty};
use tari_utilities::{epoch_time::EpochTime, hex::Hex};
use tokio::sync::{RwLock, RwLockWriteGuard};

use crate::sharechain::{Block, error::{BlockConvertError, Error}, GenerateSharesResult, MAX_BLOCKS_COUNT, MINER_REWARD_SHARE_COUNT, SHARE_COUNT, ShareChain, ShareChainResult, SubmitBlockResult, ValidateBlockResult};

const LOG_TARGET: &str = "p2pool::sharechain::in_memory";

pub struct InMemoryShareChain {
    max_blocks_count: usize,
    block_levels: Arc<RwLock<Vec<BlockLevel>>>,
}

/// A collection of blocks with the same height.
pub struct BlockLevel {
    blocks: Vec<Block>,
    height: u64,
}

impl BlockLevel {
    pub fn new(blocks: Vec<Block>, height: u64) -> Self {
        Self { blocks, height }
    }

    pub fn add_block(&mut self, block: Block) -> Result<(), Error> {
        if self.height != block.height() {
            return Err(Error::InvalidBlock(block));
        }
        self.blocks.push(block);
        Ok(())
    }
}

fn genesis_block() -> Block {
    Block::builder().with_height(0).with_prev_hash(BlockHash::zero()).build()
}

impl Default for InMemoryShareChain {
    fn default() -> Self {
        Self {
            max_blocks_count: MAX_BLOCKS_COUNT,
            block_levels: Arc::new(RwLock::new(vec![BlockLevel::new(vec![genesis_block()], 0)])),
        }
    }
}

#[allow(dead_code)]
impl InMemoryShareChain {
    pub fn new(max_blocks_count: usize) -> Self {
        Self {
            max_blocks_count,
            block_levels: Arc::new(RwLock::new(vec![BlockLevel::new(vec![genesis_block()], 0)])),
        }
    }

    /// Returns the last block in chain
    fn last_block(&self, block_level_iter: Iter<'_, BlockLevel>) -> Option<Block> {
        let levels = block_level_iter.as_slice();
        if levels.is_empty() {
            return None;
        }
        let last_level = &block_level_iter.as_slice().last().unwrap();

        last_level
            .blocks
            .iter()
            .max_by(|block1, block2| block1.height().cmp(&block2.height()))
            .cloned()
    }

    /// Returns the current (strongest) chain
    fn chain(&self, block_level_iter: Iter<'_, BlockLevel>) -> Vec<Block> {
        let mut result = vec![];
        block_level_iter.for_each(|level| {
            level
                .blocks
                .iter()
                .max_by(|block1, block2| {
                    let diff1 = if let Ok(diff) = sha3x_difficulty(block1.original_block_header()) {
                        diff.as_u64()
                    } else {
                        0
                    };
                    let diff2 = if let Ok(diff) = sha3x_difficulty(block2.original_block_header()) {
                        diff.as_u64()
                    } else {
                        0
                    };
                    diff1.cmp(&diff2)
                })
                .iter()
                .copied()
                .for_each(|block| {
                    result.push(block.clone());
                });
        });

        result
    }

    /// Generating number of shares for all the miners.
    async fn miners_with_shares(&self, block_level_iter: Iter<'_, BlockLevel>) -> HashMap<String, u64> {
        let mut result: HashMap<String, u64> = HashMap::new(); // target wallet address -> number of shares
        let chain = self.chain(block_level_iter);
        chain.iter().for_each(|block| {
            if let Some(miner_wallet_address) = block.miner_wallet_address() {
                let addr = miner_wallet_address.to_base58();
                if let Some(curr_hash_rate) = result.get(&addr) {
                    result.insert(addr, curr_hash_rate + 1);
                } else {
                    result.insert(addr, 1);
                }
            }
        });

        result
    }

    /// Validating a new block.
    async fn validate_block(
        &self,
        block_level_iter: Iter<'_, BlockLevel>,
        block: &Block,
        sync: bool,
    ) -> ShareChainResult<ValidateBlockResult> {
        let chain = self.chain(block_level_iter.clone());
        let mut last_block = None;

        for level in block_level_iter.clone() {
            let last_block_found = level.blocks.iter()
                .filter(|old_block| old_block.hash() == block.prev_hash())
                .last();
            if last_block_found.is_some() {
                last_block = last_block_found
            }
        }

        if last_block.is_some() {
            info!("VALIDATE - LAST BLOCK: {:?}", last_block.unwrap().hash());
        }

        // if the new block's height is lower than or equal to the last block height,
        // just try to look for the block level where height is previous to the new block
        // if let Some(last_block_found) = chain.last() {
        // if block.prev_hash() != last_block_found.generate_hash() {
        //     warn!("New block's prev hash is not the next one!");
        // for level in block_level_iter.clone() {
        //     let last_block_found = level.blocks.iter()
        //         .filter(|old_block| old_block.hash() == block.prev_hash())
        //         .last();
        //     if last_block_found.is_some() {
        //         last_block = last_block_found
        //     }
        // }
        // if let Some(found_level) = block_level_iter.clone()
        //     .filter(|level|
        //         block.height() != 0 && (level.height == block.height() - 1) ||
        //             (level.)
        //     ) // TODO: revisit if block.height() != 0 is needed
        //     .last() {
        //     last_block = found_level.blocks.iter()
        //         .filter(|old_block| old_block.generate_hash() == block.prev_hash())
        //         .last()
        // }
        // }
        // }


        if sync && last_block.is_none() {
            return Ok(ValidateBlockResult::new(true, false));
        }

        if let Some(last_block) = last_block {
            // check if we have outdated tip of chain
            let block_height_diff = i64::try_from(block.height()).map_err(Error::FromIntConversion)?
                - i64::try_from(last_block.height()).map_err(Error::FromIntConversion)?;
            if block_height_diff > 1 {
                warn!("Out-of-sync chain, do a sync now...");
                return Ok(ValidateBlockResult::new(false, true));
            }

            // TODO: revisit and continue validation

            // // validate hash
            // if block.hash() != block.generate_hash() {
            //     warn!(target: LOG_TARGET, "❌ Invalid block, hashes do not match");
            //     return Ok(ValidateBlockResult::new(false, false));
            // }

            // validate PoW
            match sha3x_difficulty(block.original_block_header()) {
                Ok(difficulty) => {
                    // let last_block_difficulty = sha3x_difficulty(last_block.original_block_header())
                    //     .map_err(Error::GenerateDifficulty)?;
                    // if difficulty < last_block_difficulty {
                    //     warn!(target: LOG_TARGET, "❌ Low difficulty!");
                    //     return Ok(ValidateBlockResult::new(false, false));
                    // }
                }
                Err(_) => {
                    warn!(target: LOG_TARGET, "❌ Invalid PoW, can't calculate difficulty!");
                    return Ok(ValidateBlockResult::new(false, false));
                }
            }

            // TODO: validate generated hash from original tari block's first coinbase extra
            // let current_share_count = SHARE_COUNT - MINER_REWARD_SHARE_COUNT;
            // TODO: add self miner
            let mut miners = self.miners_with_shares(block_level_iter).await;
            if miners.is_empty() {
                if let Some(miner_wallet_address) = block.miner_wallet_address() {
                    miners.insert(miner_wallet_address.to_base58(), 1);
                }
            }
            let mut miner_shares: Vec<(String, u64)> = miners
                .iter()
                .map(|(addr, rate)| (addr.clone(), (SHARE_COUNT / 100) * rate))
                .filter(|(_, share)| *share > 0)
                .collect();

            // TODO: remove, debugging only
            info!("");
            info!("----------------------------------");
            info!("SUBMIT BLOCK VALIDATION: Height: {:?}, Miner wallet address: {:?}, Prev block hash: {:?}", block.height(), block.miner_wallet_address().clone().unwrap().to_hex(), block.prev_hash().to_hex());

            let hash = block.generate_mining_hash(&self.miners_shares_hash(&mut miner_shares));

            info!("Block hash: {:?} ?= {:?}", block.proof_hash().to_hex(), hash.to_hex());
            info!("[O] PROOF HASH: {:?}", block.proof_hash());
            info!("[G] PROOF HASH: {:?}", hash);
            info!("----------------------------------");
            info!("");

            if hash.to_hex() != block.proof_hash().to_hex() {
                warn!(target: LOG_TARGET, "❌ Invalid proof hash!");
                return Ok(ValidateBlockResult::new(false, false));
            }

            // TODO: check here for miners
            // TODO: (send merkle tree root hash and generate here, then compare the two from miners list and shares)
        } else {
            return Ok(ValidateBlockResult::new(false, true));
        }

        Ok(ValidateBlockResult::new(true, false))
    }

    /// Submits a new block to share chain.
    async fn submit_block_with_lock(
        &self,
        block_levels: &mut RwLockWriteGuard<'_, Vec<BlockLevel>>,
        block: &Block,
        sync: bool,
    ) -> ShareChainResult<SubmitBlockResult> {
        let chain = self.chain(block_levels.iter());
        let last_block = chain.last();

        // validate
        let validate_result = self.validate_block(block_levels.iter(), block, sync).await?;
        if !validate_result.valid {
            return if validate_result.need_sync {
                Ok(SubmitBlockResult::new(true))
            } else {
                Err(Error::InvalidBlock(block.clone()))
            };
        }

        // remove the first couple of block levels if needed
        if block_levels.len() >= self.max_blocks_count {
            let diff = block_levels.len() - self.max_blocks_count;
            block_levels.drain(0..diff);
        }

        // look for the matching block level to append the new block to
        if let Some(found_level) = block_levels
            .iter_mut()
            .filter(|level| level.height == block.height())
            .last()
        {
            let found = found_level
                .blocks
                .iter()
                .filter(|curr_block| curr_block.generate_hash() == block.generate_hash())
                .count()
                > 0;
            if !found {
                found_level.add_block(block.clone())?;
                info!(target: LOG_TARGET, "🆕 New block added: {:?}", block.hash().to_hex());
            }
        } else if let Some(last_block) = last_block {
            if last_block.height() < block.height() {
                block_levels.push(BlockLevel::new(vec![block.clone()], block.height()));
                info!(target: LOG_TARGET, "🆕 New block added: {:?}", block.hash().to_hex());
            }
        } else {
            block_levels.push(BlockLevel::new(vec![block.clone()], block.height()));
            info!(target: LOG_TARGET, "🆕 New block added: {:?}", block.hash().to_hex());
        }

        Ok(SubmitBlockResult::new(validate_result.need_sync))
    }

    fn miners_shares_hash(&self, miner_shares: &mut Vec<(String, u64)>) -> FixedHash {
        // sorting to make sure we generate the same hash
        // for the same set of "miner wallet address" -> "share" pairs
        miner_shares.sort_by(|s1, s2| {
            s1.1.cmp(&s2.1)
        });

        let mut hasher = DomainSeparatedConsensusHasher::<BlocksHashDomain, Blake2b<U32>>::new("shares");
        for (addr, share) in miner_shares {
            hasher = hasher.chain(addr).chain(share);
        }

        hasher.finalize().into()
    }
}

#[async_trait]
impl ShareChain for InMemoryShareChain {
    async fn submit_block(&self, block: &Block) -> ShareChainResult<SubmitBlockResult> {
        let mut block_levels_write_lock = self.block_levels.write().await;
        let result = self
            .submit_block_with_lock(&mut block_levels_write_lock, block, false)
            .await;
        let chain = self.chain(block_levels_write_lock.iter());
        let last_block = chain.last().ok_or_else(|| Error::Empty)?;
        info!(target: LOG_TARGET, "⬆️  Current height: {:?}", last_block.height());
        result
    }

    async fn submit_blocks(&self, blocks: Vec<Block>, sync: bool) -> ShareChainResult<SubmitBlockResult> {
        let mut block_levels_write_lock = self.block_levels.write().await;

        if sync {
            let chain = self.chain(block_levels_write_lock.iter());
            if let Some(last_block) = chain.last() {
                if last_block.hash() != genesis_block().hash()
                    && usize::try_from(last_block.height()).map_err(Error::FromIntConversion)? < MAX_BLOCKS_COUNT
                    && usize::try_from(blocks[0].height()).map_err(Error::FromIntConversion)? > MAX_BLOCKS_COUNT
                {
                    block_levels_write_lock.clear();
                }
            }
        }

        for block in blocks {
            let result = self
                .submit_block_with_lock(&mut block_levels_write_lock, &block, sync)
                .await?;
            if result.need_sync {
                return Ok(SubmitBlockResult::new(true));
            }
        }

        let chain = self.chain(block_levels_write_lock.iter());
        let last_block = chain.last().ok_or_else(|| Error::Empty)?;
        info!(target: LOG_TARGET, "⬆️  Current height: {:?}", last_block.height());

        Ok(SubmitBlockResult::new(false))
    }

    async fn tip_height(&self) -> ShareChainResult<u64> {
        let block_levels_read_lock = self.block_levels.read().await;
        let chain = self.chain(block_levels_read_lock.iter());
        let last_block = chain.last().ok_or_else(|| Error::Empty)?;
        Ok(last_block.height())
    }

    async fn generate_shares(&self, miner_wallet_address: &TariAddress, reward: u64) -> GenerateSharesResult {
        // let sender_reward = (reward / 100) * MINER_REWARD_SHARE_COUNT;
        // let reward = reward - sender_reward;
        let block_levels_read_lock = self.block_levels.read().await;
        let mut miners = self.miners_with_shares(block_levels_read_lock.iter()).await;

        // TODO: revisit
        // calculate full hash rate and shares
        // miners.insert(miner_wallet_address.to_base58(), MINER_REWARD_SHARE_COUNT);
        // let mut coinbases = vec![
        //     NewBlockCoinbase {
        //         address: miner_wallet_address.to_base58(),
        //         value: sender_reward,
        //         stealth_payment: true,
        //         revealed_value_proof: true,
        //         coinbase_extra: vec![],
        //     }
        // ];
        let mut coinbases = vec![];

        // let current_share_count = SHARE_COUNT - MINER_REWARD_SHARE_COUNT;

        if miners.is_empty() {
            miners.insert(miner_wallet_address.to_base58(), 1);
            coinbases.push(
                NewBlockCoinbase {
                    address: miner_wallet_address.to_base58(),
                    value: (SHARE_COUNT / 100) * reward,
                    stealth_payment: true,
                    revealed_value_proof: true,
                    coinbase_extra: vec![],
                }
            );
        }

        let mut miner_shares: Vec<(String, u64)> = miners
            .iter()
            .map(|(addr, rate)| (addr.clone(), (SHARE_COUNT / 100) * rate))
            .filter(|(_, share)| *share > 0)
            .collect();

        for (addr, share) in &miner_shares {
            let curr_reward = reward * share;
            info!(target: LOG_TARGET, "{addr} -> SHARE: {share:?}, REWARD: {curr_reward:?}");
            coinbases.push(NewBlockCoinbase {
                address: addr.clone(),
                value: curr_reward,
                stealth_payment: true,
                revealed_value_proof: true,
                coinbase_extra: vec![],
            });
        }

        GenerateSharesResult::new(
            self.miners_shares_hash(&mut miner_shares),
            coinbases,
        )
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
        let origin_block_body = origin_block_grpc.body.as_ref()
            .ok_or_else(|| BlockConvertError::MissingField("body".to_string()))?;

        // extract proof hash
        let proof_hash = origin_block_body.outputs.first()
            .ok_or_else(|| BlockConvertError::MissingField("block body outputs".to_string()))?
            .features.as_ref()
            .ok_or_else(|| BlockConvertError::MissingField("block body outputs features".to_string()))?
            .coinbase_extra.clone();

        let block_levels_read_lock = self.block_levels.read().await;
        let chain = self.chain(block_levels_read_lock.iter());
        let last_block = chain.last().ok_or_else(|| Error::Empty)?;

        Ok(Block::builder()
            .with_timestamp(EpochTime::now())
            .with_prev_hash(last_block.generate_hash())
            .with_height(last_block.height() + 1)
            .with_original_block_header(origin_block_header)
            .with_proof_hash(proof_hash)
            .with_miner_wallet_address(
                TariAddress::from_hex(request.wallet_payment_address.as_str()).map_err(Error::TariAddress)?,
            )
            .build())
    }

    async fn blocks(&self, from_height: i64) -> ShareChainResult<Vec<Block>> {
        let block_levels_read_lock = self.block_levels.read().await;
        let chain = self.chain(block_levels_read_lock.iter());
        Ok(chain
            .iter()
            .filter(|block| block.height() as i64 > from_height)
            .cloned()
            .collect())
    }
}
