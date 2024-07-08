// Copyright 2024 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use blake2::Blake2b;
use digest::consts::U32;
use serde::{Deserialize, Serialize};
use tari_common_types::{tari_address::TariAddress, types::BlockHash};
use tari_core::{
    blocks::{BlockHeader, BlocksHashDomain},
    consensus::DomainSeparatedConsensusHasher,
};
use tari_utilities::epoch_time::EpochTime;

use crate::impl_conversions;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Block {
    hash: BlockHash,
    timestamp: EpochTime,
    prev_hash: BlockHash,
    height: u64,
    original_block_header: Option<BlockHeader>,
    miner_wallet_address: Option<TariAddress>,
    sent_to_main_chain: bool,
    target_difficulty: u64,
    uncles: Vec<Block>,
}
impl_conversions!(Block);



#[allow(dead_code)]
impl Block {
    pub fn builder(target_difficulty: u64) -> BlockBuilder {
        BlockBuilder::new(target_difficulty)
    }

    pub fn generate_hash(&self) -> BlockHash {
        let mut hash = DomainSeparatedConsensusHasher::<BlocksHashDomain, Blake2b<U32>>::new("block")
            .chain(&self.prev_hash);

        if let Some(miner_wallet_address) = &self.miner_wallet_address {
            hash = hash.chain(&miner_wallet_address.to_hex());
        }

        if let Some(original_block_header) = &self.original_block_header {
            hash = hash.chain(original_block_header);
        }

        hash.finalize().into()
    }

    pub fn timestamp(&self) -> EpochTime {
        self.timestamp
    }

    pub fn prev_hash(&self) -> BlockHash {
        self.prev_hash
    }

    pub fn height(&self) -> u64 {
        self.height
    }


    pub fn original_block_header(&self) -> &Option<BlockHeader> {
        &self.original_block_header
    }

    pub fn hash(&self) -> BlockHash {
        self.hash
    }

    pub fn set_sent_to_main_chain(&mut self, sent_to_main_chain: bool) {
        self.sent_to_main_chain = sent_to_main_chain;
    }

    pub fn miner_wallet_address(&self) -> &Option<TariAddress> {
        &self.miner_wallet_address
    }

    pub fn sent_to_main_chain(&self) -> bool {
        self.sent_to_main_chain
    }


    // pub fn accumulated_pow(&self) -> Result<(), Error> {
    //     let original_header = self.original_block_header.as_ref()
    //         .ok_or_else(|| Error::BlockConvert(BlockConvertError::MissingField(String::from("header"))))?;
    //     sha3x_difficulty(original_header);
    //     let acc_data = BlockHeaderAccumulatedData {
    //         hash: self.hash,
    //         total_kernel_offset: original_header.total_kernel_offset.clone(),
    //         achieved_difficulty: Default::default(),
    //         total_accumulated_difficulty: Default::default(),
    //         accumulated_randomx_difficulty: Default::default(),
    //         accumulated_sha3x_difficulty: Default::default(),
    //         target_difficulty: Default::default(),
    //     };
    //     BlockHeaderAccumulatedData::builder(&acc_data).build();
    //
    //     Ok(())
    // }

    /// Adding a new uncle block to the current one.
    pub fn add_uncle(&mut self, block: Block) {
        if block.height == self.height {
            self.uncles.push(block);
        }
    }

    /// Returns all the uncles recursively.
    /// This is useful when calculating shares.
    pub fn uncles(&self) -> Vec<Block> {
        self.all_uncles_recursive(None)
    }

    fn all_uncles_recursive(&self, parent: Option<&Block>) -> Vec<Block> {
        let uncles = if let Some(parent) = parent {
            parent.uncles.iter()
        } else {
            self.uncles.iter()
        };
        uncles.flat_map(|block| {
            let mut result = vec![block.clone()];
            if !block.uncles.is_empty() {
                let mut uncles = self.all_uncles_recursive(Some(block));
                result.append(&mut uncles);
            }
            result
        })
            .collect()
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }
    
    pub fn target_difficulty(&self) -> u64 {
        self.target_difficulty
    }
}

pub struct BlockBuilder {
    block: Block,
}

impl BlockBuilder {
    pub fn new(target_difficulty: u64) -> Self {
        Self {
            block: Block {
                hash: Default::default(),
                timestamp: EpochTime::now(),
                prev_hash: Default::default(),
                height: 0,
                original_block_header: None,
                miner_wallet_address: None,
                sent_to_main_chain: false,
                target_difficulty,
                uncles: vec![],
            },
        }
    }

    pub fn with_timestamp(&mut self, timestamp: EpochTime) -> &mut Self {
        self.block.timestamp = timestamp;
        self
    }

    pub fn with_prev_hash(&mut self, prev_hash: BlockHash) -> &mut Self {
        self.block.prev_hash = prev_hash;
        self
    }

    pub fn with_height(&mut self, height: u64) -> &mut Self {
        self.block.height = height;
        self
    }

    pub fn with_original_block_header(&mut self, original_block_header: BlockHeader) -> &mut Self {
        self.block.original_block_header = Some(original_block_header);
        self
    }

    pub fn with_miner_wallet_address(&mut self, miner_wallet_address: TariAddress) -> &mut Self {
        self.block.miner_wallet_address = Some(miner_wallet_address);
        self
    }

    pub fn build(&mut self) -> Block {
        self.block.hash = self.block.generate_hash();
        self.block.clone()
    }
}

// #[cfg(test)]
// mod tests {
//     use tari_utilities::epoch_time::EpochTime;
//
//     use crate::sharechain::block::Block;
//
//     #[test]
//     fn test_block_get_uncles_recursive() {
//         // prepare
//         let block1_uncle3 = Block::builder().with_timestamp(EpochTime::from(3)).with_height(1).build();
//         let mut block1_uncle2 = Block::builder().with_timestamp(EpochTime::from(3)).with_height(1).build();
//         block1_uncle2.add_uncle(block1_uncle3.clone());
//         let mut block1_uncle = Block::builder().with_timestamp(EpochTime::from(2)).with_height(1).build();
//         block1_uncle.add_uncle(block1_uncle2.clone());
//         let mut block1 = Block::builder().with_timestamp(EpochTime::from(1)).with_height(1).build();
//         block1.add_uncle(block1_uncle.clone());
//
//         // execute
//         let result = block1.uncles();
//
//         // assert
//         assert_eq!(result, vec![block1_uncle.clone(), block1_uncle2.clone(), block1_uncle3.clone()]);
//     }
// }
