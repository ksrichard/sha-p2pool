// Copyright 2024 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use blake2::Blake2b;
use digest::consts::U32;
use log::info;
use serde::{Deserialize, Serialize};
use tari_common_types::{tari_address::TariAddress, types::BlockHash};
use tari_common_types::types::FixedHash;
use tari_core::{
    blocks::{BlockHeader, BlocksHashDomain},
    consensus::DomainSeparatedConsensusHasher,
};
use tari_utilities::epoch_time::EpochTime;
use tari_utilities::hex::Hex;

use crate::impl_conversions;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Block {
    hash: BlockHash,
    timestamp: EpochTime,
    prev_hash: BlockHash,
    height: u64,
    original_block_header: BlockHeader,
    proof_hash: Vec<u8>,
    miner_wallet_address: Option<TariAddress>,
    sent_to_main_chain: bool,
}
impl_conversions!(Block);

#[allow(dead_code)]
impl Block {
    pub fn builder() -> BlockBuilder {
        BlockBuilder::new()
    }

    pub fn generate_hash(&self) -> BlockHash {
        let mut hasher = DomainSeparatedConsensusHasher::<BlocksHashDomain, Blake2b<U32>>::new("block")
            .chain(&self.prev_hash.to_hex())
            .chain(&self.height);

        if self.miner_wallet_address.is_some() {
            hasher = hasher.chain(&self.miner_wallet_address.clone().unwrap().to_base58());
        }

        hasher.chain(&self.original_block_header).finalize().into()
    }

    pub fn generate_mining_hash(&self) -> FixedHash {
        info!("[generate_mining_hash] - {:?} + {:?}", self.height, self.miner_wallet_address.clone().unwrap().to_base58());
        let mut hasher = DomainSeparatedConsensusHasher::<BlocksHashDomain, Blake2b<U32>>::new("mining")
            // .chain(&self.prev_hash.to_hex())
            .chain(&self.height);

        if self.miner_wallet_address.is_some() {
            hasher = hasher.chain(&self.miner_wallet_address.clone().unwrap().to_base58());
        }
        // .chain(&self.height) // TODO: revisit
        // .chain(shares_hash) // TODO: revisit
        hasher.finalize().into()
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

    pub fn original_block_header(&self) -> &BlockHeader {
        &self.original_block_header
    }

    pub fn hash(&self) -> BlockHash {
        self.hash
    }

    pub fn set_sent_to_main_chain(&mut self, sent_to_main_chain: bool) {
        self.sent_to_main_chain = sent_to_main_chain;
    }

    pub fn sent_to_main_chain(&self) -> bool {
        self.sent_to_main_chain
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }
    pub fn miner_wallet_address(&self) -> &Option<TariAddress> {
        &self.miner_wallet_address
    }
    pub fn proof_hash(&self) -> &Vec<u8> {
        &self.proof_hash
    }
}

pub struct BlockBuilder {
    block: Block,
}

impl BlockBuilder {
    pub fn new() -> Self {
        Self {
            block: Block {
                hash: Default::default(),
                timestamp: EpochTime::now(),
                prev_hash: Default::default(),
                height: 0,
                original_block_header: BlockHeader::new(0),
                miner_wallet_address: Default::default(),
                sent_to_main_chain: false,
                proof_hash: vec![],
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
        self.block.original_block_header = original_block_header;
        self
    }

    pub fn with_miner_wallet_address(&mut self, miner_wallet_address: TariAddress) -> &mut Self {
        self.block.miner_wallet_address = Some(miner_wallet_address);
        self
    }

    pub fn with_proof_hash(&mut self, proof_hash: Vec<u8>) -> &mut Self {
        self.block.proof_hash = proof_hash;
        self
    }

    pub fn build(&mut self) -> Block {
        self.block.hash = self.block.generate_hash();
        self.block.clone()
    }
}
