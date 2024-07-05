// Copyright 2024 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use std::{
    sync::RwLock,
    time::{Duration, Instant},
};
use std::ops::Deref;

use libp2p::PeerId;
use log::debug;
use moka::future::{Cache, CacheBuilder};
use tari_core::proof_of_work::AccumulatedDifficulty;

use crate::server::p2p::messages::PeerInfo;
use crate::sharechain::block::Block;

const LOG_TARGET: &str = "peer_store";

#[derive(Copy, Clone, Debug)]
pub struct PeerStoreConfig {
    pub peer_record_ttl: Duration,
}

impl Default for PeerStoreConfig {
    fn default() -> Self {
        Self {
            peer_record_ttl: Duration::from_secs(10),
        }
    }
}

/// A record in peer store that holds all needed info of a peer.
#[derive(Clone, Debug)]
pub struct PeerStoreRecord {
    peer_info: PeerInfo,
    created: Instant,
}

impl PeerStoreRecord {
    pub fn new(peer_info: PeerInfo) -> Self {
        Self {
            peer_info,
            created: Instant::now(),
        }
    }
}

/// Tip of height from known peers.
#[derive(Clone, Debug)]
pub struct PeerStoreStrongestChain {
    pub peer_id: PeerId,
    pub chain_difficulty: AccumulatedDifficulty,
}

impl PeerStoreStrongestChain {
    pub fn new(peer_id: PeerId, chain_difficulty: AccumulatedDifficulty) -> Self {
        Self { peer_id, chain_difficulty }
    }
}

/// A peer store, which stores all the known peers (from broadcasted [`PeerInfo`] messages) in-memory.
/// This implementation is thread safe and async, so an [`Arc<PeerStore>`] is enough to be used to share.
pub struct PeerStore {
    inner: Cache<PeerId, PeerStoreRecord>,
    // Max time to live for the items to avoid non-existing peers in list.
    ttl: Duration,
    // Peer with the strongest share chain.
    strongest_chain: RwLock<Option<PeerStoreStrongestChain>>,
}

impl PeerStore {
    /// Constructs a new peer store with config.
    pub fn new(config: &PeerStoreConfig) -> Self {
        Self {
            inner: CacheBuilder::new(100_000)
                .time_to_live(config.peer_record_ttl * 2)
                .build(),
            ttl: config.peer_record_ttl,
            strongest_chain: RwLock::new(None),
        }
    }

    /// Add a new peer to store.
    /// If a peer already exists, just replaces it.
    pub async fn add(&self, peer_id: PeerId, peer_info: PeerInfo) {
        self.inner.insert(peer_id, PeerStoreRecord::new(peer_info)).await;
        self.set_tip_of_chain().await;
    }

    /// Returns count of peers.
    /// Note: it is needed to calculate number of validations needed to make sure a new block is valid.
    pub async fn peer_count(&self) -> u64 {
        self.inner.entry_count()
    }

    /// Sets the actual highest block height with peer.
    async fn set_tip_of_chain(&self) {
        if let Some((k, v)) = self
            .inner
            .iter()
            .max_by(|(_k1, v1), (_k2, v2)| v1.peer_info.chain_difficulty.cmp(
                &v2.peer_info.chain_difficulty,
            ))
        {
            // save result
            if let Ok(mut strongest_chain_opt) = self.strongest_chain.write() {
                if strongest_chain_opt.is_none() {
                    let _ = strongest_chain_opt.insert(PeerStoreStrongestChain::new(*k, v.peer_info.chain_difficulty));
                } else {
                    let strongest_chain = strongest_chain_opt.as_mut().unwrap();
                    strongest_chain.peer_id = *k;
                    strongest_chain.chain_difficulty = v.peer_info.chain_difficulty;
                }
            }
        }
    }

    /// Returns peer with the strongest share chain.
    pub async fn strongest_chain(&self) -> Option<PeerStoreStrongestChain> {
        if let Ok(result) = self.strongest_chain.read() {
            if result.is_some() {
                return Some(result.as_ref().unwrap().clone());
            }
        }
        None
    }

    /// Clean up expired peers.
    pub async fn cleanup(&self) -> Vec<PeerId> {
        let mut expired_peers = vec![];

        for (k, v) in self.inner.iter() {
            debug!(target: LOG_TARGET, "{:?} -> {:?}", k, v);
            let elapsed = v.created.elapsed();
            let expired = elapsed.gt(&self.ttl);
            debug!(target: LOG_TARGET, "{:?} ttl elapsed: {:?} <-> {:?}, Expired: {:?}", k, elapsed, &self.ttl, expired);
            if expired {
                expired_peers.push(*k);
                self.inner.remove(k.as_ref()).await;
            }
        }

        self.set_tip_of_chain().await;

        expired_peers
    }
}
