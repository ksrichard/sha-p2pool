use std::convert::Infallible;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::{AddrParseError, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use libp2p::{gossipsub, mdns, multiaddr, noise, PeerId, Swarm, tcp, TransportError, yamux};
use libp2p::futures::StreamExt;
use libp2p::mdns::tokio::Tokio;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use log::{error, info};
use minotari_app_grpc::tari_rpc::base_node_server::BaseNodeServer;
use minotari_app_grpc::tari_rpc::sha_p2_pool_server::ShaP2PoolServer;
use thiserror::Error;
use tokio::{io, io::AsyncBufReadExt, select};

use crate::server::{config, grpc, p2p};
use crate::server::grpc::base_node::TariBaseNodeGrpc;
use crate::server::grpc::error::TonicError;
use crate::server::grpc::p2pool::ShaP2PoolGrpc;
use crate::server::p2p::{ServerNetworkBehaviour, ServerNetworkBehaviourEvent};

#[derive(Error, Debug)]
pub enum Error {
    #[error("LibP2P error: {0}")]
    LibP2P(#[from] LibP2PError),
    #[error("gRPC error: {0}")]
    GRPC(#[from] grpc::error::Error),
    #[error("Socket address parse error: {0}")]
    AddrParse(#[from] AddrParseError),
}

#[derive(Error, Debug)]
pub enum LibP2PError {
    #[error("Noise error: {0}")]
    Noise(#[from] noise::Error),
    #[error("Multi address parse error: {0}")]
    MultiAddrParse(#[from] multiaddr::Error),
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError<std::io::Error>),
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Behaviour error: {0}")]
    Behaviour(String),
}

/// Server represents the server running all the necessary components for sha-p2pool.
pub struct Server {
    config: config::Config,
    swarm: Swarm<ServerNetworkBehaviour>,
    base_node_grpc_service: BaseNodeServer<TariBaseNodeGrpc>,
    p2pool_grpc_service: ShaP2PoolServer<ShaP2PoolGrpc>,
}

impl Server {
    pub async fn new(config: config::Config) -> Result<Self, Error> {
        let swarm = p2p::swarm(&config)?;
        let base_node_grpc_service = TariBaseNodeGrpc::new(config.base_node_address.clone()).await.map_err(Error::GRPC)?;
        let base_node_grpc_server = BaseNodeServer::new(base_node_grpc_service);

        let p2pool_grpc_service = ShaP2PoolGrpc::new(config.base_node_address.clone()).await.map_err(Error::GRPC)?;
        let p2pool_server = ShaP2PoolServer::new(p2pool_grpc_service);

        Ok(Self { config, swarm, base_node_grpc_service: base_node_grpc_server, p2pool_grpc_service: p2pool_server })
    }

    pub async fn start_grpc(
        base_node_service: BaseNodeServer<TariBaseNodeGrpc>,
        p2pool_service: ShaP2PoolServer<ShaP2PoolGrpc>,
        grpc_port: u16,
    ) -> Result<(), Error> {
        info!("Starting gRPC server on port {}!", &grpc_port);

        tonic::transport::Server::builder()
            .add_service(base_node_service)
            .add_service(p2pool_service)
            .serve(
                SocketAddr::from_str(
                    format!("0.0.0.0:{}", grpc_port).as_str()
                ).map_err(Error::AddrParse)?
            )
            .await
            .map_err(|err| {
                error!("GRPC encountered an error: {:?}", err);
                Error::GRPC(grpc::error::Error::Tonic(TonicError::Transport(err)))
            })?;

        info!("gRPC server stopped!");

        Ok(())
    }

    pub async fn start(&mut self) -> Result<(), Error> {
        self.swarm
            .listen_on(
                format!("/ip4/0.0.0.0/tcp/{}", self.config.p2p_port)
                    .parse()
                    .map_err(|e| Error::LibP2P(LibP2PError::MultiAddrParse(e)))?,
            )
            .map_err(|e| Error::LibP2P(LibP2PError::Transport(e)))?;

        info!("Starting Tari SHA-3 mining P2Pool...");

        // grpc serve
        let base_node_grpc_service = self.base_node_grpc_service.clone();
        let p2pool_grpc_service = self.p2pool_grpc_service.clone();
        let grpc_port = self.config.grpc_port;
        tokio::spawn(async move {
            match Self::start_grpc(base_node_grpc_service, p2pool_grpc_service, grpc_port).await {
                Ok(_) => {}
                Err(error) => {
                    error!("GRPC Server encountered an error: {:?}", error);
                }
            }
        });

        // main loop
        loop {
            select! {
                 next = self.swarm.select_next_some() => match next {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("Listening on {address:?}");
                    },
                    SwarmEvent::Behaviour(event) => match event {
                        ServerNetworkBehaviourEvent::Mdns(mdns_event) => match mdns_event {
                          mdns::Event::Discovered(peers) => {
                            for (peer, addr) in peers {
                                info!("Discovered new peer {} at {}", peer, addr);
                                self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                            }
                          },
                            mdns::Event::Expired(peers) => {
                                for (peer, addr) in peers {
                                    info!("Expired peer {} at {}", peer, addr);
                                    self.swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
                                }
                            },
                        },
                        ServerNetworkBehaviourEvent::Gossipsub(event) => {
                            info!("GOSSIP: {event:?}");
                        },
                    },
                 _ => {}
                }
            }
        }
    }
}
