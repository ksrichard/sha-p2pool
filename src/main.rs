// Copyright 2024 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use std::path::PathBuf;

use clap::{
    builder::{Styles, styling::AnsiColor},
    Parser,
};
use tari_common::initialize_logging;
use tari_utilities::hex::Hex;

use crate::server::p2p;
use crate::sharechain::in_memory::InMemoryShareChain;

mod server;
mod sharechain;

fn cli_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::BrightYellow.on_default())
        .usage(AnsiColor::BrightYellow.on_default())
        .literal(AnsiColor::BrightGreen.on_default())
        .placeholder(AnsiColor::BrightCyan.on_default())
        .error(AnsiColor::BrightRed.on_default())
        .invalid(AnsiColor::BrightRed.on_default())
        .valid(AnsiColor::BrightGreen.on_default())
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Parser)]
#[command(version)]
#[command(styles = cli_styles())]
#[command(about = "⛏ Decentralized mining pool for Tari network ⛏", long_about = None)]
struct Cli {
    base_dir: Option<PathBuf>,

    /// (Optional) gRPC port to use.
    #[arg(short, long, value_name = "grpc-port")]
    grpc_port: Option<u16>,

    /// (Optional) p2p port to use. It is used to connect p2pool nodes.
    #[arg(short, long, value_name = "p2p-port")]
    p2p_port: Option<u16>,

    /// (Optional) stats server port to use.
    #[arg(long, value_name = "stats-server-port")]
    stats_server_port: Option<u16>,

    /// (Optional) seed peers.
    /// Any amount of seed peers can be added to join a p2pool network.
    ///
    /// Please note that these addresses must be in libp2p multi address format and must contain peer ID!
    ///
    /// e.g.: /ip4/127.0.0.1/tcp/52313/p2p/12D3KooWCUNCvi7PBPymgsHx39JWErYdSoT3EFPrn3xoVff4CHFu
    #[arg(short, long, value_name = "seed-peers")]
    seed_peers: Option<Vec<String>>,

    /// Starts the node as a stable peer.
    ///
    /// Identity of the peer will be saved locally (to --private-key-location)
    /// and ID of the Peer remains the same.
    #[arg(long, value_name = "stable-peer", default_value_t = false)]
    stable_peer: bool,

    /// Private key folder.
    ///
    /// Needs --stable-peer to be set.
    #[arg(
        long,
        value_name = "private-key-folder",
        requires = "stable_peer",
        default_value = "."
    )]
    private_key_folder: PathBuf,

    /// Mining disabled
    ///
    /// In case it is set, the node will only handle p2p operations,
    /// will be syncing with share chain, but not starting gRPC services and no Tari base node needed.
    /// By setting this it can be used as a stable node for routing only.
    #[arg(long, value_name = "mining-disabled", default_value_t = false)]
    mining_disabled: bool,

    /// mDNS disabled
    ///
    /// If set, mDNS local peer discovery is disabled.
    #[arg(long, value_name = "mdns-disabled", default_value_t = false)]
    mdns_disabled: bool,

    /// Stats server disabled
    ///
    /// If set, local stats HTTP server is disabled.
    #[arg(long, value_name = "stats-server-disabled", default_value_t = false)]
    stats_server_disabled: bool,

    /// Generate identity
    ///
    /// If set, sha_p2pool will only generate a private key in `--private-key-folder`
    /// and output a stable peer ID, that could be used later when running as a stable peer.
    #[arg(long, value_name = "generate-identity", default_value_t = false)]
    generate_identity: bool,
}

impl Cli {
    pub fn base_dir(&self) -> PathBuf {
        self.base_dir
            .clone()
            .unwrap_or_else(|| dirs::home_dir().unwrap().join(".tari/p2pool"))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // generate identity
    if cli.generate_identity {
        let result = p2p::util::generate_identity().await?;
        print!("{}", serde_cbor::to_vec(&result)?.to_hex());
        return Ok(());
    }

    // logger setup
    if let Err(e) = initialize_logging(
        &cli.base_dir().join("configs/logs.yml"),
        &cli.base_dir(),
        include_str!("../log4rs_sample.yml"),
    ) {
        eprintln!("{}", e);
        return Err(e.into());
    }

    let mut config_builder = server::Config::builder();
    if let Some(grpc_port) = cli.grpc_port {
        config_builder.with_grpc_port(grpc_port);
    }
    if let Some(p2p_port) = cli.p2p_port {
        config_builder.with_p2p_port(p2p_port);
    }
    if let Some(seed_peers) = cli.seed_peers.clone() {
        config_builder.with_seed_peers(seed_peers);
    }
    config_builder.with_stable_peer(cli.stable_peer);
    config_builder.with_private_key_folder(cli.private_key_folder.clone());
    config_builder.with_mining_enabled(!cli.mining_disabled);
    config_builder.with_mdns_enabled(!cli.mdns_disabled);
    config_builder.with_stats_server_enabled(!cli.stats_server_disabled);
    if let Some(stats_server_port) = cli.stats_server_port {
        config_builder.with_stats_server_port(stats_server_port);
    }

    // server start
    let config = config_builder.build();
    let share_chain = InMemoryShareChain::default();
    let mut server = server::Server::new(config, share_chain).await?;
    server.start().await?;
    Ok(())
}
