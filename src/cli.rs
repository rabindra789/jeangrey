//! Command-line interface for JeanGrey MVP-1.
//!
//! Commands:
//!
//! - `init`        create a device identity and configuration.
//! - `node`        run the interactive node (REPL).
//! - `lookup`      one-shot: discover a peer's authenticated addresses.
//! - `send` one-shot: discover, connect and send one message (waits for
//!   the authenticated acknowledgement).
//! - `peers`       one-shot: run briefly and print discovered peers.
//!
//! Data lives under `--data-dir` (default `~/.jeangrey`).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use libp2p::PeerId;
use tokio::sync::{mpsc, oneshot};

use crate::identity::{short_id, DeviceIdentity};
use crate::node::{self, BootstrapPeer, Node, NodeCommand, NodeOptions};
use crate::storage::{NodeConfig, Storage};

const DEFAULT_PORT: u16 = 9000;
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
const SESSION_TIMEOUT: Duration = Duration::from_secs(20);
const ACK_TIMEOUT: Duration = Duration::from_secs(10);
const PEERS_RUN: Duration = Duration::from_secs(20);

#[derive(Parser)]
#[command(
    name = "jeangrey",
    version,
    about = "Post-quantum secure decentralized messaging (LAN implementation)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Options shared by every command.
#[derive(Args, Clone)]
pub struct Common {
    /// Data directory (default: ~/.jeangrey).
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
    /// TCP port to listen on (default: from config, or 9000).
    #[arg(long)]
    pub listen_port: Option<u16>,
    /// Bootstrap peer as PEERID@/ip4/.../tcp/PORT (repeatable).
    #[arg(long = "bootstrap")]
    pub bootstrap: Vec<String>,
    /// Circuit relay v2 server for NAT traversal coordination as
    /// PEERID@/ip4/.../tcp/PORT (M2.4). Both peers must share a relay.
    #[arg(long = "relay")]
    pub relay: Vec<String>,
    /// Serve as a circuit relay v2 server (M2.4). Requires a publicly
    /// reachable address.
    #[arg(long = "relay-server")]
    pub relay_server: bool,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create a device identity.
    Init {
        #[command(flatten)]
        common: Common,
        /// Display name for this device/user.
        #[arg(long)]
        name: String,
    },
    /// Run the interactive node.
    Node {
        #[command(flatten)]
        common: Common,
    },
    /// Discover a peer's authenticated LAN addresses.
    Lookup {
        #[command(flatten)]
        common: Common,
        /// Peer ID (base58) to look up.
        peer: String,
    },
    /// Send one message and wait for the authenticated acknowledgement.
    Send {
        #[command(flatten)]
        common: Common,
        /// Peer ID (base58) to send to.
        peer: String,
        /// Message text.
        text: String,
    },
    /// Run briefly and print discovered peers.
    Peers {
        #[command(flatten)]
        common: Common,
    },
}

fn default_data_dir() -> PathBuf {
    std::env::var_os("JEANGREY_DATA_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::home_dir().map(|h| h.join(".jeangrey")))
        .unwrap_or_else(|| PathBuf::from(".jeangrey"))
}

fn build_options(common: &Common) -> Result<NodeOptions> {
    let storage = Storage::new(common.data_dir.clone().unwrap_or_else(default_data_dir));
    let config = storage.load_config()?;
    let listen_port = common
        .listen_port
        .or(Some(config.listen_port))
        .unwrap_or(DEFAULT_PORT);
    let mut bootstrap = Vec::new();
    for s in &common.bootstrap {
        bootstrap.push(BootstrapPeer::parse(s).map_err(anyhow::Error::msg)?);
    }
    let mut relay = None;
    for s in &common.relay {
        relay = Some(BootstrapPeer::parse(s).map_err(anyhow::Error::msg)?);
    }
    Ok(NodeOptions {
        listen_port,
        bootstrap,
        external_ips: Vec::new(),
        relay,
        relay_server: common.relay_server,
    })
}

fn load_identity(common: &Common) -> Result<DeviceIdentity> {
    let storage = Storage::new(common.data_dir.clone().unwrap_or_else(default_data_dir));
    let identity = storage
        .load_identity()?
        .ok_or_else(|| anyhow!("no identity found; run `jeangrey init --name <name>` first"))?;
    Ok(identity)
}

fn new_node(common: &Common) -> Result<Node> {
    let options = build_options(common)?;
    let storage = Storage::new(common.data_dir.clone().unwrap_or_else(default_data_dir));
    storage.ensure()?;
    let identity = load_identity(common)?;
    let node = Node::new(identity, storage, options)?;
    Ok(node)
}

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init { common, name } => cmd_init(&common, &name),
        Command::Node { common } => cmd_node(&common).await,
        Command::Lookup { common, peer } => cmd_lookup(&common, &peer).await,
        Command::Send { common, peer, text } => cmd_send(&common, &peer, &text).await,
        Command::Peers { common } => cmd_peers(&common).await,
    }
}

fn cmd_init(common: &Common, name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("name must not be empty");
    }
    if name.len() > crate::handshake::MAX_USER_NAME {
        bail!(
            "name too long (max {} chars)",
            crate::handshake::MAX_USER_NAME
        );
    }
    let data_dir = common.data_dir.clone().unwrap_or_else(default_data_dir);
    let storage = Storage::new(data_dir.clone());
    if storage.load_identity()?.is_some() {
        bail!("identity already exists in {}", data_dir.display());
    }
    let identity = DeviceIdentity::generate(name);
    storage.save_identity(&identity)?;
    let config = NodeConfig {
        listen_port: common.listen_port.unwrap_or(DEFAULT_PORT),
    };
    storage.save_config(&config)?;
    println!("identity created");
    println!("  user:        {name} (id {})", identity.user.short_id());
    println!("  device peer: {}", identity.peer_id);
    println!("  short:       {}", short_id(&identity.peer_id));
    println!("  data dir:    {}", data_dir.display());
    println!();
    println!("To start:  jeangrey node");
    Ok(())
}

async fn cmd_node(common: &Common) -> Result<()> {
    let mut node = new_node(common)?;
    let (tx, rx) = mpsc::channel::<NodeCommand>(16);

    // REPL task: reads stdin lines and forwards commands.
    let repl = async move {
        use tokio::io::AsyncBufReadExt;
        let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
        println!("jeangrey interactive node. Commands:");
        println!("  send <peer-id> <text>   send a message");
        println!("  lookup <peer-id>        discover a peer's addresses");
        println!("  peers                   list established sessions");
        println!("  quit                    exit");
        loop {
            let line = match lines.next_line().await {
                Ok(Some(l)) => l,
                _ => break,
            };
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.splitn(3, ' ');
            match (parts.next(), parts.next(), parts.next()) {
                (Some("quit"), _, _) | (Some("exit"), _, _) => {
                    let _ = tx.send(NodeCommand::Quit).await;
                    break;
                }
                (Some("peers"), _, _) => {
                    let (reply, rx) = oneshot::channel();
                    if tx.send(NodeCommand::Peers { reply }).await.is_err() {
                        break;
                    }
                    match rx.await {
                        Ok(peers) if peers.is_empty() => {
                            println!("no sessions established yet");
                        }
                        Ok(peers) => {
                            println!("established sessions (path):");
                            for (name, peer, path) in peers {
                                println!("  {name}  {peer}  [{path}]");
                            }
                        }
                        Err(_) => println!("node went away"),
                    }
                }
                (Some("lookup"), Some(peer), _) => match peer.parse::<PeerId>() {
                    Ok(peer) => {
                        let (reply, rx) = oneshot::channel();
                        if tx.send(NodeCommand::Lookup { peer, reply }).await.is_err() {
                            break;
                        }
                        match rx.await {
                            Ok(records) if records.is_empty() => {
                                println!("no verified records found for {peer}");
                            }
                            Ok(records) => {
                                for r in records {
                                    println!(
                                        "{}  ({} addr(s), issued {}s ago)",
                                        r.peer_id,
                                        r.addrs.len(),
                                        r.issued_at
                                    );
                                    for a in &r.addrs {
                                        println!("    {a}");
                                    }
                                }
                            }
                            Err(_) => println!("node went away"),
                        }
                    }
                    Err(_) => println!("invalid peer id: {peer}"),
                },
                (Some("send"), Some(peer), Some(text)) => match peer.parse::<PeerId>() {
                    Ok(peer) => {
                        let (reply, rx) = oneshot::channel();
                        if tx
                            .send(NodeCommand::Send {
                                peer,
                                text: text.to_string(),
                                reply,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                        match rx.await {
                            Ok(Ok(msg_id)) => {
                                println!("sent (id {msg_id}); awaiting acknowledgement...")
                            }
                            Ok(Err(e)) => println!("send failed: {e}"),
                            Err(_) => println!("node went away"),
                        }
                    }
                    Err(_) => println!("invalid peer id: {peer}"),
                },
                (Some("help"), _, _) => {
                    println!("send <peer-id> <text> | lookup <peer-id> | peers | quit");
                }
                _ => println!("unknown command (try: help)"),
            }
        }
    };

    let repl_task = tokio::spawn(repl);
    node::run_interactive(&mut node, rx).await;
    let _ = repl_task.await;
    Ok(())
}

async fn cmd_lookup(common: &Common, peer: &str) -> Result<()> {
    let peer_id = peer.parse::<PeerId>().context("invalid peer id")?;
    let mut node = new_node(common)?;
    let _ = node.lookup(peer_id);
    node.wait_for(|_| false, LOOKUP_TIMEOUT).await;
    let discovered = std::mem::take(&mut node.records)
        .into_values()
        .collect::<Vec<_>>();
    if discovered.is_empty() {
        println!("no verified record found for {peer_id}");
        return Ok(());
    }
    for r in discovered {
        println!("{}", r.peer_id);
        for a in &r.addrs {
            println!("  {a}");
        }
    }
    Ok(())
}

async fn cmd_send(common: &Common, peer: &str, text: &str) -> Result<()> {
    let peer_id = peer.parse::<PeerId>().context("invalid peer id")?;
    let mut node = new_node(common)?;

    // 1. Discovery (if we don't already have a session).
    if !node.has_session(&peer_id) {
        let _ = node.lookup(peer_id);
        let found = node
            .wait_for(
                |ev| matches!(ev, node::BehaviourEvent::SessionEstablished { peer_id: p, .. } if *p == peer_id),
                LOOKUP_TIMEOUT,
            )
            .await;
        if found.is_none() {
            // The record may already be in the DHT and dialing may still be
            // in flight; give the session more time.
            let found = node
                .wait_for(
                    |ev| matches!(ev, node::BehaviourEvent::SessionEstablished { peer_id: p, .. } if *p == peer_id),
                    SESSION_TIMEOUT - LOOKUP_TIMEOUT,
                )
                .await;
            if found.is_none() {
                bail!("could not establish an authenticated session with {peer_id}");
            }
        }
    }

    // 2. Send and wait for the authenticated acknowledgement.
    let msg_id = node.send_message(peer_id, text.to_string());
    match node
        .wait_for(
            |ev| matches!(ev, node::BehaviourEvent::AckReceived { peer_id: p, msg_id: m, .. } if *p == peer_id && *m == msg_id),
            ACK_TIMEOUT,
        )
        .await
    {
        Some(_) => println!("delivered (id {msg_id})"),
        None => println!("no acknowledgement within {}s (id {msg_id})", ACK_TIMEOUT.as_secs()),
    }
    Ok(())
}

async fn cmd_peers(common: &Common) -> Result<()> {
    let mut node = new_node(common)?;
    println!("discovering peers for {}s...", PEERS_RUN.as_secs());
    node.run_for(PEERS_RUN).await;
    // M2.4: report AutoNAT reachability when known.
    println!(
        "nat reachability: {}",
        match node.nat_status() {
            "public" => "public (directly reachable)",
            "private" => "private (behind NAT)",
            _ => "unknown (no probes yet)",
        }
    );
    if node.serves_relay() {
        println!("this node serves circuit relay reservations");
    }
    let connected = node.connected_peers();
    if !connected.is_empty() {
        println!("connected peers (path):");
        let paths = node.peer_paths();
        for p in connected {
            let path = paths.get(&p).map(|x| x.label()).unwrap_or("unknown");
            println!("  {}  [{path}]", short_id(&p));
        }
    } else {
        println!("no peers connected");
    }
    let sessions = node.session_peers();
    if sessions.is_empty() {
        println!("no sessions established");
        return Ok(());
    }
    println!("established sessions:");
    for p in sessions {
        println!("  {}", p);
    }
    Ok(())
}
