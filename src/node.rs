//! The JeanGrey node: swarm assembly, DHT discovery, and the event loop.
//!
//! Composition: `NodeBehaviour = SessionBehaviour + kad::Behaviour`. The
//! Kademlia DHT is used strictly for discovery of address records; all
//! application data is exchanged over authenticated JeanGrey sessions.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::core::upgrade::Version;
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{self, QueryId, RecordKey};
use libp2p::swarm::{Config as SwarmConfig, NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::{Multiaddr, PeerId, Transport as _};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::identity::{short_id, DeviceIdentity};
use crate::records::{self, AddrRecord, VerifiedRecord};
use crate::storage::Storage;
use crate::transport::SessionBehaviour;

pub use crate::transport::BehaviourEvent;

/// JeanGrey Kademlia protocol name (distinct from the transport protocol).
pub const KAD_PROTOCOL: &str = "/jeangrey/kad/1.0.0";
/// How often our address record is re-published into the DHT.
pub const PUBLISH_INTERVAL: Duration = Duration::from_secs(30);
/// Maximum times a discovery lookup is re-issued before giving up.
pub const MAX_LOOKUP_ATTEMPTS: u32 = 10;
/// Delay between lookup retries (gives the DHT time to learn the record).
pub const LOOKUP_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Composed network behaviour.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "NodeEvent", prelude = "libp2p::swarm::derive_prelude")]
pub struct NodeBehaviour {
    /// JeanGrey sessions (handshake + messaging).
    pub session: SessionBehaviour,
    /// Kademlia DHT for discovery.
    pub kad: kad::Behaviour<MemoryStore>,
}

/// Events produced by the composed behaviour.
#[derive(Debug)]
pub enum NodeEvent {
    Session(BehaviourEvent),
    Kad(kad::Event),
}

impl From<BehaviourEvent> for NodeEvent {
    fn from(e: BehaviourEvent) -> Self {
        NodeEvent::Session(e)
    }
}

impl From<kad::Event> for NodeEvent {
    fn from(e: kad::Event) -> Self {
        NodeEvent::Kad(e)
    }
}

/// Bootstrap peer: `peer_id` at `addrs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapPeer {
    pub peer_id: String,
    pub addrs: Vec<String>,
}

impl BootstrapPeer {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (peer_id, rest) = s.split_once('@').ok_or_else(|| {
            "expected PEERID@MULTIADDR (e.g. Qm...@/ip4/10.0.0.5/tcp/9000)".to_string()
        })?;
        let peer_id = peer_id
            .parse::<PeerId>()
            .map_err(|_| format!("invalid peer id: {peer_id}"))?;
        let addr = rest
            .parse::<Multiaddr>()
            .map_err(|_| format!("invalid multiaddr: {rest}"))?;
        Ok(BootstrapPeer {
            peer_id: peer_id.to_base58(),
            addrs: vec![addr.to_string()],
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id.parse().expect("validated at parse time")
    }

    pub fn multiaddrs(&self) -> Vec<Multiaddr> {
        self.addrs.iter().filter_map(|a| a.parse().ok()).collect()
    }
}

/// Configuration for a node run.
#[derive(Debug, Clone)]
pub struct NodeOptions {
    pub listen_port: u16,
    pub bootstrap: Vec<BootstrapPeer>,
}

/// One in-flight discovery lookup.
#[derive(Debug, Clone)]
struct LookupRequest {
    peer: PeerId,
    attempts: u32,
}

/// A lookup scheduled for retry.
struct LookupRetry {
    peer: PeerId,
    attempts: u32,
    next_at: Instant,
}

/// A running JeanGrey node.
pub struct Node {
    pub swarm: Swarm<NodeBehaviour>,
    pub identity: Arc<DeviceIdentity>,
    pub storage: Storage,
    our_record: AddrRecord,
    last_publish: Instant,
    last_bootstrap: Instant,
    connected: HashSet<PeerId>,
    /// Bootstrap peers whose transport Peer ID is not yet known.
    bootstrap_pending: Vec<BootstrapPeer>,
    /// Bootstrap peers whose transport Peer ID has been learned.
    bootstrap_mapped: HashSet<PeerId>,
    /// In-flight discovery queries.
    pending_lookups: HashMap<QueryId, LookupRequest>,
    /// Failed lookups waiting for their retry window.
    retry_lookups: VecDeque<LookupRetry>,
    /// Peers discovered through verified DHT records.
    pub discovered: Vec<VerifiedRecord>,
}

impl Node {
    pub fn new(
        identity: DeviceIdentity,
        storage: Storage,
        options: NodeOptions,
    ) -> Result<Self, NodeError> {
        let identity = Arc::new(identity);

        // Transport: TCP + plaintext (the JeanGrey layer provides all real
        // authentication) + yamux multiplexing.
        let transport =
            libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::new().nodelay(true))
                .upgrade(Version::V1)
                .authenticate(libp2p::plaintext::Config::new(&identity.transport_keypair))
                .multiplex(libp2p::yamux::Config::default())
                .boxed();

        let session = SessionBehaviour::new(identity.clone());
        let mut kad_config = kad::Config::new(libp2p::swarm::StreamProtocol::new(KAD_PROTOCOL));
        kad_config.set_query_timeout(Duration::from_secs(20));
        // The DHT/routing layer speaks the TRANSPORT Peer ID (libp2p requires
        // the swarm local id to match the plaintext signing keypair). The
        // device Peer ID remains the identity users address; the signed
        // address record binds the two.
        let transport_peer_id = identity.transport_peer_id();
        let mut kad = kad::Behaviour::with_config(
            transport_peer_id,
            MemoryStore::new(transport_peer_id),
            kad_config,
        );
        // Serve DHT records on every node. kad's default is client mode,
        // which denies inbound kad substreams until an external address is
        // confirmed — that never happens on a LAN, leaving the DHT dead.
        kad.set_mode(Some(kad::Mode::Server));
        let behaviour = NodeBehaviour { session, kad };
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            transport_peer_id,
            SwarmConfig::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(60)),
        );

        // Listen on the configured port.
        let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", options.listen_port)
            .parse()
            .map_err(NodeError::Address)?;
        swarm
            .listen_on(listen_addr)
            .map_err(|e| NodeError::Listen(e.to_string()))?;

        // Bootstrap peers are dialed with unknown transport Peer ID; the
        // transport id is learned when the connection establishes (the
        // device/transport binding is then recorded and the DHT is seeded).
        // Seeding the DHT with the *device* id would make every kad dial fail
        // with an unexpected-peer-id error, because the wire presents the
        // transport id.
        let our_record = records::sign_addr_record(&identity, &[]);
        let node = Node {
            swarm,
            identity,
            storage,
            our_record,
            last_publish: Instant::now(),
            last_bootstrap: Instant::now(),
            connected: HashSet::new(),
            bootstrap_pending: options.bootstrap,
            bootstrap_mapped: HashSet::new(),
            pending_lookups: HashMap::new(),
            retry_lookups: VecDeque::new(),
            discovered: Vec::new(),
        };
        Ok(node)
    }

    pub fn our_listen_addrs(&self) -> Vec<Multiaddr> {
        self.swarm.listeners().cloned().collect()
    }

    /// Record the current listen addresses and re-publish to the DHT.
    pub fn publish_record(&mut self) {
        let addrs = self.our_listen_addrs();
        if addrs.is_empty() {
            return;
        }
        self.our_record = records::sign_addr_record(&self.identity, &addrs);
        let record = libp2p::kad::Record::new(
            RecordKey::new(&self.identity.peer_id.to_bytes()),
            self.our_record.to_bytes(),
        );
        match self
            .swarm
            .behaviour_mut()
            .kad
            .put_record(record, kad::Quorum::One)
        {
            Ok(_) => {
                tracing::debug!(node = %self.identity.user.user_name, addrs = addrs.len(), "published address record");
            }
            Err(e) => {
                tracing::warn!(node = %self.identity.user.user_name, error = %e, "could not publish record");
            }
        }
        self.last_publish = Instant::now();
    }

    /// Start (or restart) the DHT bootstrap.
    pub fn bootstrap_kad(&mut self) {
        match self.swarm.behaviour_mut().kad.bootstrap() {
            Ok(_) => {
                tracing::debug!(node = %self.identity.user.user_name, "kademlia bootstrap started");
            }
            Err(_) => {
                tracing::debug!(node = %self.identity.user.user_name, "no known peers to bootstrap with yet");
            }
        }
        self.last_bootstrap = Instant::now();
    }

    /// Look up the address record for `peer` in the DHT.
    pub fn lookup(&mut self, peer: PeerId) -> Option<QueryId> {
        let id = self
            .swarm
            .behaviour_mut()
            .kad
            .get_record(RecordKey::new(&peer.to_bytes()));
        self.pending_lookups
            .insert(id, LookupRequest { peer, attempts: 1 });
        Some(id)
    }

    /// Send a text message; returns the assigned message id.
    pub fn send_message(&mut self, peer: PeerId, text: String) -> u64 {
        self.swarm.behaviour_mut().session.send_message(peer, text)
    }

    /// Whether a session with `peer` is established.
    pub fn has_session(&self, peer: &PeerId) -> bool {
        self.swarm.behaviour().session.has_session(peer)
    }

    /// Peers with established sessions.
    pub fn session_peers(&self) -> Vec<PeerId> {
        self.swarm.behaviour().session.session_peers()
    }

    /// Connected peers (transport level).
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().copied().collect()
    }

    /// Dial a device directly. `transport` is the device's libp2p transport
    /// Peer ID (from its verified address record); `peer` is the device id.
    pub fn dial_peer(&mut self, peer: PeerId, transport: PeerId, addrs: Vec<Multiaddr>) {
        self.swarm
            .behaviour_mut()
            .session
            .connect(peer, transport, addrs);
    }

    fn on_kad_event(&mut self, event: kad::Event) {
        if let kad::Event::OutboundQueryProgressed { id, result, .. } = event {
            let Some(req) = self.pending_lookups.remove(&id) else {
                return;
            };
            match result {
                kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(peer_record))) => {
                    let key = peer_record.record.key.as_ref().to_vec();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    if let Ok(record) = AddrRecord::from_bytes(&peer_record.record.value) {
                        match records::verify_addr_record(&key, &record, now) {
                            Ok(verified) => {
                                tracing::info!(
                                    node = %self.identity.user.user_name,
                                    peer = %short_id(&verified.peer_id),
                                    device = %hex::encode(verified.device_uuid),
                                    addrs = verified.addrs.len(),
                                    "verified DHT address record"
                                );
                                // Discovery leads to connection: dial the
                                // authenticated address set via the transport id
                                // bound in the signed record.
                                self.dial_peer(
                                    verified.peer_id,
                                    verified.transport_peer,
                                    verified.addrs.clone(),
                                );
                                self.discovered.push(verified);
                            }
                            Err(e) => {
                                tracing::warn!(node = %self.identity.user.user_name, error = %e, "rejected DHT record");
                            }
                        }
                    } else {
                        tracing::warn!(node = %self.identity.user.user_name, "malformed DHT record");
                    }
                }
                kad::QueryResult::GetRecord(_) => {
                    // NotFound / Timeout / QuorumFailed: the record may not
                    // have been published yet, or the DHT had no peers when
                    // the query was issued. Retry a bounded number of times.
                    tracing::debug!(
                        node = %self.identity.user.user_name,
                        peer = %short_id(&req.peer),
                        attempts = req.attempts,
                        "lookup failed; scheduling retry"
                    );
                    if req.attempts < MAX_LOOKUP_ATTEMPTS {
                        self.retry_lookups.push_back(LookupRetry {
                            peer: req.peer,
                            attempts: req.attempts + 1,
                            next_at: Instant::now() + LOOKUP_RETRY_DELAY,
                        });
                    } else {
                        tracing::warn!(
                            node = %self.identity.user.user_name,
                            peer = %short_id(&req.peer),
                            "lookup gave up after retries; peer not found"
                        );
                    }
                }
                _ => {}
            }
        }
    }

    fn on_session_event(&mut self, event: BehaviourEvent) -> BehaviourEvent {
        match &event {
            BehaviourEvent::SessionEstablished {
                peer_id,
                connection_id,
                result,
            } => {
                tracing::info!(
                    node = %self.identity.user.user_name,
                    peer = %short_id(peer_id),
                    conn = ?connection_id,
                    user = %result.peer_hello.user_name,
                    device = %hex::encode(result.peer_hello.device_uuid),
                    "session established (ML-KEM + ML-DSA authenticated)"
                );
                let _ = self
                    .storage
                    .append_history(crate::storage::HistoryKind::Sent {
                        peer: peer_id.to_base58(),
                        msg_id: 0,
                        status: "session-established".into(),
                    });
            }
            BehaviourEvent::HandshakeFailed { peer_id, error } => {
                tracing::warn!(node = %self.identity.user.user_name, peer = %short_id(peer_id), error = %error, "connection failed");
                // Fail closed: drop the connection (by transport id). The id
                // reported here is the device id when known, else the
                // transport id itself.
                let transport = self
                    .swarm
                    .behaviour()
                    .session
                    .transport_of(peer_id)
                    .copied()
                    .unwrap_or(*peer_id);
                let _ = self.swarm.disconnect_peer_id(transport);
            }
            BehaviourEvent::MessageReceived {
                peer_id,
                msg_id,
                body,
                ts_ms,
            } => {
                let name = self
                    .swarm
                    .behaviour()
                    .session
                    .peer_name(peer_id)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| short_id(peer_id));
                tracing::info!(node = %self.identity.user.user_name, peer = %name, msg_id, ts = *ts_ms, "message: {body}");
                let _ = self
                    .storage
                    .append_history(crate::storage::HistoryKind::Received {
                        peer: peer_id.to_base58(),
                        msg_id: *msg_id,
                    });
            }
            BehaviourEvent::AckReceived {
                peer_id,
                msg_id,
                ack_seq,
            } => {
                tracing::info!(node = %self.identity.user.user_name, peer = %short_id(peer_id), msg_id, ack_seq, "acknowledged by peer");
                let _ = self
                    .storage
                    .append_history(crate::storage::HistoryKind::Sent {
                        peer: peer_id.to_base58(),
                        msg_id: *msg_id,
                        status: "delivered".into(),
                    });
            }
            BehaviourEvent::PeerConnected { peer_id } => {
                self.connected.insert(*peer_id);
            }
            BehaviourEvent::PeerDisconnected { peer_id } => {
                self.connected.remove(peer_id);
                tracing::info!(node = %self.identity.user.user_name, peer = %short_id(peer_id), "peer disconnected");
            }
        }
        event
    }

    /// Periodic maintenance, shared by all run loops.
    fn maintenance(&mut self) {
        if self.last_publish.elapsed() >= PUBLISH_INTERVAL {
            self.publish_record();
        }
        // Re-issue failed discovery lookups once their retry window elapses.
        let now = Instant::now();
        while let Some(retry) = self.retry_lookups.front() {
            if retry.next_at > now {
                break;
            }
            let retry = self.retry_lookups.pop_front().unwrap();
            let id = self
                .swarm
                .behaviour_mut()
                .kad
                .get_record(RecordKey::new(&retry.peer.to_bytes()));
            self.pending_lookups.insert(
                id,
                LookupRequest {
                    peer: retry.peer,
                    attempts: retry.attempts,
                },
            );
            tracing::debug!(
                node = %self.identity.user.user_name,
                peer = %short_id(&retry.peer),
                attempts = retry.attempts,
                "re-issuing discovery lookup"
            );
        }
        if self.swarm.connected_peers().count() == 0
            && self.last_bootstrap.elapsed() >= Duration::from_secs(5)
        {
            self.last_bootstrap = Instant::now();
            for bp in &self.bootstrap_pending {
                if !self.bootstrap_mapped.contains(&bp.peer_id()) {
                    self.swarm
                        .behaviour_mut()
                        .session
                        .connect_unknown(bp.multiaddrs());
                }
            }
        }
    }

    /// Handle one swarm event; returns the session event if there was one.
    fn handle_event(&mut self, event: SwarmEvent<NodeEvent>) -> Option<BehaviourEvent> {
        match event {
            SwarmEvent::Behaviour(NodeEvent::Session(ev)) => Some(self.on_session_event(ev)),
            SwarmEvent::Behaviour(NodeEvent::Kad(ev)) => {
                self.on_kad_event(ev);
                None
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!(node = %self.identity.user.user_name, %address, "listening");
                self.publish_record();
                None
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                connection_id,
                ..
            } => {
                // A bootstrap dial was issued with unknown transport Peer ID;
                // the established connection reveals it. Record the
                // device/transport binding, seed the DHT routing table, and
                // restart bootstrap queries.
                if let libp2p::core::ConnectedPoint::Dialer { address, .. } = &endpoint {
                    if let Some(bp) = self
                        .bootstrap_pending
                        .iter()
                        .find(|bp| bp.multiaddrs().iter().any(|a| a == address))
                    {
                        if self.bootstrap_mapped.insert(bp.peer_id()) {
                            self.swarm
                                .behaviour_mut()
                                .session
                                .map_transport(bp.peer_id(), peer_id);
                            self.swarm
                                .behaviour_mut()
                                .kad
                                .add_address(&peer_id, address.clone());
                            tracing::info!(
                                node = %self.identity.user.user_name,
                                peer = %short_id(&bp.peer_id()),
                                transport = %short_id(&peer_id),
                                %address,
                                "learned bootstrap transport id"
                            );
                            self.bootstrap_kad();
                            self.publish_record();
                        }
                    }
                }
                tracing::debug!(
                    node = %self.identity.user.user_name,
                    peer = %short_id(&peer_id),
                    conn = ?connection_id,
                    endpoint = ?endpoint,
                    "connection established"
                );
                None
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                endpoint,
                num_established,
                cause,
            } => {
                tracing::debug!(
                    node = %self.identity.user.user_name,
                    peer = %short_id(&peer_id),
                    conn = ?connection_id,
                    endpoint = ?endpoint,
                    remaining = num_established,
                    cause = ?cause,
                    "connection closed"
                );
                None
            }
            SwarmEvent::IncomingConnectionError { error, .. } => {
                tracing::warn!(node = %self.identity.user.user_name, error = %error, "incoming connection error");
                None
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::warn!(node = %self.identity.user.user_name, peer = ?peer_id, error = %error, "dial failed");
                None
            }
            _ => None,
        }
    }

    /// Poll the swarm (and run maintenance) until `predicate` matches a
    /// session event or `timeout` elapses. Returns the matched event.
    pub async fn wait_for<F>(
        &mut self,
        mut predicate: F,
        timeout: Duration,
    ) -> Option<BehaviourEvent>
    where
        F: FnMut(&BehaviourEvent) -> bool,
    {
        let sleep = tokio::time::sleep(timeout);
        tokio::pin!(sleep);
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                biased;
                _ = &mut sleep => return None,
                _ = tick.tick() => self.maintenance(),
                event = self.swarm.select_next_some() => {
                    if let Some(ev) = self.handle_event(event) {
                        if predicate(&ev) {
                            return Some(ev);
                        }
                    }
                }
            }
        }
    }

    /// Run maintenance + event handling until `stop` resolves to `true`.
    pub async fn run<F>(&mut self, mut stop: F)
    where
        F: std::future::Future<Output = bool> + Unpin,
    {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                biased;
                _ = tick.tick() => self.maintenance(),
                event = self.swarm.select_next_some() => {
                    let _ = self.handle_event(event);
                }
                stop_flag = &mut stop => {
                    if stop_flag {
                        break;
                    }
                }
            }
        }
    }

    /// Run for a fixed duration, then stop.
    pub async fn run_for(&mut self, duration: Duration) {
        let sleep = tokio::time::sleep(duration);
        let stop = async move {
            sleep.await;
            true
        };
        self.run(Box::pin(stop)).await;
    }
}

#[derive(Debug)]
pub enum NodeError {
    Listen(String),
    Address(libp2p::multiaddr::Error),
    Storage(crate::storage::StorageError),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::Listen(e) => write!(f, "could not listen: {e}"),
            NodeError::Address(e) => write!(f, "invalid multiaddr: {e}"),
            NodeError::Storage(e) => write!(f, "storage error: {e}"),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<crate::storage::StorageError> for NodeError {
    fn from(e: crate::storage::StorageError) -> Self {
        NodeError::Storage(e)
    }
}

/// The event loop commands for interactive mode.
#[derive(Debug)]
pub enum NodeCommand {
    /// Send a message; reply carries the message id.
    Send {
        peer: PeerId,
        text: String,
        reply: tokio::sync::oneshot::Sender<Result<u64, String>>,
    },
    /// Look up a peer's DHT record; reply carries verified records.
    Lookup {
        peer: PeerId,
        reply: tokio::sync::oneshot::Sender<Vec<VerifiedRecord>>,
    },
    /// List established sessions; reply carries (name, peer id) pairs.
    Peers {
        reply: tokio::sync::oneshot::Sender<Vec<(String, PeerId)>>,
    },
    /// Shut the node down.
    Quit,
}

/// Interactive (REPL-style) run: processes `commands` while running.
pub async fn run_interactive(node: &mut Node, mut commands: mpsc::Receiver<NodeCommand>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    // Pending lookup replies: (deadline, sender).
    let mut lookup_waiters: Vec<(Instant, tokio::sync::oneshot::Sender<Vec<VerifiedRecord>>)> =
        Vec::new();
    loop {
        tokio::select! {
            biased;
            cmd = commands.recv() => {
                match cmd {
                    Some(NodeCommand::Send { peer, text, reply }) => {
                        if !node.has_session(&peer) {
                            // Try discovery first: the send is queued in the
                            // session behaviour and flushed on establishment.
                            let _ = node.lookup(peer);
                        }
                        let msg_id = node.send_message(peer, text);
                        let _ = reply.send(Ok(msg_id));
                    }
                    Some(NodeCommand::Lookup { peer, reply }) => {
                        let _ = node.lookup(peer);
                        lookup_waiters.push((Instant::now() + Duration::from_secs(10), reply));
                    }
                    Some(NodeCommand::Peers { reply }) => {
                        let names = node
                            .session_peers()
                            .into_iter()
                            .map(|p| {
                                let name = node
                                    .swarm
                                    .behaviour()
                                    .session
                                    .peer_name(&p)
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| "?".to_string());
                                (name, p)
                            })
                            .collect();
                        let _ = reply.send(names);
                    }
                    Some(NodeCommand::Quit) | None => break,
                }
            }
            _ = tick.tick() => {
                node.maintenance();
                // Flush lookup replies once their wait window elapses.
                let now = Instant::now();
                let (done, keep): (Vec<_>, Vec<_>) = lookup_waiters
                    .into_iter()
                    .partition(|(deadline, _)| *deadline <= now);
                lookup_waiters = keep;
                for (_, reply) in done {
                    let _ = reply.send(std::mem::take(&mut node.discovered));
                }
            }
            event = node.swarm.select_next_some() => {
                let _ = node.handle_event(event);
            }
        }
    }
}
