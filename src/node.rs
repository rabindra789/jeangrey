//! The JeanGrey node: swarm assembly, DHT discovery, and the event loop.
//!
//! Composition: `NodeBehaviour = SessionBehaviour + kad::Behaviour`. The
//! Kademlia DHT is used strictly for discovery of address records; all
//! application data is exchanged over authenticated JeanGrey sessions.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::core::upgrade::Version;
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{self, QueryId, RecordKey};
use libp2p::swarm::{Config as SwarmConfig, DialError, NetworkBehaviour, Swarm, SwarmEvent};
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
/// How often the local interface set is re-enumerated to detect stale
/// addresses (a Wi-Fi/network change removes the old IP from the OS).
pub const INTERFACE_SCAN_INTERVAL: Duration = Duration::from_secs(5);
/// Maximum times a discovery lookup is re-issued before giving up.
pub const MAX_LOOKUP_ATTEMPTS: u32 = 10;
/// Delay between lookup retries (gives the DHT time to learn the record).
pub const LOOKUP_RETRY_DELAY: Duration = Duration::from_secs(1);
/// Delay before re-dialing the CACHED address record of a peer whose session
/// was lost (the cached set may be stale; the dial failure drives
/// invalidation + rediscovery).
pub const RECONNECT_DIAL_DELAY: Duration = Duration::from_secs(2);
/// Delay before a dynamic rediscovery lookup after a session loss.
pub const RECONNECT_DELAY: Duration = Duration::from_secs(3);

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

/// A re-dial of a peer's cached address record (scheduled after session
/// loss; single attempt — a failure invalidates the cached candidates and
/// the scheduled rediscovery takes over).
struct RetryDial {
    peer: PeerId,
    transport: PeerId,
    addrs: Vec<Multiaddr>,
    next_at: Instant,
}

/// Filter `addrs` down to the addresses whose IP is still configured on a
/// local interface. Loopback addresses are always accepted (they cannot go
/// stale); addresses without an IP protocol component are dropped; the
/// order of the surviving addresses is preserved and duplicates removed.
///
/// This is the core of the address-lifecycle fix: libp2p does not expire a
/// wildcard listener's per-interface addresses when the underlying network
/// changes, so the swarm would otherwise keep advertising an IP that the OS
/// no longer owns (observed as `No route to host` after a Wi-Fi switch).
pub fn filter_local_addrs(
    addrs: &[Multiaddr],
    local_ips: &std::collections::HashSet<IpAddr>,
) -> Vec<Multiaddr> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for a in addrs {
        let ip = a.iter().find_map(|p| match p {
            libp2p::multiaddr::Protocol::Ip4(i) => Some(IpAddr::V4(i)),
            libp2p::multiaddr::Protocol::Ip6(i) => Some(IpAddr::V6(i)),
            _ => None,
        });
        let keep = match ip {
            Some(ip) if ip.is_loopback() => true,
            Some(ip) => local_ips.contains(&ip),
            None => false,
        };
        if keep && seen.insert(a.to_string()) {
            out.push(a.clone());
        }
    }
    out
}

/// Enumerate the IPs currently configured on this host. Returns `None` on
/// scan failure: an unknown interface set must not cause addresses to be
/// dropped (fail-safe).
fn local_ip_set() -> Option<HashSet<IpAddr>> {
    match local_ip_address::list_afinet_netifas() {
        Ok(list) => Some(list.into_iter().map(|(_, ip)| ip).collect()),
        Err(e) => {
            tracing::warn!(error = %e, "interface scan failed; keeping current addresses");
            None
        }
    }
}

/// A running JeanGrey node.
pub struct Node {
    pub swarm: Swarm<NodeBehaviour>,
    pub identity: Arc<DeviceIdentity>,
    pub storage: Storage,
    our_record: AddrRecord,
    /// The addresses we currently believe are reachable on this host
    /// (swarm listen addresses minus those whose IP is no longer local).
    current_addrs: Vec<Multiaddr>,
    last_publish: Instant,
    last_interface_scan: Instant,
    last_bootstrap: Instant,
    connected: HashSet<PeerId>,
    /// Bootstrap peers whose transport Peer ID is not yet known.
    bootstrap_pending: Vec<BootstrapPeer>,
    /// Bootstrap peers whose transport Peer ID has been learned.
    bootstrap_mapped: HashSet<PeerId>,
    /// Bootstrap peer addresses with a dial in flight (dedup: prevents a
    /// second dial while the first connection is still being set up, which
    /// would collide with the in-flight tuple on the same loopback port).
    bootstrap_dialing: HashSet<Multiaddr>,
    /// In-flight discovery queries.
    pending_lookups: HashMap<QueryId, LookupRequest>,
    /// Failed lookups waiting for their retry window.
    retry_lookups: VecDeque<LookupRetry>,
    /// Peers with a dial in flight (dedup; keyed by device Peer ID).
    dialing: HashSet<PeerId>,
    /// Peers with which a session has been established at least once (they
    /// are reconnection candidates on disconnect).
    had_session: HashSet<PeerId>,
    /// Re-dials of cached address records waiting for their fire time.
    retry_dials: VecDeque<RetryDial>,
    /// The latest verified DHT record per device (keyed by device Peer ID).
    /// A verified record REPLACES an older one for the same device; a dial
    /// failure removes the failed candidates (possibly the whole record),
    /// which triggers a dynamic rediscovery.
    pub records: HashMap<PeerId, VerifiedRecord>,
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
            current_addrs: Vec::new(),
            last_publish: Instant::now(),
            last_interface_scan: Instant::now() - INTERFACE_SCAN_INTERVAL,
            // Due immediately: the first maintenance tick dials the
            // bootstrap peers without waiting out a full interval.
            last_bootstrap: Instant::now() - Duration::from_secs(5),
            connected: HashSet::new(),
            bootstrap_pending: options.bootstrap,
            bootstrap_mapped: HashSet::new(),
            bootstrap_dialing: HashSet::new(),
            pending_lookups: HashMap::new(),
            retry_lookups: VecDeque::new(),
            dialing: HashSet::new(),
            had_session: HashSet::new(),
            retry_dials: VecDeque::new(),
            records: HashMap::new(),
        };
        Ok(node)
    }

    pub fn our_listen_addrs(&self) -> Vec<Multiaddr> {
        self.swarm.listeners().cloned().collect()
    }

    /// The address set currently believed reachable on this host (the
    /// source of what gets signed into our DHT record).
    pub fn current_addrs(&self) -> Vec<Multiaddr> {
        self.current_addrs.clone()
    }

    /// Record `addr` as one of our listen addresses. Returns `true` if the
    /// set changed (callers then republish).
    pub fn note_listen_addr(&mut self, addr: Multiaddr) -> bool {
        if self.current_addrs.contains(&addr) {
            return false;
        }
        self.current_addrs.push(addr);
        true
    }

    /// Remove `addr` from our listen set (it is no longer reachable, e.g.
    /// the OS dropped the interface). Returns `true` if the set changed.
    pub fn note_listen_addr_gone(&mut self, addr: &Multiaddr) -> bool {
        let before = self.current_addrs.len();
        self.current_addrs.retain(|a| a != addr);
        self.current_addrs.len() != before
    }

    /// Re-check our listen addresses against the OS interface set and drop
    /// any whose IP is no longer configured locally. Runs at most every
    /// [`INTERFACE_SCAN_INTERVAL`]; publishes immediately on any change.
    pub fn refresh_local_addresses(&mut self) {
        if self.last_interface_scan.elapsed() < INTERFACE_SCAN_INTERVAL {
            return;
        }
        self.last_interface_scan = Instant::now();
        let Some(local_ips) = local_ip_set() else {
            return;
        };
        // Pick up any addresses the swarm reported that we have not seen.
        for addr in self.swarm.listeners() {
            if !self.current_addrs.contains(addr) {
                self.current_addrs.push(addr.clone());
            }
        }
        let filtered = filter_local_addrs(&self.current_addrs, &local_ips);
        if filtered == self.current_addrs {
            return;
        }
        let dropped: Vec<String> = self
            .current_addrs
            .iter()
            .filter(|a| !filtered.contains(a))
            .map(|a| a.to_string())
            .collect();
        self.current_addrs = filtered;
        tracing::info!(
            node = %self.identity.user.user_name,
            dropped = ?dropped,
            "dropped stale local address(es); republishing record"
        );
        self.publish_record();
    }

    /// Record the current listen addresses and re-publish to the DHT.
    pub fn publish_record(&mut self) {
        let addrs = self.current_addrs.clone();
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
    /// No-op while a dial for `peer` is already in flight (dedup).
    pub fn dial_peer(&mut self, peer: PeerId, transport: PeerId, addrs: Vec<Multiaddr>) {
        if !self.dialing.insert(peer) {
            return;
        }
        self.swarm
            .behaviour_mut()
            .session
            .connect(peer, transport, addrs);
    }

    /// The latest verified DHT records (one per device).
    pub fn records(&self) -> Vec<VerifiedRecord> {
        self.records.values().cloned().collect()
    }

    /// Whether a discovery lookup for `peer` is pending or already queued.
    fn lookup_in_flight(&self, peer: &PeerId) -> bool {
        self.pending_lookups.values().any(|r| &r.peer == peer)
            || self.retry_lookups.iter().any(|r| &r.peer == peer)
    }

    /// Schedule a dynamic rediscovery lookup for `peer` (deduplicated).
    fn schedule_rediscovery(&mut self, peer: PeerId, delay: Duration) {
        if self.lookup_in_flight(&peer) {
            return;
        }
        self.retry_lookups.push_back(LookupRetry {
            peer,
            attempts: 1,
            next_at: Instant::now() + delay,
        });
        tracing::info!(
            node = %self.identity.user.user_name,
            peer = %short_id(&peer),
            delay = ?delay,
            "scheduling dynamic rediscovery"
        );
    }

    /// Schedule reconnection to `peer` after its session was lost: re-dial
    /// the cached address record once (it may be stale — the dial failure
    /// then invalidates it), and in parallel refresh the record from the
    /// DHT.
    fn schedule_reconnect(&mut self, peer: PeerId) {
        let Some(record) = self.records.get(&peer).cloned() else {
            tracing::debug!(
                node = %self.identity.user.user_name,
                peer = %short_id(&peer),
                "no cached record; skipping reconnect"
            );
            return;
        };
        if !self.dialing.contains(&peer) && !self.has_session(&peer) {
            self.retry_dials.push_back(RetryDial {
                peer,
                transport: record.transport_peer,
                addrs: record.addrs,
                next_at: Instant::now() + RECONNECT_DIAL_DELAY,
            });
        }
        self.schedule_rediscovery(peer, RECONNECT_DELAY);
    }

    /// Drop `failed` addresses from the cached record of `device` (dial
    /// failures prove they are not reachable). A record with no surviving
    /// candidates is removed entirely; the caller schedules the rediscovery.
    fn invalidate_candidates(&mut self, device: PeerId, failed: &[Multiaddr]) {
        if failed.is_empty() {
            return;
        }
        let Some(record) = self.records.get_mut(&device) else {
            return;
        };
        let before = record.addrs.len();
        record.addrs.retain(|a| !failed.contains(a));
        if record.addrs.len() == before {
            return;
        }
        if record.addrs.is_empty() {
            self.records.remove(&device);
            tracing::warn!(
                node = %self.identity.user.user_name,
                peer = %short_id(&device),
                "cached address record fully stale; removed (rediscovery scheduled)"
            );
        } else {
            tracing::info!(
                node = %self.identity.user.user_name,
                peer = %short_id(&device),
                removed = before - record.addrs.len(),
                "dropped failed address candidate(s) from cached record"
            );
        }
    }

    /// Cache a freshly verified DHT record (newest wins per device) and dial
    /// it unless a dial or session already covers the peer.
    fn on_verified_record(&mut self, verified: VerifiedRecord) {
        let replace = match self.records.get(&verified.peer_id) {
            // An equal `issued_at` means the very same record was re-fetched
            // (e.g. a rediscovery lookup after a dial failure): still replace
            // and re-dial — a strict `<` would silently drop the reconnect.
            Some(old) => old.issued_at <= verified.issued_at,
            None => true,
        };
        if !replace {
            return;
        }
        let dial =
            !self.dialing.contains(&verified.peer_id) && !self.has_session(&verified.peer_id);
        tracing::info!(
            node = %self.identity.user.user_name,
            peer = %short_id(&verified.peer_id),
            device = %hex::encode(verified.device_uuid),
            addrs = verified.addrs.len(),
            "verified DHT address record"
        );
        self.records.insert(verified.peer_id, verified.clone());
        if dial {
            self.dial_peer(
                verified.peer_id,
                verified.transport_peer,
                verified.addrs.clone(),
            );
        }
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
                                // Cache the newest verified record per device
                                // and dial it (unless already covered); the
                                // record becomes the reconnect candidate set.
                                self.on_verified_record(verified);
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
                self.had_session.insert(*peer_id);
                self.dialing.remove(peer_id);
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
                // Reconnect: the peer had a session; re-dial its cached
                // record (which may be stale — the failure invalidates it)
                // and refresh the record from the DHT in parallel.
                if self.had_session.remove(peer_id) {
                    self.schedule_reconnect(*peer_id);
                }
            }
        }
        event
    }

    /// Periodic maintenance, shared by all run loops.
    fn maintenance(&mut self) {
        // Address lifecycle: drop stale local addresses and republish
        // immediately when the reachable set changes.
        self.refresh_local_addresses();
        if self.last_publish.elapsed() >= PUBLISH_INTERVAL {
            self.publish_record();
        }
        // Fire scheduled re-dials of cached address records (reconnect).
        let now = Instant::now();
        while let Some(dial) = self.retry_dials.front() {
            if dial.next_at > now {
                break;
            }
            let dial = self.retry_dials.pop_front().unwrap();
            // A concurrent rediscovery may already have reconnected us.
            if self.has_session(&dial.peer) || self.dialing.contains(&dial.peer) {
                continue;
            }
            tracing::info!(
                node = %self.identity.user.user_name,
                peer = %short_id(&dial.peer),
                addrs = dial.addrs.len(),
                "re-dialing cached address record after disconnect"
            );
            self.dial_peer(dial.peer, dial.transport, dial.addrs);
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
                if !self.bootstrap_mapped.contains(&bp.peer_id())
                    && bp
                        .multiaddrs()
                        .iter()
                        .all(|a| !self.bootstrap_dialing.contains(a))
                {
                    tracing::debug!(
                        node = %self.identity.user.user_name,
                        addresses = ?bp.multiaddrs(),
                        "dialing bootstrap peer"
                    );
                    self.bootstrap_dialing
                        .extend(bp.multiaddrs().iter().cloned());
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
                if self.note_listen_addr(address) {
                    self.publish_record();
                }
                None
            }
            SwarmEvent::ExpiredListenAddr { address, .. } => {
                tracing::warn!(node = %self.identity.user.user_name, %address, "listen address expired");
                if self.note_listen_addr_gone(&address) {
                    self.publish_record();
                }
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
                            self.bootstrap_dialing
                                .retain(|a| !bp.multiaddrs().iter().any(|b| b == a));
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
                // A dial that was superseded or failed at the transport
                // layer clears the dialing guard so a fresh lookup can dial.
                if let Some(device) = self.swarm.behaviour().session.device_of(&peer_id) {
                    self.dialing.remove(&device);
                }
                // If a bootstrap connection closed before its transport Peer
                // ID was learned, allow the bootstrap loop to re-dial it.
                if let libp2p::core::ConnectedPoint::Dialer { address, .. } = &endpoint {
                    self.bootstrap_dialing.remove(address);
                }
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
                // M2.2: a failed dial proves the attempted addresses are not
                // reachable — drop them from the cached record and refresh
                // it from the DHT (dynamic rediscovery). Bootstrap dials
                // (unknown device) have no cached record and are left alone.
                let device = peer_id.and_then(|t| self.swarm.behaviour().session.device_of(&t));
                let failed: Vec<Multiaddr> = match &error {
                    DialError::Transport(failures) => {
                        failures.iter().map(|(a, _)| a.clone()).collect()
                    }
                    DialError::WrongPeerId { .. } => {
                        // The address is live but belongs to a DIFFERENT
                        // transport id: the cached binding is wrong. Treat
                        // the whole record as stale.
                        if let Some(d) = device {
                            self.records.remove(&d);
                        }
                        Vec::new()
                    }
                    _ => Vec::new(),
                };
                if peer_id.is_none() {
                    // Peerless bootstrap dial: release the per-address
                    // in-flight guard so the bootstrap loop can re-dial.
                    for addr in &failed {
                        self.bootstrap_dialing.remove(addr);
                    }
                }
                if let Some(d) = device {
                    if !failed.is_empty() {
                        self.invalidate_candidates(d, &failed);
                        self.schedule_rediscovery(d, LOOKUP_RETRY_DELAY);
                    }
                    self.dialing.remove(&d);
                }
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
                    let _ = reply
                        .send(std::mem::take(&mut node.records).into_values().collect());
                }
            }
            event = node.swarm.select_next_some() => {
                let _ = node.handle_event(event);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn maddr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    fn ips(v: &[&str]) -> HashSet<IpAddr> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn filter_keeps_loopback_and_local_ips() {
        let addrs = [
            maddr("/ip4/127.0.0.1/tcp/9000"),
            maddr("/ip4/10.0.0.5/tcp/9000"),
            maddr("/ip4/10.9.9.9/tcp/9000"),
            maddr("/ip6/::1/tcp/9000"),
        ];
        let local = ips(&["10.0.0.5", "10.1.1.1"]);
        let filtered = filter_local_addrs(&addrs, &local);
        assert_eq!(filtered.len(), 3);
        assert!(filtered.contains(&maddr("/ip4/127.0.0.1/tcp/9000")));
        assert!(filtered.contains(&maddr("/ip4/10.0.0.5/tcp/9000")));
        assert!(filtered.contains(&maddr("/ip6/::1/tcp/9000")));
        assert!(!filtered.contains(&maddr("/ip4/10.9.9.9/tcp/9000")));
    }

    #[test]
    fn filter_drops_addrs_without_ip_and_dedups() {
        let addrs = [
            maddr("/ip4/127.0.0.1/tcp/9000"),
            maddr("/ip4/127.0.0.1/tcp/9000"),
            maddr("/dns4/example.com/tcp/9000"),
        ];
        let local = HashSet::new();
        let filtered = filter_local_addrs(&addrs, &local);
        assert_eq!(filtered, vec![maddr("/ip4/127.0.0.1/tcp/9000")]);
    }

    #[test]
    fn filter_removes_stale_ip_after_network_change() {
        // The motivating real-world case: the phone moved from Wi-Fi A
        // (10.174.110.x) to Wi-Fi B (172.20.56.x); the old IP is gone from
        // the OS and must not be advertised any longer.
        let addrs = [
            maddr("/ip4/10.174.110.167/tcp/9000"),
            maddr("/ip4/172.20.56.251/tcp/9000"),
        ];
        let local = ips(&["172.20.56.251"]);
        let filtered = filter_local_addrs(&addrs, &local);
        assert_eq!(filtered, vec![maddr("/ip4/172.20.56.251/tcp/9000")]);
    }

    #[tokio::test]
    async fn note_addr_add_remove_change_detection() {
        let id = crate::identity::DeviceIdentity::generate("addr-test");
        let storage = crate::storage::Storage::new(
            std::env::temp_dir().join(format!("jg-addr-test-{}", std::process::id())),
        );
        let mut node = Node::new(
            id,
            storage,
            NodeOptions {
                listen_port: 0,
                bootstrap: Vec::new(),
            },
        )
        .unwrap();
        let a = maddr("/ip4/127.0.0.1/tcp/9100");
        assert!(node.note_listen_addr(a.clone()));
        assert!(!node.note_listen_addr(a.clone()));
        assert_eq!(node.current_addrs(), vec![a.clone()]);
        assert!(node.note_listen_addr_gone(&a));
        assert!(!node.note_listen_addr_gone(&a));
        assert!(node.current_addrs().is_empty());
    }

    fn test_node(name: &str) -> Node {
        let id = crate::identity::DeviceIdentity::generate(name);
        let storage = crate::storage::Storage::new(
            std::env::temp_dir().join(format!("jg-unit-{name}-{}", std::process::id())),
        );
        Node::new(
            id,
            storage,
            NodeOptions {
                listen_port: 0,
                bootstrap: Vec::new(),
            },
        )
        .unwrap()
    }

    fn verified_record(
        identity: &crate::identity::DeviceIdentity,
        addrs: &[&str],
    ) -> VerifiedRecord {
        let addrs: Vec<Multiaddr> = addrs.iter().map(|s| s.parse().unwrap()).collect();
        let record = records::sign_addr_record(identity, &addrs);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        records::verify_addr_record(&identity.peer_id.to_bytes(), &record, now).unwrap()
    }

    #[tokio::test]
    async fn schedule_rediscovery_dedups_same_peer() {
        let mut node = test_node("rediscovery-dedup");
        let peer = node.identity.peer_id;
        node.schedule_rediscovery(peer, LOOKUP_RETRY_DELAY);
        node.schedule_rediscovery(peer, LOOKUP_RETRY_DELAY);
        assert_eq!(
            node.retry_lookups.iter().filter(|r| r.peer == peer).count(),
            1,
            "a peer with a lookup in flight must not get a duplicate"
        );
        assert_eq!(
            node.retry_lookups.front().unwrap().attempts,
            1,
            "rediscovery starts its own bounded retry budget"
        );
    }

    #[tokio::test]
    async fn dialing_guard_prevents_duplicate_dials() {
        let mut node = test_node("dialing-guard");
        let device = node.identity.peer_id;
        let transport = crate::identity::DeviceIdentity::generate("remote").transport_peer_id();
        let addr = maddr("/ip4/127.0.0.1/tcp/9300");
        node.dial_peer(device, transport, vec![addr.clone()]);
        node.dial_peer(device, transport, vec![addr]);
        assert_eq!(node.dialing.len(), 1, "second dial must be a no-op");
    }

    #[tokio::test]
    async fn verified_record_cached_once_and_replaced_when_newer() {
        let mut node = test_node("cache-latest");
        let target = crate::identity::DeviceIdentity::generate("target");
        let mut older = verified_record(&target, &["/ip4/127.0.0.1/tcp/9301"]);
        older.issued_at -= 1000;
        let newer = verified_record(&target, &["/ip4/127.0.0.1/tcp/9302"]);

        node.on_verified_record(older.clone());
        node.on_verified_record(newer.clone());
        assert_eq!(
            node.records().len(),
            1,
            "one device keeps one cached record"
        );
        assert_eq!(
            node.records().first().unwrap().issued_at,
            newer.issued_at,
            "the newer record wins"
        );
        assert!(node
            .records()
            .first()
            .unwrap()
            .addrs
            .iter()
            .any(|a| a.to_string().contains("9302")));

        // An older record arriving late must not replace the newer one.
        node.on_verified_record(older);
        assert_eq!(node.records().first().unwrap().issued_at, newer.issued_at);
    }

    #[tokio::test]
    async fn invalidate_candidates_drops_failed_addrs_and_empty_records() {
        let mut node = test_node("invalidate");
        let target = crate::identity::DeviceIdentity::generate("target");
        let record = verified_record(
            &target,
            &["/ip4/127.0.0.1/tcp/9310", "/ip4/127.0.0.1/tcp/9311"],
        );
        node.records.insert(target.peer_id, record);

        node.invalidate_candidates(target.peer_id, &[maddr("/ip4/127.0.0.1/tcp/9310")]);
        assert_eq!(
            node.records.get(&target.peer_id).unwrap().addrs,
            vec![maddr("/ip4/127.0.0.1/tcp/9311")],
            "only the failed candidate is dropped"
        );

        node.invalidate_candidates(target.peer_id, &[maddr("/ip4/127.0.0.1/tcp/9311")]);
        assert!(
            !node.records.contains_key(&target.peer_id),
            "a record with no surviving candidates is removed"
        );
    }
}
