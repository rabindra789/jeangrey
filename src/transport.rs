//! JeanGrey transport: one negotiated substream per connection carrying
//! handshake frames and (later) AEAD-encrypted session frames.
//!
//! The `SessionUpgrade` is a pass-through: protocol negotiation happens via
//! multistream-select on the multiplexed substream; the handler then runs the
//! JeanGrey framing (see `framing`) directly on `libp2p::Stream`.
//!
//! Routing model (connection-scoped):
//!
//! - The dialer's handler opens the single outbound substream; the listener's
//!   handler accepts the single inbound substream. The first negotiated
//!   substream (in either direction) wins; extras are dropped.
//! - libp2p addresses connections by the *transport* Peer ID (ed25519 key);
//!   the JeanGrey layer addresses peers by the *device* Peer ID (ML-DSA key
//!   hash). The behaviour maps between the two: dials are issued for the
//!   transport id found in the signed address record, and every session event
//!   is re-keyed to the device id once the handshake authenticates it.
//! - The `SessionBehaviour` tracks one `Handshake` per `(transport PeerId,
//!   ConnectionId)`. Frames received on a connection are routed to that
//!   handshake; once established, a `Session` is stored per device peer.
//! - `SubstreamReady` is emitted as soon as a substream is negotiated; the
//!   behaviour then starts the handshake by sending the `Hello` frame.

use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use futures::future::Ready;
use futures::io::{AsyncRead, AsyncWrite};
use futures::ready;
use libp2p::core::upgrade::{InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::handler::{
    ConnectionEvent, ConnectionHandler, ConnectionHandlerEvent, SubstreamProtocol,
};
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, ToSwarm,
};
use libp2p::{Multiaddr, PeerId, Stream};

use crate::framing::{self, Frame};
use crate::handshake::{Handshake, HandshakeAction, HandshakeResult};
use crate::identity::DeviceIdentity;
use crate::session::{Inbound, Session};

/// The JeanGrey application protocol name on the wire.
pub const PROTOCOL_NAME: &str = "/jeangrey/1.0.0";

/// Maximum bytes buffered while waiting for a complete frame. Any stream that
/// exceeds this without delivering a frame is treated as hostile.
pub const MAX_READ_BUFFER: usize = framing::HEADER_LEN + framing::MAX_PAYLOAD;

// ---------------------------------------------------------------------------
// Protocol upgrade (pass-through)
// ---------------------------------------------------------------------------

/// Negotiates `/jeangrey/1.0.0` and hands the raw substream to the handler.
#[derive(Clone, Copy, Debug, Default)]
pub struct SessionUpgrade;

impl UpgradeInfo for SessionUpgrade {
    type Info = &'static str;
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once(PROTOCOL_NAME)
    }
}

impl InboundUpgrade<Stream> for SessionUpgrade {
    type Output = Stream;
    type Error = Infallible;
    type Future = Ready<Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, socket: Stream, _info: Self::Info) -> Self::Future {
        futures::future::ready(Ok(socket))
    }
}

impl OutboundUpgrade<Stream> for SessionUpgrade {
    type Output = Stream;
    type Error = Infallible;
    type Future = Ready<Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, socket: Stream, _info: Self::Info) -> Self::Future {
        futures::future::ready(Ok(socket))
    }
}

// ---------------------------------------------------------------------------
// Handler <-> Behaviour events
// ---------------------------------------------------------------------------

/// Events from the connection handler to the behaviour.
#[derive(Debug)]
pub enum HandlerToBehaviour {
    /// The single connection substream has been negotiated; start the
    /// handshake.
    SubstreamReady,
    /// One complete frame was read from the substream.
    FrameReceived { frame: Frame },
    /// The substream reached EOF or failed; no more frames will arrive.
    StreamClosed,
}

/// Events from the behaviour to the connection handler.
#[derive(Debug, Clone)]
pub enum BehaviourToHandler {
    /// Encode and write these frames to the connection substream.
    SendFrames(Vec<Frame>),
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

/// Per-connection handler: owns the substream, the read buffer and the write
/// queue. It is protocol-agnostic with respect to handshake vs. session
/// frames — every frame is forwarded to the behaviour, which routes it.
pub struct SessionHandler {
    /// True if this side dialed the connection (and therefore must open the
    /// outbound substream).
    initiator: bool,
    /// Remote transport Peer ID (for log attribution).
    peer: String,
    outbound_requested: bool,
    substream: Option<Pin<Box<Stream>>>,
    /// Set when a substream was negotiated; emitted once from `poll`.
    pending_ready: bool,
    read_buf: Vec<u8>,
    write_queue: VecDeque<Vec<u8>>,
    writing: Option<(Vec<u8>, usize)>,
    closed: bool,
}

impl SessionHandler {
    pub fn new(initiator: bool, peer: PeerId) -> Self {
        let peer = peer.to_base58();
        SessionHandler {
            initiator,
            peer,
            outbound_requested: false,
            substream: None,
            pending_ready: false,
            read_buf: Vec::with_capacity(1024),
            write_queue: VecDeque::new(),
            writing: None,
            closed: false,
        }
    }

    fn set_substream(&mut self, stream: Stream) {
        if self.substream.is_some() {
            // Second substream on one connection: drop it (closes it).
            return;
        }
        self.substream = Some(Pin::new(Box::new(stream)));
        self.pending_ready = true;
    }

    /// Poll-write pending frames; returns true if all queued bytes were
    /// flushed (or nothing was queued).
    fn poll_flush_writes(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            let stream = match self.substream.as_mut() {
                Some(s) => s,
                None => return Poll::Ready(Ok(true)),
            };
            if self.writing.is_none() {
                match self.write_queue.pop_front() {
                    Some(chunk) => self.writing = Some((chunk, 0)),
                    None => return Poll::Ready(Ok(true)),
                }
            }
            let (buf, offset) = self.writing.as_mut().expect("set above");
            let n = ready!(stream.as_mut().poll_write(cx, &buf[*offset..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "substream write returned 0",
                )));
            }
            *offset += n;
            if *offset == buf.len() {
                self.writing = None;
            }
        }
    }

    /// Poll-read and decode the next complete frame. Only the bytes of that
    /// frame are consumed from the buffer; any further complete frames stay
    /// buffered and are decoded on subsequent polls (never dropped). Bytes
    /// are read from the network only when no complete frame is buffered.
    fn poll_read_once(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Frame>>> {
        let stream = match self.substream.as_mut() {
            Some(s) => s,
            None => return Poll::Ready(Ok(None)),
        };
        loop {
            match framing::decode(&self.read_buf) {
                Ok(frame) => {
                    let consumed = framing::HEADER_LEN + frame.payload.len();
                    self.read_buf.drain(..consumed);
                    return Poll::Ready(Ok(Some(frame)));
                }
                Err(framing::FrameError::Truncated) => {}
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("malformed frame: {e}"),
                    )));
                }
            }
            if self.read_buf.len() > MAX_READ_BUFFER {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "read buffer exceeds frame size limit",
                )));
            }
            let mut tmp = [0u8; 4096];
            let n = ready!(stream.as_mut().poll_read(cx, &mut tmp))?;
            if n == 0 {
                return Poll::Ready(Ok(None)); // EOF
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }
    }
}

impl ConnectionHandler for SessionHandler {
    type FromBehaviour = ConnectionHandlerEvent<SessionUpgrade, (), BehaviourToHandler>;
    type ToBehaviour = HandlerToBehaviour;
    type InboundProtocol = SessionUpgrade;
    type OutboundProtocol = SessionUpgrade;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        SubstreamProtocol::new(SessionUpgrade, ())
    }

    fn connection_keep_alive(&self) -> bool {
        true
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        if self.closed {
            tracing::debug!(peer = %self.peer, "handler polled while closed");
            return Poll::Pending;
        }

        // 1. The dialer opens the outbound substream once, at connection start.
        if self.initiator && !self.outbound_requested && self.substream.is_none() {
            self.outbound_requested = true;
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(SessionUpgrade, ()),
            });
        }

        // 2. Announce a freshly negotiated substream (starts the handshake).
        if self.pending_ready {
            self.pending_ready = false;
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                HandlerToBehaviour::SubstreamReady,
            ));
        }

        // 2. Flush pending writes (handshake/session frames).
        if !self.write_queue.is_empty() || self.writing.is_some() {
            match self.poll_flush_writes(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => {
                    tracing::debug!(peer = %self.peer, error = %e, "handler closed: write failed");
                    self.closed = true;
                    self.substream = None;
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        HandlerToBehaviour::StreamClosed,
                    ));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // 3. Decode the next buffered frame (reading only as needed); emit
        //    at most one frame per poll.
        match self.poll_read_once(cx) {
            Poll::Ready(Ok(Some(frame))) => Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                HandlerToBehaviour::FrameReceived { frame },
            )),
            Poll::Ready(Ok(None)) => Poll::Pending,
            Poll::Ready(Err(e)) => {
                tracing::debug!(peer = %self.peer, error = %e, "handler closed: read failed");
                self.closed = true;
                self.substream = None;
                Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                    HandlerToBehaviour::StreamClosed,
                ))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        if let ConnectionHandlerEvent::NotifyBehaviour(BehaviourToHandler::SendFrames(frames)) =
            event
        {
            for frame in frames {
                self.write_queue.push_back(framing::encode(&frame));
            }
        }
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(negotiated) => {
                self.set_substream(negotiated.protocol);
            }
            ConnectionEvent::FullyNegotiatedOutbound(negotiated) => {
                self.set_substream(negotiated.protocol);
            }
            ConnectionEvent::DialUpgradeError(_) | ConnectionEvent::ListenUpgradeError(_) => {
                // No substream; the connection is unusable for JeanGrey.
                tracing::debug!(peer = %self.peer, "handler closed: substream upgrade error");
                self.closed = true;
            }
            _ => {}
        }
    }

    fn poll_close(&mut self, _cx: &mut Context<'_>) -> Poll<Option<Self::ToBehaviour>> {
        tracing::debug!(peer = %self.peer, "handler poll_close called");
        self.substream = None;
        self.closed = true;
        Poll::Ready(None)
    }
}

// ---------------------------------------------------------------------------
// Session behaviour
// ---------------------------------------------------------------------------

/// Events the session behaviour emits to the node. All `peer_id`s are
/// *device* Peer IDs (ML-DSA), except `HandshakeFailed`/`PeerDisconnected`
/// where the device id may not be known yet (inbound, pre-handshake) — there
/// the transport Peer ID is reported and `SessionBehaviour::transport_of` is
/// unavailable for it.
#[derive(Debug)]
pub enum BehaviourEvent {
    /// A new authenticated session was established over a connection.
    SessionEstablished {
        peer_id: PeerId,
        connection_id: ConnectionId,
        result: Box<HandshakeResult>,
    },
    /// A handshake failed (bad signature, peer-id mismatch, malformed frame,
    /// or the connection died mid-handshake).
    HandshakeFailed { peer_id: PeerId, error: String },
    /// A decrypted, authenticated message arrived.
    MessageReceived {
        peer_id: PeerId,
        msg_id: u64,
        body: String,
        ts_ms: u64,
    },
    /// A decrypted, authenticated acknowledgement arrived.
    AckReceived {
        peer_id: PeerId,
        msg_id: u64,
        ack_seq: u32,
    },
    /// The peer reports the address at which it observed our connection
    /// (M2.3 observed-address discovery).
    ObservedAddrReported {
        peer_id: PeerId,
        ip: IpAddr,
        source_port: u16,
    },
    /// The peer asks us to dial back a candidate address of theirs (M2.3
    /// reachability validation).
    DialBackRequested { peer_id: PeerId, addr: Multiaddr },
    /// The result of a dial-back probe we requested (M2.3).
    DialBackResolved {
        peer_id: PeerId,
        addr: Multiaddr,
        reachable: bool,
    },
    /// A connection to a peer was established (transport level).
    PeerConnected { peer_id: PeerId },
    /// The last connection to a peer was closed.
    PeerDisconnected { peer_id: PeerId },
}

/// The JeanGrey session/stream behaviour. One handshake per
/// (transport peer, connection); one session per *device* peer
/// (latest handshake wins).
pub struct SessionBehaviour {
    identity: Arc<DeviceIdentity>,
    handshakes: HashMap<(PeerId, ConnectionId), (Handshake, Option<PeerId>)>,
    sessions: HashMap<PeerId, (PeerId, ConnectionId, Session)>,
    peer_names: HashMap<PeerId, String>,
    pending_sends: HashMap<PeerId, VecDeque<(u64, String)>>,
    connected: HashSet<PeerId>,
    /// transport Peer ID -> device Peer ID (from dials and handshakes).
    transport_devices: HashMap<PeerId, PeerId>,
    /// device Peer ID -> transport Peer ID (for disconnects).
    device_transports: HashMap<PeerId, PeerId>,
    /// Observed source address of each inbound connection (the address at
    /// which the dialing peer is seen), keyed by (transport peer, conn).
    observed_addrs: HashMap<(PeerId, ConnectionId), (IpAddr, u16)>,
    queue: VecDeque<
        ToSwarm<BehaviourEvent, ConnectionHandlerEvent<SessionUpgrade, (), BehaviourToHandler>>,
    >,
}

impl SessionBehaviour {
    pub fn new(identity: Arc<DeviceIdentity>) -> Self {
        SessionBehaviour {
            identity,
            handshakes: HashMap::new(),
            sessions: HashMap::new(),
            peer_names: HashMap::new(),
            pending_sends: HashMap::new(),
            connected: HashSet::new(),
            transport_devices: HashMap::new(),
            device_transports: HashMap::new(),
            observed_addrs: HashMap::new(),
            queue: VecDeque::new(),
        }
    }

    /// Whether we have an established session with `device`.
    pub fn has_session(&self, peer: &PeerId) -> bool {
        self.sessions.contains_key(peer)
    }

    /// The authenticated user name of a device with an established session.
    pub fn peer_name(&self, peer: &PeerId) -> Option<&str> {
        self.peer_names.get(peer).map(|s| s.as_str())
    }

    /// The transport Peer ID behind `device`, if one is known.
    pub fn transport_of(&self, device: &PeerId) -> Option<&PeerId> {
        self.device_transports.get(device)
    }

    /// Queue a send; encrypted immediately if a session exists, otherwise
    /// buffered until the session is established. Returns the message id.
    pub fn send_message(&mut self, peer: PeerId, text: String) -> u64 {
        let msg_id = rand::random::<u64>();
        if let Some((transport, conn_id, session)) = self.sessions.get_mut(&peer) {
            match session.encrypt_message(&text, msg_id) {
                Ok(frame) => {
                    let (transport, conn_id) = (*transport, *conn_id);
                    self.notify_conn(transport, conn_id, vec![frame]);
                }
                Err(e) => {
                    tracing::warn!(%peer, %msg_id, error = %e, "message encryption failed");
                    self.queue
                        .push_back(ToSwarm::GenerateEvent(BehaviourEvent::HandshakeFailed {
                            peer_id: peer,
                            error: format!("session error: {e}"),
                        }));
                }
            }
        } else {
            self.pending_sends
                .entry(peer)
                .or_default()
                .push_back((msg_id, text));
        }
        msg_id
    }

    /// Queue a dial to the *transport* Peer ID of `device` at the given
    /// addresses. The device/transport binding comes from the verified DHT
    /// record (the transport id is part of the ML-DSA-signed record).
    pub fn connect(&mut self, device: PeerId, transport: PeerId, addrs: Vec<libp2p::Multiaddr>) {
        if addrs.is_empty() {
            return;
        }
        self.transport_devices.insert(transport, device);
        self.device_transports.insert(device, transport);
        self.queue.push_back(ToSwarm::Dial {
            opts: DialOpts::peer_id(transport)
                .addresses(addrs)
                .allocate_new_port()
                .build(),
        });
    }

    /// Queue a dial where the remote's transport Peer ID is not yet known
    /// (bootstrap peers: only the device Peer ID and the address are given).
    /// Once the connection establishes, the caller maps the learned transport
    /// Peer ID to the device via [`Self::map_transport`].
    pub fn connect_unknown(&mut self, addrs: Vec<libp2p::Multiaddr>) {
        let Some(addr) = addrs.into_iter().next() else {
            return;
        };
        self.queue.push_back(ToSwarm::Dial {
            opts: DialOpts::unknown_peer_id()
                .address(addr)
                .allocate_new_port()
                .build(),
        });
    }

    /// Dial `addr` without a known transport Peer ID: a reachability probe
    /// (M2.3 dial-back validation). `unknown_peer_id` dials are never
    /// suppressed by an existing connection to that peer.
    pub fn connect_probe(&mut self, addr: libp2p::Multiaddr) {
        self.queue.push_back(ToSwarm::Dial {
            opts: DialOpts::unknown_peer_id()
                .address(addr)
                .allocate_new_port()
                .build(),
        });
    }

    /// Send an observed-address report (M2.3) to a session peer.
    pub fn send_observed_addr(&mut self, peer: PeerId, ip: IpAddr, source_port: u16) {
        let Some((transport, conn_id, session)) = self.sessions.get_mut(&peer) else {
            tracing::debug!(%peer, "observed-addr report dropped: no session");
            return;
        };
        let (transport, conn_id) = (*transport, *conn_id);
        let frame = session.encrypt_observed_addr(ip, source_port);
        self.notify_conn(transport, conn_id, vec![frame]);
    }

    /// Ask a session peer to dial back `addr` (M2.3 reachability probe).
    pub fn send_dial_back_req(&mut self, peer: PeerId, addr: &libp2p::Multiaddr) {
        let Some((transport, conn_id, session)) = self.sessions.get_mut(&peer) else {
            tracing::debug!(%peer, "dial-back request dropped: no session");
            return;
        };
        let (transport, conn_id) = (*transport, *conn_id);
        let frame = session.encrypt_dial_back_req(addr);
        self.notify_conn(transport, conn_id, vec![frame]);
    }

    /// Report the result of a dial-back probe (M2.3).
    pub fn send_dial_back_res(&mut self, peer: PeerId, addr: &libp2p::Multiaddr, reachable: bool) {
        let Some((transport, conn_id, session)) = self.sessions.get_mut(&peer) else {
            tracing::debug!(%peer, "dial-back result dropped: no session");
            return;
        };
        let (transport, conn_id) = (*transport, *conn_id);
        let frame = session.encrypt_dial_back_res(addr, reachable);
        self.notify_conn(transport, conn_id, vec![frame]);
    }

    /// Record the transport Peer ID behind `device`, learned from an
    /// established connection (bootstrap).
    pub fn map_transport(&mut self, device: PeerId, transport: PeerId) {
        self.transport_devices.insert(transport, device);
        self.device_transports.insert(device, transport);
    }

    fn notify_conn(&mut self, peer: PeerId, conn_id: ConnectionId, frames: Vec<Frame>) {
        tracing::debug!(%peer, ?conn_id, n = frames.len(), "sending frames to connection");
        self.queue.push_back(ToSwarm::NotifyHandler {
            peer_id: peer,
            handler: NotifyHandler::One(conn_id),
            event: ConnectionHandlerEvent::NotifyBehaviour(BehaviourToHandler::SendFrames(frames)),
        });
    }

    /// The device id behind `transport`, if known (the reverse of
    /// [`Self::transport_of`]).
    pub fn device_of(&self, transport: &PeerId) -> Option<PeerId> {
        self.transport_devices.get(transport).copied()
    }

    fn on_handler_event(
        &mut self,
        transport: PeerId,
        conn_id: ConnectionId,
        event: HandlerToBehaviour,
    ) {
        match event {
            HandlerToBehaviour::SubstreamReady => {
                tracing::debug!(
                    transport = %transport,
                    conn_id = ?conn_id,
                    expected = ?self.device_of(&transport).map(|d| d.to_base58()),
                    "substream ready; starting handshake"
                );
                // Start the handshake for this connection. The expected peer
                // is the DEVICE id (from the DHT record if we dialed).
                if self.handshakes.contains_key(&(transport, conn_id)) {
                    return;
                }
                let expected_device = self.device_of(&transport);
                let (hs, hello) = Handshake::new(&self.identity, expected_device);
                self.handshakes
                    .insert((transport, conn_id), (hs, expected_device));
                self.notify_conn(transport, conn_id, vec![hello]);
            }
            HandlerToBehaviour::FrameReceived { frame } => {
                self.on_frame(transport, conn_id, frame);
            }
            HandlerToBehaviour::StreamClosed => {
                self.handshakes.remove(&(transport, conn_id));
            }
        }
    }

    fn on_frame(&mut self, transport: PeerId, conn_id: ConnectionId, frame: Frame) {
        if frame.is_session_frame() {
            self.on_session_frame(transport, conn_id, frame);
            return;
        }
        let Some((hs, _)) = self.handshakes.get_mut(&(transport, conn_id)) else {
            tracing::debug!(%transport, "dropping frame: no handshake for connection");
            return;
        };
        match hs.on_frame(&self.identity, &frame) {
            Ok(HandshakeAction::Frames(frames)) => {
                self.notify_conn(transport, conn_id, frames);
            }
            Ok(HandshakeAction::Established(result)) => {
                self.handshakes.remove(&(transport, conn_id));
                // The device Peer ID is now authenticated: re-key all state
                // from the transport id to the device id.
                let device = result.peer_id;
                self.transport_devices.insert(transport, device);
                self.device_transports.insert(device, transport);
                self.peer_names
                    .insert(device, result.peer_hello.user_name.clone());
                let session = Session::new(&result);
                self.sessions.insert(device, (transport, conn_id, session));
                self.flush_pending_sends(device, transport, conn_id);
                // M2.3: if this connection was INBOUND, tell the peer the
                // address at which we observed it (external address
                // discovery). The receiver decides what to do with it.
                if let Some((ip, source_port)) = self.observed_addrs.remove(&(transport, conn_id)) {
                    self.send_observed_addr(device, ip, source_port);
                }
                self.queue
                    .push_back(ToSwarm::GenerateEvent(BehaviourEvent::SessionEstablished {
                        peer_id: device,
                        connection_id: conn_id,
                        result,
                    }));
            }
            Err(e) => {
                tracing::warn!(%transport, error = %e, "handshake failed; closing");
                self.handshakes.remove(&(transport, conn_id));
                let peer_id = self.device_of(&transport).unwrap_or(transport);
                self.queue
                    .push_back(ToSwarm::GenerateEvent(BehaviourEvent::HandshakeFailed {
                        peer_id,
                        error: e.to_string(),
                    }));
            }
        }
    }

    fn on_session_frame(&mut self, transport: PeerId, conn_id: ConnectionId, frame: Frame) {
        let Some(device) = self.device_of(&transport) else {
            tracing::debug!(%transport, "dropping session frame: device not identified");
            return;
        };
        let Some((_, _, session)) = self.sessions.get_mut(&device) else {
            tracing::debug!(%device, "dropping session frame: no session for device");
            return;
        };
        let result = session.handle_frame(&frame);
        match result {
            Ok(Inbound::Message {
                msg_id,
                seq,
                body,
                created_ts_ms,
            }) => {
                let ack = session.encrypt_ack(msg_id, seq);
                self.notify_conn(transport, conn_id, vec![ack]);
                self.queue
                    .push_back(ToSwarm::GenerateEvent(BehaviourEvent::MessageReceived {
                        peer_id: device,
                        msg_id,
                        body,
                        ts_ms: created_ts_ms,
                    }));
            }
            Ok(Inbound::Ack { msg_id, ack_seq }) => {
                self.queue
                    .push_back(ToSwarm::GenerateEvent(BehaviourEvent::AckReceived {
                        peer_id: device,
                        msg_id,
                        ack_seq,
                    }));
            }
            Ok(Inbound::ObservedAddr {
                ip, source_port, ..
            }) => {
                self.queue.push_back(ToSwarm::GenerateEvent(
                    BehaviourEvent::ObservedAddrReported {
                        peer_id: device,
                        ip,
                        source_port,
                    },
                ));
            }
            Ok(Inbound::DialBackReq { addr, .. }) => {
                self.queue
                    .push_back(ToSwarm::GenerateEvent(BehaviourEvent::DialBackRequested {
                        peer_id: device,
                        addr,
                    }));
            }
            Ok(Inbound::DialBackRes {
                addr, reachable, ..
            }) => {
                self.queue
                    .push_back(ToSwarm::GenerateEvent(BehaviourEvent::DialBackResolved {
                        peer_id: device,
                        addr,
                        reachable,
                    }));
            }
            Err(e) => {
                tracing::warn!(%device, error = %e, "session error; dropping session");
                self.sessions.remove(&device);
                self.queue
                    .push_back(ToSwarm::GenerateEvent(BehaviourEvent::HandshakeFailed {
                        peer_id: device,
                        error: format!("session error: {e}"),
                    }));
            }
        }
    }

    fn flush_pending_sends(&mut self, device: PeerId, transport: PeerId, conn_id: ConnectionId) {
        let Some(queue) = self.pending_sends.remove(&device) else {
            return;
        };
        let Some((_, _, session)) = self.sessions.get_mut(&device) else {
            return;
        };
        let mut frames = Vec::new();
        for (msg_id, text) in queue {
            match session.encrypt_message(&text, msg_id) {
                Ok(frame) => frames.push(frame),
                Err(e) => {
                    tracing::warn!(%device, %msg_id, error = %e, "queued message failed to encrypt");
                }
            }
        }
        self.notify_conn(transport, conn_id, frames);
    }

    /// Peers we currently have an established session with.
    pub fn session_peers(&self) -> Vec<PeerId> {
        self.sessions.keys().copied().collect()
    }
}

impl NetworkBehaviour for SessionBehaviour {
    type ConnectionHandler = SessionHandler;
    type ToSwarm = BehaviourEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &libp2p::Multiaddr,
        _remote_addr: &libp2p::Multiaddr,
    ) -> Result<Self::ConnectionHandler, ConnectionDenied> {
        Ok(SessionHandler::new(false, peer))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &libp2p::Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<Self::ConnectionHandler, ConnectionDenied> {
        Ok(SessionHandler::new(true, peer))
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(established) => {
                self.connected.insert(established.peer_id);
                // Inbound connection: record where the DIALER is seen from.
                // This is the observed (source) address used for external
                // address discovery (M2.3).
                if let libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } =
                    &established.endpoint
                {
                    let ip = send_back_addr.iter().find_map(|p| match p {
                        libp2p::multiaddr::Protocol::Ip4(i) => Some(IpAddr::V4(i)),
                        libp2p::multiaddr::Protocol::Ip6(i) => Some(IpAddr::V6(i)),
                        _ => None,
                    });
                    let port = send_back_addr
                        .iter()
                        .find_map(|p| match p {
                            libp2p::multiaddr::Protocol::Tcp(p) => Some(p),
                            _ => None,
                        })
                        .unwrap_or(0);
                    if let Some(ip) = ip {
                        self.observed_addrs
                            .insert((established.peer_id, established.connection_id), (ip, port));
                    }
                }
                let peer_id = self
                    .device_of(&established.peer_id)
                    .unwrap_or(established.peer_id);
                self.queue
                    .push_back(ToSwarm::GenerateEvent(BehaviourEvent::PeerConnected {
                        peer_id,
                    }));
            }
            FromSwarm::ConnectionClosed(closed) => {
                let transport = closed.peer_id;
                self.observed_addrs
                    .remove(&(transport, closed.connection_id));
                let device = self.device_of(&transport);
                self.connected.remove(&transport);
                self.handshakes.remove(&(transport, closed.connection_id));
                if let Some((t, conn, _)) = self.sessions.get(&device.unwrap_or(transport)) {
                    if *conn == closed.connection_id && *t == transport {
                        tracing::debug!(
                            transport = %transport,
                            device = ?device.map(|d| d.to_base58()),
                            conn = ?closed.connection_id,
                            remaining = closed.remaining_established,
                            "session removed on connection close"
                        );
                        self.sessions.remove(&device.unwrap_or(transport));
                        if let Some(d) = device {
                            self.peer_names.remove(&d);
                        }
                    }
                } else {
                    tracing::debug!(
                        transport = %transport,
                        device = ?device.map(|d| d.to_base58()),
                        conn = ?closed.connection_id,
                        remaining = closed.remaining_established,
                        "connection closed without matching session"
                    );
                }
                if closed.remaining_established == 0 {
                    self.queue.push_back(ToSwarm::GenerateEvent(
                        BehaviourEvent::PeerDisconnected {
                            peer_id: device.unwrap_or(transport),
                        },
                    ));
                }
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: HandlerToBehaviour,
    ) {
        self.on_handler_event(peer_id, connection_id, event)
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, ConnectionHandlerEvent<SessionUpgrade, (), BehaviourToHandler>>>
    {
        // Expire handshakes that have been in flight too long.
        let now = Instant::now();
        let expired: Vec<(PeerId, ConnectionId)> = self
            .handshakes
            .iter()
            .filter(|(_, (hs, _))| hs.timed_out(now))
            .map(|((peer, conn), _)| (*peer, *conn))
            .collect();
        for (transport, conn) in expired {
            tracing::warn!(%transport, ?conn, "handshake timed out; closing");
            self.handshakes.remove(&(transport, conn));
            let peer_id = self.device_of(&transport).unwrap_or(transport);
            self.queue
                .push_back(ToSwarm::GenerateEvent(BehaviourEvent::HandshakeFailed {
                    peer_id,
                    error: "handshake timed out".into(),
                }));
        }
        if let Some(ev) = self.queue.pop_front() {
            return Poll::Ready(ev);
        }
        Poll::Pending
    }
}
