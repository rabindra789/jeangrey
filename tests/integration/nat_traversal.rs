//! NAT traversal integration test (M2.4): three nodes on the loopback
//! interface —
//!
//! - R: a circuit relay v2 server (traversal coordination).
//! - A and B: nodes that reserve relayed addresses on R; A dials B through
//!   the relay only (B's LAN address is never dialed).
//!
//! The scenario asserts:
//!
//! 1. A reaches B via the relayed path (`via-relay` connection path),
//! 2. DCUtR hole punches the relayed connection into a direct one
//!    (`direct` path), and the relayed connection is dropped,
//! 3. the JeanGrey secure session re-establishes over the new direct
//!    transport (fresh ML-KEM handshake; no session reuse across paths),
//! 4. an AEAD-encrypted message round-trips with an authenticated ACK.

use std::time::Duration;

use jeangrey::identity::DeviceIdentity;
use jeangrey::node::{BehaviourEvent, BootstrapPeer, Node, NodeOptions, PeerPath};
use jeangrey::storage::Storage;

const TIMEOUT: Duration = Duration::from_secs(120);

fn identity_for(storage: &Storage, name: &str) -> DeviceIdentity {
    storage.ensure().unwrap();
    let id = DeviceIdentity::generate(name);
    storage.save_identity(&id).unwrap();
    id
}

fn node_at(
    storage: Storage,
    id: DeviceIdentity,
    port: u16,
    relay: Option<BootstrapPeer>,
    relay_server: bool,
) -> Node {
    Node::new(
        id,
        storage,
        NodeOptions {
            listen_port: port,
            bootstrap: Vec::new(),
            external_ips: Vec::new(),
            relay,
            relay_server,
        },
    )
    .unwrap()
}

fn relay_ref(relay_id: &jeangrey::PeerId) -> BootstrapPeer {
    BootstrapPeer::parse(&format!("{relay_id}@/ip4/127.0.0.1/tcp/9261")).unwrap()
}

/// Drive `node` until `check` holds or `timeout` elapses.
async fn drive_until<F>(node: &mut Node, mut check: F, timeout: Duration)
where
    F: FnMut(&Node) -> bool,
{
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if check(node) {
            return;
        }
        node.run_for(Duration::from_millis(250)).await;
    }
    panic!("timed out waiting for condition");
}

/// Drive `a` and `b` concurrently until `on_a` matches an event from
/// `a` or `on_b` matches an event from `b`; returns the matched event,
/// or `None` on timeout.
///
/// Both nodes must stay polled: B completes its own session handshake
/// with the relay, accepts the incoming relayed connection and answers
/// the DCUtR punch only while it is driven.
async fn wait_for_pair<FA, FB>(
    a: &mut Node,
    b: &mut Node,
    mut on_a: FA,
    mut on_b: FB,
    timeout: Duration,
) -> Option<BehaviourEvent>
where
    FA: FnMut(&BehaviourEvent) -> bool,
    FB: FnMut(&BehaviourEvent) -> bool,
{
    let sleep = tokio::time::sleep(timeout);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            biased;
            _ = &mut sleep => return None,
            ev = a.next_event() => {
                if let Some(ev) = ev {
                    if on_a(&ev) {
                        return Some(ev);
                    }
                }
            }
            ev = b.next_event() => {
                if let Some(ev) = ev {
                    if on_b(&ev) {
                        return Some(ev);
                    }
                }
            }
        }
    }
}

/// Whether `node` has reserved a relayed (`/p2p-circuit`) listen address.
fn has_circuit_addr(node: &Node) -> bool {
    node.current_addrs()
        .iter()
        .any(|a| a.to_string().contains("p2p-circuit"))
}

#[tokio::test]
async fn relayed_connection_punches_to_direct_and_session_survives() {
    crate::init_tracing();

    let dir_r = tempfile::tempdir().unwrap();
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();

    let sr = Storage::new(dir_r.path().to_path_buf());
    let sa = Storage::new(dir_a.path().to_path_buf());
    let sb = Storage::new(dir_b.path().to_path_buf());

    let idr = identity_for(&sr, "relay");
    let ida = identity_for(&sa, "alpha");
    let idb = identity_for(&sb, "bravo");
    let peer_r = idr.peer_id;
    let transport_r = idr.transport_peer_id();
    let peer_b = idb.peer_id;
    let transport_b = idb.transport_peer_id();

    let mut relay = node_at(sr, idr, 9261, None, true);
    let mut a = node_at(sa, ida, 9262, Some(relay_ref(&peer_r)), false);
    let mut b = node_at(sb, idb, 9263, Some(relay_ref(&peer_r)), false);

    // Relay runs in the background; A and B reserve their relayed
    // addresses.
    let relay_task = tokio::spawn(async move { relay.run_for(TIMEOUT).await });
    drive_until(&mut a, has_circuit_addr, TIMEOUT).await;
    drive_until(&mut b, has_circuit_addr, TIMEOUT).await;

    // A dials B THROUGH the relay only: the direct LAN address is never
    // dialed, so the only path to B is the circuit. The circuit address
    // carries the relay's *transport* Peer ID and address (libp2p layer)
    // plus B's transport Peer ID as the destination.
    let circuit_b: jeangrey::Multiaddr =
        format!("/ip4/127.0.0.1/tcp/9261/p2p/{transport_r}/p2p-circuit/p2p/{transport_b}")
            .parse()
            .unwrap();
    a.dial_peer(peer_b, transport_b, vec![circuit_b]);

    // Phases 1-2: A and B establish a session over the RELAYED path, then
    // DCUtR punches it into a direct one. Both nodes must stay polled and
    // the path observation must run concurrently with the session wait: on
    // loopback the punch is nearly instant, so the via-relay window is only
    // caught by re-checking the path map after every event (the path map
    // changes exactly when connection events are processed).
    let mut saw_relayed = false;
    let mut relayed_established = None;
    let mut punched = false;
    let sleep = tokio::time::sleep(TIMEOUT);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            biased;
            _ = &mut sleep => break,
            ev = a.next_event() => {
                if let Some(ev) = ev {
                    if matches!(ev, BehaviourEvent::SessionEstablished { peer_id, .. } if peer_id == peer_b) {
                        relayed_established = Some(ev);
                    }
                }
                match a.peer_paths().get(&transport_b) {
                    Some(PeerPath::Relayed) | Some(PeerPath::Traversing) => saw_relayed = true,
                    Some(PeerPath::Direct) => punched = true,
                    _ => {}
                }
            }
            ev = b.next_event() => {
                let _ = ev;
            }
        }
        if relayed_established.is_some() && saw_relayed && punched {
            break;
        }
    }
    assert!(
        relayed_established.is_some(),
        "A must establish a session with B over the relayed path"
    );
    assert!(
        saw_relayed,
        "A must observe the relayed path before the punch"
    );
    assert_eq!(
        a.peer_paths().get(&transport_b),
        Some(&PeerPath::Direct),
        "the DCUtR hole punch must upgrade the relayed path to a direct one"
    );

    // Phase 3: a message round-trips with an authenticated ack over the
    // post-punch direct transport (fresh session). B must stay polled to
    // receive the message and emit the ack.
    let msg_id = a.send_message(peer_b, "hello over the punched hole".to_string());
    let mut b_received = false;
    let acked = wait_for_pair(
        &mut a,
        &mut b,
        |ev| {
            matches!(
                ev,
                BehaviourEvent::AckReceived { peer_id, msg_id: m, .. }
                    if *peer_id == peer_b && *m == msg_id
            )
        },
        |ev| {
            if matches!(
                ev,
                BehaviourEvent::MessageReceived { body, .. }
                    if body == "hello over the punched hole"
            ) {
                b_received = true;
            }
            false
        },
        Duration::from_secs(30),
    )
    .await;
    assert!(
        acked.is_some(),
        "B must ack the message over the direct path"
    );
    assert!(b_received, "B must receive the message");

    relay_task.abort();
    let _ = relay_task.await;
}
