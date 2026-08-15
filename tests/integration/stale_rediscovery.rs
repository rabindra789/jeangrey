//! Integration test (M2.2): stale address detection and dynamic rediscovery.
//!
//! Four real nodes over loopback:
//!
//!   A     DHT anchor (9241)
//!   B1    device X at 9242 (original record: 127.0.0.1/tcp/9242)
//!   C     looks X up, establishes a session (caches B1's record), then
//!         loses the session when B1 dies
//!   B2    the SAME device X at 9244 (same identity, loaded from storage;
//!         new record: 127.0.0.1/tcp/9244), started only after B1 is gone:
//!         two live connections from the same device/transport id would
//!         collide in the session layer, so B1 must be dead first
//!
//! Verifies the full recovery chain: cached old address -> dial fails ->
//! invalidate stale candidate -> Kademlia lookup -> new signed address ->
//! reconnect -> fresh PQC session -> message + ACK.

use std::time::Duration;

use jeangrey::identity::DeviceIdentity;
use jeangrey::node::{BootstrapPeer, Node, NodeOptions};
use jeangrey::storage::Storage;
use jeangrey::transport::BehaviourEvent;

const TIMEOUT: Duration = Duration::from_secs(120);
const BACKGROUND_LIFETIME: Duration = Duration::from_secs(600);

fn identity_for(storage: &Storage, name: &str) -> DeviceIdentity {
    storage.ensure().unwrap();
    let id = DeviceIdentity::generate(name);
    storage.save_identity(&id).unwrap();
    id
}

fn node_at(storage: Storage, id: DeviceIdentity, port: u16, bootstrap: Vec<BootstrapPeer>) -> Node {
    Node::new(
        id,
        storage,
        NodeOptions {
            listen_port: port,
            bootstrap,
            external_ips: Vec::new(),
            relay: None,
            relay_server: false,
        },
    )
    .unwrap()
}

async fn drive_until<F>(node: &mut Node, mut check: F, timeout: Duration)
where
    F: FnMut(&Node) -> bool,
{
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if check(node) {
            return;
        }
        node.run_for(Duration::from_millis(500)).await;
    }
    panic!("condition not met within {timeout:?}");
}

#[tokio::test]
async fn stale_cached_address_recovers_via_rediscovery() {
    crate::init_tracing();

    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let dir_c = tempfile::tempdir().unwrap();

    let sa = Storage::new(dir_a.path().to_path_buf());
    let sb = Storage::new(dir_b.path().to_path_buf());
    let sc = Storage::new(dir_c.path().to_path_buf());

    let ida = identity_for(&sa, "anchor");
    let idb = identity_for(&sb, "mover");
    let idc = identity_for(&sc, "looker");

    let mut a = node_at(sa, ida, 9241, vec![]);
    let peer_a = a.identity.peer_id;
    let bootstrap_a = BootstrapPeer::parse(&format!("{peer_a}@/ip4/127.0.0.1/tcp/9241")).unwrap();

    // Phase 1: nodes come up ONE AT A TIME. On Windows loopback, two
    // simultaneous dials to the same destination from one process can race
    // for the same source port (WSAEADDRINUSE), so every bootstrap dial is
    // driven to completion before the next node starts.
    let a_task = tokio::spawn(async move { a.wait_for(|_| false, BACKGROUND_LIFETIME).await });
    let mut b1 = node_at(
        Storage::new(dir_b.path().to_path_buf()),
        idb,
        9242,
        vec![bootstrap_a.clone()],
    );
    let peer_b = b1.identity.peer_id;
    drive_until(&mut b1, |n| !n.connected_peers().is_empty(), TIMEOUT).await;
    let b1_task = tokio::spawn(async move { b1.wait_for(|_| false, BACKGROUND_LIFETIME).await });

    // C bootstraps (its own dial), then looks X up: its kad queries reuse
    // the bootstrap connection instead of dialing the anchor again.
    let mut c = node_at(sc, idc, 9243, vec![bootstrap_a.clone()]);
    drive_until(&mut c, |n| !n.connected_peers().is_empty(), TIMEOUT).await;
    let _ = c.lookup(peer_b);
    drive_until(&mut c, |n| n.has_session(&peer_b), TIMEOUT).await;
    assert!(
        c.records
            .get(&peer_b)
            .expect("C must have cached B1's verified record")
            .addrs
            .iter()
            .any(|a| a.to_string().contains("127.0.0.1/tcp/9242")),
        "cached record must advertise B1's listen address"
    );

    // Phase 2: B1 dies (the old address becomes unreachable). C's session
    // is lost; C re-dials the CACHED (stale) 9242 address, the dial fails,
    // the candidate is invalidated, and the dynamic rediscovery starts.
    b1_task.abort();
    let _ = b1_task.await;

    // Phase 3: the same device X comes up at a NEW address (9244) with the
    // same identity (loaded from B's storage) and publishes its new record.
    // Only after B1 is dead: two live connections from the same device
    // (transport) id would collide in the session layer.
    let idb2 = Storage::new(dir_b.path().to_path_buf())
        .load_identity()
        .unwrap()
        .expect("identity saved by B1 must load");
    assert_eq!(idb2.peer_id, peer_b, "B2 must be the same device as B1");
    let mut b2 = node_at(sb, idb2, 9244, vec![bootstrap_a]);
    drive_until(&mut b2, |n| !n.connected_peers().is_empty(), TIMEOUT).await;
    // Give B2's put-record query time to flush to the anchor's store.
    b2.run_for(Duration::from_secs(2)).await;
    let b2_task = tokio::spawn(async move { b2.wait_for(|_| false, BACKGROUND_LIFETIME).await });

    // Phase 4: the dynamic rediscovery returns B2's new record -> reconnect.
    drive_until(
        &mut c,
        |n| {
            n.has_session(&peer_b)
                && n.records.get(&peer_b).is_some_and(|r| {
                    r.addrs
                        .iter()
                        .any(|a| a.to_string().contains("127.0.0.1/tcp/9244"))
                        && !r
                            .addrs
                            .iter()
                            .any(|a| a.to_string().contains("127.0.0.1/tcp/9242"))
                })
        },
        TIMEOUT,
    )
    .await;

    // Phase 5: fresh PQC session carries a message to an authenticated ACK.
    let msg_id = c.send_message(peer_b, "hello after rediscovery".to_string());
    let ack = c
        .wait_for(
            |ev| {
                matches!(
                    ev,
                    BehaviourEvent::AckReceived {
                        peer_id,
                        msg_id: m,
                        ..
                    } if *peer_id == peer_b && *m == msg_id
                )
            },
            TIMEOUT,
        )
        .await;
    assert!(
        ack.is_some(),
        "message must be acknowledged after reconnect"
    );

    let final_record = c
        .records
        .get(&peer_b)
        .expect("C must hold the recovered record");
    assert!(
        !final_record
            .addrs
            .iter()
            .any(|a| a.to_string().contains("127.0.0.1/tcp/9242")),
        "stale address must stay gone from the recovered record: {:?}",
        final_record.addrs
    );

    b2_task.abort();
    let _ = b2_task.await;
    a_task.abort();
    let _ = a_task.await;
}
