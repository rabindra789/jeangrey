//! End-to-end integration test (M9): three real nodes over the loopback
//! interface exercising the full MVP-1 flow —
//!
//! - Kademlia DHT discovery through a bootstrap node (B and C bootstrap to A),
//! - retrieval and cryptographic verification of address records,
//! - direct dialing and the ML-KEM + ML-DSA authenticated handshake,
//! - AEAD-encrypted message delivery and the authenticated acknowledgement.

use std::time::Duration;

use jeangrey::identity::DeviceIdentity;
use jeangrey::node::{BehaviourEvent, BootstrapPeer, Node, NodeOptions};
use jeangrey::storage::Storage;

const TIMEOUT: Duration = Duration::from_secs(90);

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
        },
    )
    .unwrap()
}

#[tokio::test]
async fn discovery_session_and_message_round_trip() {
    crate::init_tracing();

    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let dir_c = tempfile::tempdir().unwrap();

    let sa = Storage::new(dir_a.path().to_path_buf());
    let sb = Storage::new(dir_b.path().to_path_buf());
    let sc = Storage::new(dir_c.path().to_path_buf());

    let ida = identity_for(&sa, "alpha");
    let idb = identity_for(&sb, "bravo");
    let idc = identity_for(&sc, "charlie");

    let mut a = node_at(sa, ida, 9221, vec![]);
    let peer_a = a.identity.peer_id;

    let bootstrap_a = BootstrapPeer::parse(&format!("{peer_a}@/ip4/127.0.0.1/tcp/9221")).unwrap();

    let mut b = node_at(sb, idb, 9222, vec![bootstrap_a.clone()]);
    let peer_b = b.identity.peer_id;

    let mut c = node_at(sc, idc, 9223, vec![bootstrap_a]);

    // A and B run in the background while C drives the scenario.
    let a_task = tokio::spawn(async move { a.wait_for(|_| false, TIMEOUT).await });
    let b_task = tokio::spawn(async move {
        let got = b
            .wait_for(
                |ev| {
                    matches!(
                        ev,
                        BehaviourEvent::MessageReceived { body, .. } if body == "hello from charlie"
                    )
                },
                TIMEOUT,
            )
            .await;
        // Keep B polling after the message so its authenticated ack is
        // actually flushed to the wire before the node is dropped.
        b.run_for(Duration::from_secs(10)).await;
        got
    });

    // 1. Discovery: look up B's address record via the DHT (through A),
    //    verify its ML-DSA signature, and dial the authenticated address set.
    let _ = c.lookup(peer_b);
    let established = c
        .wait_for(
            |ev| {
                matches!(
                    ev,
                    BehaviourEvent::SessionEstablished { peer_id, .. } if *peer_id == peer_b
                )
            },
            TIMEOUT,
        )
        .await;
    assert!(established.is_some(), "C must establish a session with B");

    assert!(
        c.records.iter().any(|(p, _)| *p == peer_b),
        "B's address record must have been retrieved and verified"
    );

    // 2. Send a message; B must acknowledge it with an authenticated ack.
    let msg_id = c.send_message(peer_b, "hello from charlie".to_string());
    let acked = c
        .wait_for(
            |ev| {
                matches!(
                    ev,
                    BehaviourEvent::AckReceived { peer_id, msg_id: m, .. }
                        if *peer_id == peer_b && *m == msg_id
                )
            },
            Duration::from_secs(30),
        )
        .await;
    assert!(acked.is_some(), "B must acknowledge the message");

    // 3. B must have received the decrypted, authenticated message.
    let received = b_task.await.expect("background B task panicked");
    assert!(received.is_some(), "B must receive the message");
    // A was only needed as bootstrap/DHT anchor while the scenario ran.
    a_task.abort();
    let _ = a_task.await;
}
