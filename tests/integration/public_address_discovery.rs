//! End-to-end integration test (M2.3): external address discovery,
//! reachability validation, and public address advertisement.
//!
//! - B dials the bootstrap anchor A; A observes B's source address
//!   (127.0.0.1 on loopback) and reports it over the authenticated session.
//! - B classifies the observed address (the `external_ips` seam stands in
//!   for a public IP in this loopback environment), requests a dial-back
//!   validation, and A probes the candidate `/ip4/127.0.0.1/tcp/9252`.
//! - On a successful probe B validates the address and publishes it in its
//!   signed DHT record; a consumer C then discovers that record, dials the
//!   advertised address, and exchanges an authenticated message.

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
    node_with_ips(storage, id, port, bootstrap, Vec::new())
}

fn node_with_ips(
    storage: Storage,
    id: DeviceIdentity,
    port: u16,
    bootstrap: Vec<BootstrapPeer>,
    external_ips: Vec<std::net::IpAddr>,
) -> Node {
    Node::new(
        id,
        storage,
        NodeOptions {
            listen_port: port,
            bootstrap,
            external_ips,
            relay: None,
            relay_server: false,
        },
    )
    .unwrap()
}

#[tokio::test]
async fn external_address_discovery_validation_and_advertisement() {
    crate::init_tracing();

    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let dir_c = tempfile::tempdir().unwrap();

    let sa = Storage::new(dir_a.path().to_path_buf());
    let sb = Storage::new(dir_b.path().to_path_buf());
    let sc = Storage::new(dir_c.path().to_path_buf());

    let ida = identity_for(&sa, "anchor");
    let idb = identity_for(&sb, "owner");
    let idc = identity_for(&sc, "consumer");

    let mut a = node_at(sa, ida, 9251, vec![]);
    let peer_a = a.identity.peer_id;
    let bootstrap_a = BootstrapPeer::parse(&format!("{peer_a}@/ip4/127.0.0.1/tcp/9251")).unwrap();

    // B advertises 127.0.0.1 as an "external" address via the test seam.
    let mut b = node_with_ips(
        sb,
        idb,
        9252,
        vec![bootstrap_a.clone()],
        vec!["127.0.0.1".parse().unwrap()],
    );
    let peer_b = b.identity.peer_id;

    let mut c = node_at(sc, idc, 9253, vec![bootstrap_a]);

    let a_task = tokio::spawn(async move { a.wait_for(|_| false, TIMEOUT).await });

    // 1. B dials A (bootstrap), which observes B's source address and
    //    reports it; B must end up validating and publishing the candidate.
    let _ = b.lookup(peer_a);
    let observed = b
        .wait_for(
            |ev| {
                matches!(
                    ev,
                    BehaviourEvent::ObservedAddrReported { peer_id, .. } if *peer_id == peer_a
                )
            },
            Duration::from_secs(30),
        )
        .await;
    assert!(observed.is_some(), "A must report B's observed address");

    let advertised = "/ip4/127.0.0.1/tcp/9252";
    let published = b
        .wait_for(
            |ev| {
                matches!(
                    ev,
                    BehaviourEvent::DialBackResolved { addr, reachable, .. }
                        if addr.to_string() == advertised && *reachable
                )
            },
            TIMEOUT,
        )
        .await;
    assert!(
        published.is_some(),
        "the dial-back probe must validate B's candidate"
    );
    assert!(
        b.validated_public_addrs()
            .iter()
            .any(|a| a.to_string() == advertised),
        "B must hold the validated public address"
    );

    // 2. B stays alive in the background to receive the consumer's message.
    let b_task = tokio::spawn(async move {
        let got = b
            .wait_for(
                |ev| {
                    matches!(
                        ev,
                        BehaviourEvent::MessageReceived { body, .. } if body == "hello via public address"
                    )
                },
                TIMEOUT,
            )
            .await;
        b.run_for(Duration::from_secs(10)).await;
        got
    });

    // 3. A consumer discovers the record and dials the advertised address.
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

    // 4. Message + authenticated acknowledgement over the advertised address.
    let msg_id = c.send_message(peer_b, "hello via public address".to_string());
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

    let received = b_task.await.expect("background B task panicked");
    assert!(received.is_some(), "B must receive the message");
    a_task.abort();
    let _ = a_task.await;
}
