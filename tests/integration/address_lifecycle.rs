//! Integration test (M2.1): dynamic address lifecycle and DHT republishing.
//!
//! Three real nodes over loopback: A is the DHT anchor, B is the node whose
//! reachable address set "changes" (updated through the same plumbing the
//! event handlers and the interface scanner use), and C looks B up through
//! the DHT.
//!
//! Verifies that when B's address set changes, B re-signs and re-publishes
//! its record, and C's next lookup returns the NEW verified record (not the
//! stale one).

use std::time::Duration;

use jeangrey::identity::DeviceIdentity;
use jeangrey::node::{BootstrapPeer, Node, NodeOptions};
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
            external_ips: Vec::new(),
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

/// Drive B and C alternately (both must keep polling for their DHT queries
/// to progress) until `check(c)` holds.
async fn drive_both_until<F>(b: &mut Node, c: &mut Node, mut check: F, timeout: Duration)
where
    F: FnMut(&Node) -> bool,
{
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if check(c) {
            return;
        }
        b.run_for(Duration::from_millis(250)).await;
        c.run_for(Duration::from_millis(250)).await;
    }
    panic!("condition not met within {timeout:?}");
}

#[tokio::test]
async fn address_change_is_republished_and_discovered() {
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

    let mut a = node_at(sa, ida, 9231, vec![]);
    let peer_a = a.identity.peer_id;
    let bootstrap_a = BootstrapPeer::parse(&format!("{peer_a}@/ip4/127.0.0.1/tcp/9231")).unwrap();

    let mut b = node_at(sb, idb, 9232, vec![bootstrap_a.clone()]);
    let peer_b = b.identity.peer_id;

    let mut c = node_at(sc, idc, 9233, vec![bootstrap_a]);

    let a_task = tokio::spawn(async move { a.wait_for(|_| false, TIMEOUT).await });

    // B settles its listen addresses (NewListenAddr -> current_addrs ->
    // record published; loopback survives the interface filter).
    drive_until(&mut b, |n| !n.current_addrs().is_empty(), TIMEOUT).await;

    // C discovers B's ORIGINAL record through the DHT (via the anchor).
    // B keeps polling so its put-record query actually completes.
    let _ = c.lookup(peer_b);
    drive_both_until(
        &mut b,
        &mut c,
        |n| n.records.iter().any(|(p, _)| *p == peer_b),
        TIMEOUT,
    )
    .await;
    let original = c
        .records
        .get(&peer_b)
        .expect("B's record must be discovered");
    assert!(
        original
            .addrs
            .iter()
            .any(|a| a.to_string().contains("127.0.0.1/tcp/9232")),
        "original record must advertise B's first listen address: {:?}",
        original.addrs
    );

    // B's reachable set changes (a Wi-Fi switch: the old listen address is
    // gone, a new one appears). These are the same methods the event
    // handlers use; the publish mirrors the ExpiredListenAddr handler.
    let old_addr: jeangrey::Multiaddr = "/ip4/127.0.0.1/tcp/9232".parse().unwrap();
    let new_addr: jeangrey::Multiaddr = "/ip4/127.0.0.1/tcp/9242".parse().unwrap();
    assert!(b.note_listen_addr_gone(&old_addr));
    assert!(b.note_listen_addr(new_addr));
    b.publish_record();
    // Let B's put-record query flush to the DHT.
    b.run_for(Duration::from_secs(2)).await;

    // C looks B up again: the DHT now returns the NEW record.
    c.records.clear();
    let _ = c.lookup(peer_b);
    drive_both_until(
        &mut b,
        &mut c,
        |n| {
            n.records.get(&peer_b).is_some_and(|r| {
                r.addrs
                    .iter()
                    .any(|a| a.to_string().contains("127.0.0.1/tcp/9242"))
            })
        },
        TIMEOUT,
    )
    .await;
    let updated = c
        .records
        .get(&peer_b)
        .expect("B's updated record must be discovered");
    assert!(
        !updated
            .addrs
            .iter()
            .any(|a| a.to_string().contains("127.0.0.1/tcp/9232")),
        "updated record must not advertise the stale address: {:?}",
        updated.addrs
    );

    a_task.abort();
    let _ = a_task.await;
}
