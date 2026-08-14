//! End-to-end integration test (M9): device identity and message metadata
//! persist across process restarts, and a restarted node re-uses the same
//! self-certifying Peer ID.

use std::time::Duration;

use jeangrey::identity::DeviceIdentity;
use jeangrey::node::{Node, NodeOptions};
use jeangrey::storage::{HistoryKind, NodeConfig, Storage};

#[tokio::test]
async fn identity_and_history_persist_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();

    // First run: create the identity, start the node, record some history.
    let storage = Storage::new(path.clone());
    storage.ensure().unwrap();
    let id = DeviceIdentity::generate("persistent");
    storage.save_identity(&id).unwrap();
    storage.save_config(&NodeConfig { listen_port: 0 }).unwrap();

    let node = Node::new(
        id,
        Storage::new(path.clone()),
        NodeOptions {
            listen_port: 0,
            bootstrap: vec![],
        },
    )
    .unwrap();
    let peer_id = node.identity.peer_id;
    node.storage
        .append_history(HistoryKind::Sent {
            peer: "12D3KooWNotAPeer".to_string(),
            msg_id: 7,
            status: "delivered".to_string(),
        })
        .unwrap();
    drop(node);

    // Second run: the same data directory must restore the same identity.
    let storage2 = Storage::new(path.clone());
    let loaded = storage2
        .load_identity()
        .expect("storage readable")
        .expect("identity persists");
    assert_eq!(loaded.peer_id, peer_id, "restarted node keeps its Peer ID");
    assert_eq!(loaded.user.user_name, "persistent");

    let config = storage2.load_config().unwrap();
    assert_eq!(config.listen_port, 0);

    let history = std::fs::read_to_string(path.join("history.jsonl")).unwrap();
    assert!(
        history.contains("\"event\":\"sent\"") && history.contains("\"msg_id\":7"),
        "history must survive restarts"
    );

    // And a restarted node can actually run.
    let mut restarted = Node::new(
        loaded,
        Storage::new(path),
        NodeOptions {
            listen_port: 0,
            bootstrap: vec![],
        },
    )
    .unwrap();
    restarted.run_for(Duration::from_secs(2)).await;
    assert!(
        !restarted.our_listen_addrs().is_empty(),
        "restarted node must listen"
    );
}
