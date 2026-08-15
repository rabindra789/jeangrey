# JeanGrey MVP-1 — Testing

## Test suites

| suite | command | scope |
|---|---|---|
| unit | `cargo test --lib` | 78 tests: crypto (KEM/ML-DSA/HKDF), handshake (happy path, tampering, timeout), framing (malformed/truncated), session (encryption, replay, ack round trip, control frames), records (sign/verify, tamper, skew), identity (Peer ID derivation, key separation), address lifecycle (local-address filtering, change detection), stale-record handling (dial-failure invalidation, rediscovery scheduling, dedup), external-address discovery (classification, candidate lifecycle, validation/rejection, expiry, re-validation, probe dedup/timeout) |
| integration | `cargo test --test integration` | six end-to-end tests (below) |
| all | `cargo test --all-targets` | everything; also `cargo clippy --all-targets` and `cargo fmt --check` are clean |

### Integration tests (`tests/integration/`)

- `messaging::discovery_session_and_message_round_trip` — three real nodes
  over loopback: A is the DHT bootstrap anchor, B and C bootstrap to A; C
  looks up B's address record through the DHT, verifies it, dials, completes
  the ML-KEM + ML-DSA handshake, sends "hello from charlie", B authenticates
  and acknowledges, C verifies the authenticated ack, B verifies the
  decrypted message. Runtime ~16 s.
- `address_lifecycle::address_change_is_republished_and_discovered` —
  three real nodes over loopback: B's reachable address set changes
  (old listen address removed, new one added); B re-signs and re-publishes
  its record; C's subsequent lookup returns the NEW verified record and
  the stale address is gone. Runtime ~9 s. This is the M2.1 regression
  test for the observed Android network-change failure.
- `stale_rediscovery::stale_cached_address_recovers_via_rediscovery` —
  four real nodes over loopback (A anchor, B1 at 9242, C, B2 at 9244 with
  B1's identity): C caches B1's record and forms a session; B1 dies; C's
  session is lost, the cached 9242 re-dial fails (connection refused), the
  stale candidates are invalidated, the DHT lookup returns B2's fresh
  9244 record, C reconnects and a message round-trips with an
  authenticated ack. Runtime ~10 s. This is the M2.2 regression test.
  On Windows the test brings nodes up one at a time so no two dials to
  the same destination race for a source port (`WSAEADDRINUSE`).
- `persistence::...` — identity and configuration survive storage
  round-trips.
- `public_address_discovery::external_address_discovery_validation_and_advertisement` —
  three real nodes over loopback (A anchor at 9251, B at 9252 with the
  `external_ips` seam declaring 127.0.0.1 "public", C at 9253): B dials A,
  A observes B's source address and reports it over the session; B forms
  the candidate, A probes it back (dial-back validation), B validates and
  publishes; C then discovers B's record through the DHT, dials the
  advertised address, and a message round-trips with an authenticated
  ack. Runtime ~12 s. This is the M2.3 regression test. The loopback
  test seam (`NodeOptions::external_ips`) stands in for a public IP —
  on Windows the loopback source is always seen as 127.0.0.1, so a real
  "external" observed address cannot be produced without it.
- `nat_traversal::nat_traversal_relayed_session_punch_and_round_trip` —
  three real nodes over loopback (relay server R at 9261, A at 9262, B at
  9263): A and B reserve circuits through R, A dials B via the full-form
  circuit address (`/p2p/<relay>/p2p-circuit/p2p/<bravo>`), a session
  establishes over the relayed path, DCUtR punches it into a direct
  connection (observed on both sides: `connection path upgraded` +
  `nat traversal succeeded`), the path map shows `Direct` (reachable only
  via the punch, since the test never dials B directly), and a message
  round-trips with an authenticated ack. Runtime ~2 s. This is the M2.4
  regression test. Two test-harness lessons from earlier failing runs:
  (1) a relayed path requires BOTH nodes to be polled continuously — a
  test that stops polling B after it learned its circuit address starves
  the relay's handshake frames to B, the 30 s handshake timeout closes the
  circuit, and A's pending dial fails (`unexpected end of file`) — hence
  `Node::next_event` (src/node.rs) and the `wait_for_pair` helper that
  select-poll both nodes; (2) on loopback the DCUtR punch (~110 ms after
  the relayed connection) beats the ML-KEM/ML-DSA handshake, so the
  via-relay path state would be missed by sequential phase polling — the
  path observation runs concurrently with the session wait and re-checks
  the path map after every event.

### Environment knobs

| variable | effect |
|---|---|
| `JEANGREY_TEST_LOG` | tracing filter (e.g. `jeangrey=debug`); when set, logs are printed unconditionally with `node = <name>` attribution on every line |
| `JEANGREY_DATA_DIR` | overrides the data directory (CLI) |

## Manual LAN walkthrough

1. Machine A (DHT anchor):
   ```sh
   jeangrey init --name hub
   jeangrey node
   # note the printed peer id, e.g. Qm...; hub listens on :9000
   ```
2. Machine B:
   ```sh
   jeangrey init --name laptop
   jeangrey node --bootstrap Qm...@/ip4/<hub-lan-ip>/tcp/9000
   ```
3. From either node:
   ```
   > peers          # wait ~30 s for DHT propagation, then sessions list
   > send Qm... "hello from the LAN"
   sent (id 123); awaiting acknowledgement...
   acknowledged by peer Qm... (id 123)
   ```
   The receiver's terminal logs `message: ...` with node attribution.

## Android (Termux) build

A single binary can be cross-compiled on Windows for an Android phone:

1. Install the Android NDK and point cargo at its clang in
   `~/.cargo/config.toml` (paths escaped for TOML):
   ```toml
   [target.aarch64-linux-android]
   linker = "C:\\android-ndk-r27d\\toolchains\\llvm\\prebuilt\\windows-x86_64\\bin\\aarch64-linux-android24-clang.cmd"
   ar = "C:\\android-ndk-r27d\\toolchains\\llvm\\prebuilt\\windows-x86_64\\bin\\llvm-ar.exe"
   ```
2. `rustup target add aarch64-linux-android` (if not present), then
   `cargo build --release --target aarch64-linux-android`.
3. The artifact is `target\aarch64-linux-android\release\jeangrey`
   (6–7 MB, statically linked, runs on Android 7+ / API 24+).

On the phone:

1. Install Termux (F-Droid). Copy the binary in — e.g. `adb push jeangrey
   /sdcard/Download/`, then in Termux:
   ```
   termux-setup-storage          # grant storage access
   cp /sdcard/Download/jeangrey ~/
   chmod +x ~/jeangrey
   ```
2. Run it like on any other machine (same LAN Wi-Fi as the PC):
   ```
   ~/jeangrey init --name phone
   ~/jeangrey node --bootstrap <hub-id>@/ip4/<PC-LAN-IP>/tcp/9000
   ```

## MVP-1 acceptance run — 2026-08-13 (Windows hub ↔ Android phone)

Real end-to-end run over a home Wi-Fi LAN: the anchor (`hub`) on Windows
(PowerShell, native release build), the second node (`phone`) on an Android
phone in Termux (aarch64 cross-compiled binary). Both nodes on the same
Wi-Fi (192.168.29.0/24); phone at 192.168.29.27, PC at 192.168.29.40.

Phone — Termux:

```
~ $ ./jeangrey init --name phone
identity created
  user:        phone (id 5b392309)
  device peer: QmTgNtf77T9RyeGtHTJGUm2p8CdYaTFsXuLhnG1P6B3tTE
  short:       QmTgNtf77T
  data dir:    /data/data/com.termux/files/home/.jeangrey

To start:  jeangrey node
~ $ ./jeangrey node --bootstrap 29069f8a@/ip4/192.168.29.40/tcp/9000
Error: invalid peer id: 29069f8a
~ $ ./jeangrey node --bootstrap QmSsHR4u2FbTcJuybhcqRkC1cfVWMibBf3yRvAF5a8EpgP@/ip4/192.168.29.40/tcp/9000
jeangrey interactive node. Commands:
  send <peer-id> <text>   send a message
  lookup <peer-id>        discover a peer's addresses
  peers                   list established sessions
  quit                    exit
2026-08-13T15:55:25.543839Z  INFO jeangrey::node: listening node=phone address=/ip4/192.168.29.27/tcp/9000
2026-08-13T15:55:25.546225Z  INFO jeangrey::node: listening node=phone address=/ip4/127.0.0.1/tcp/9000
2026-08-13T15:55:26.046415Z  WARN libp2p_kad::behaviour: Failed to trigger bootstrap: No known peers.
2026-08-13T15:55:30.563701Z  INFO jeangrey::node: learned bootstrap transport id node=phone peer=QmSsHR4u2F transport=12D3KooWER address=/ip4/192.168.29.40/tcp/9000
2026-08-13T15:55:30.591881Z  INFO jeangrey::node: session established (ML-KEM + ML-DSA authenticated) node=phone peer=QmSsHR4u2F conn=ConnectionId(1) user=hub device=ad5eadbe93e47a078b77046eb0d31eb8

2026-08-13T15:59:23.481317Z  INFO jeangrey::node: message: "Hello from PC" node=phone peer=hub msg_id=12953241106010657205 ts=1786636764563
```

PC — PowerShell:

```
PS D:\workspace\development\jeangrey> .\target\release\jeangrey.exe init --name hub
identity created
  user:        hub (id 29069f8a)
  device peer: QmSsHR4u2FbTcJuybhcqRkC1cfVWMibBf3yRvAF5a8EpgP
  short:       QmSsHR4u2F
  data dir:    C:\Users\rabindra\.jeangrey

To start:  jeangrey node
PS D:\workspace\development\jeangrey> .\target\release\jeangrey.exe node
jeangrey interactive node. Commands:
  send <peer-id> <text>   send a message
  lookup <peer-id>        discover a peer's addresses
  peers                   list established sessions
  quit                    exit
2026-08-13T15:52:14.076492Z  INFO jeangrey::node: listening node=hub address=/ip4/192.168.29.40/tcp/9000
2026-08-13T15:52:14.077932Z  INFO jeangrey::node: listening node=hub address=/ip4/192.168.56.1/tcp/9000
2026-08-13T15:52:14.078804Z  INFO jeangrey::node: listening node=hub address=/ip4/127.0.0.1/tcp/9000
2026-08-13T15:52:14.080085Z  INFO jeangrey::node: listening node=hub address=/ip4/172.30.96.1/tcp/9000
2026-08-13T15:52:14.581733Z  WARN libp2p_kad::behaviour: Failed to trigger bootstrap: No known peers.
2026-08-13T15:55:31.902788Z  INFO jeangrey::node: session established (ML-KEM + ML-DSA authenticated) node=hub peer=QmTgNtf77T conn=ConnectionId(1) user=phone device=46b91d3ae884fdf912c154a843583e7a
send QmSsHR4u2FbTcJuybhcqRkC1cfVWMibBf3yRvAF5a8EpgP "Hello from PC"
sent (id 8021757692813596938); awaiting acknowledgement...
2026-08-13T15:56:29.421566Z  INFO jeangrey::node: verified DHT address record node=hub peer=QmSsHR4u2F device=ad5eadbe93e47a078b77046eb0d31eb8 addrs=4
2026-08-13T15:57:14.594008Z  WARN libp2p_kad::behaviour: Failed to trigger bootstrap: No known peers.
send QmTgNtf77T9RyeGtHTJGUm2p8CdYaTFsXuLhnG1P6B3tTE "Hello from PC"
sent (id 12953241106010657205); awaiting acknowledgement...
2026-08-13T15:59:24.794805Z  INFO jeangrey::node: acknowledged by peer node=hub peer=QmTgNtf77T msg_id=12953241106010657205 ack_seq=0
```

Observations from the run:

- **Mutual handshake, no manual dialing needed.** The phone bootstraps to
  the hub (its own DHT bootstrap trigger reports "No known peers", which is
  expected for a two-node network — the bootstrap connection is what
  establishes the network). ~5 s after starting, both sides log
  `session established (ML-KEM + ML-DSA authenticated)` with each other's
  device fingerprint. A single inbound firewall rule for `jeangrey.exe`
  (enabled, Public profile) sufficed.
- **Delivery.** `send` on the hub printed `sent (id 12953241106010657205);
  awaiting acknowledgement...`, the phone logged
  `message: "Hello from PC" ... msg_id=12953241106010657205` (ts =
  Unix-ms), and the hub logged `acknowledged by peer ... msg_id=... ack_seq=0`.
- **`--bootstrap` takes the full device Peer ID**, not the short `id`
  shown by `init` (`Error: invalid peer id: 29069f8a`).
- **Known limitation:** sending to your own Peer ID (the first `send`
  above targeted the hub itself) hangs in `awaiting acknowledgement...`
  forever — the sender waits on a session it already is. A send timeout
  would turn this into a fast failure.
- Timestamps `ts` in the `message:` line are client-side Unix ms; the
  receiver does not currently compare them to local time.

## MVP-1 acceptance run — 2026-08-14 (Android ↔ Android)

Two Android phones in Termux, same Wi-Fi, aarch64 cross-compiled binaries.
Phone 1 (`phone`, the anchor) starts its node with no bootstrap; phone 2
(`rohan`) bootstraps to it. `init --name <anything>` on phone 1 is rejected
("identity already exists") — idempotence guard works as designed.

Phone 1 — Termux (anchor, no bootstrap):

```
~ $ ./jeangrey init --name rabindra
Error: identity already exists in /data/data/com.termux/files/home/.jeangrey
~ $ ./jeangrey node
2026-08-14T03:17:28.753799Z  INFO jeangrey::node: listening node=phone address=/ip4/10.174.110.167/tcp/9000
2026-08-14T03:17:28.759155Z  INFO jeangrey::node: listening node=phone address=/ip4/127.0.0.1/tcp/9000
2026-08-14T03:17:29.260336Z  WARN libp2p_kad::behaviour: Failed to trigger bootstrap: No known peers.
2026-08-14T03:21:27.437804Z  INFO jeangrey::node: session established (ML-KEM + ML-DSA authenticated) node=phone peer=QmYKfsocNH conn=ConnectionId(1) user=rohan device=24efd9d17bb0d2fde9d75ebfae879767
2026-08-14T03:22:03.865619Z  INFO jeangrey::node: peer disconnected node=phone peer=QmYKfsocNH
2026-08-14T03:24:18.749216Z  INFO jeangrey::node: listening node=phone address=/ip4/172.20.56.251/tcp/9000   # Wi-Fi changed mid-test
2026-08-14T03:25:09.860131Z  INFO jeangrey::node: session established (ML-KEM + ML-DSA authenticated) node=phone peer=QmYKfsocNH conn=ConnectionId(2) user=rohan device=24efd9d17bb0d2fde9d75ebfae879767
2026-08-14T03:25:23.734186Z  INFO jeangrey::node: message: "hello" node=phone peer=rohan msg_id=14170443540126089548 ts=1786677924102
2026-08-14T03:26:36.128617Z  INFO jeangrey::node: message: "QmYKfsocNHanntrsr6dv5GrYaavSRyVrWPLwwsPLZpaQsJ" node=phone peer=rohan msg_id=2623908211697780208 ts=1786677996481
send QmYKfsocNHanntrsr6dv5GrYaavSRyVrWPLwwsPLZpaQsJ "hey"
sent (id 1767835371371876310); awaiting acknowledgement...
2026-08-14T03:28:14.845387Z  INFO jeangrey::node: acknowledged by peer node=phone peer=QmYKfsocNH msg_id=1767835371371876310 ack_seq=2
send QmYKfsocNHanntrsr6dv5GrYaavSRyVrWPLwwsPLZpaQsJ "how are you?"
sent (id 15366191217735927551); awaiting acknowledgement...
2026-08-14T03:28:39.155335Z  INFO jeangrey::node: acknowledged by peer node=phone peer=QmYKfsocNH msg_id=15366191217735927551 ack_seq=3
```

Phone 2 — Termux (bootstraps to phone 1):

```
~ $ ./jeangrey init --name rohan
identity created
  user:        rohan (id 74e58754)
  device peer: QmYKfsocNHanntrsr6dv5GrYaavSRyVrWPLwwsPLZpaQsJ
  short:       QmYKfsocNH
~ $ ./jeangrey node --bootstrap QmTgNtf77T@/ip4/10.174.110.167/tcp/9000
Error: invalid peer id: QmTgNtf77T
~ $ ./jeangrey node --bootstrap QmTgNtf77T9RyeGtHTJGUm2p8CdYaTFsXuLhnG1P6B3tTE@/ip4/10.174.110.167/tcp/9000
2026-08-14T03:21:21.544572Z  INFO jeangrey::node: listening node=rohan address=/ip4/10.174.110.235/tcp/9000
2026-08-14T03:21:27.812670Z  INFO jeangrey::node: learned bootstrap transport id node=rohan peer=QmTgNtf77T transport=12D3KooWPz address=/ip4/10.174.110.167/tcp/9000
2026-08-14T03:21:27.918052Z  INFO jeangrey::node: session established (ML-KEM + ML-DSA authenticated) node=rohan peer=QmTgNtf77T conn=ConnectionId(1) user=phone device=46b91d3ae884fdf912c154a843583e7a
send QmTgNtf77T9RyeGtHTJGUm2p8CdYaTFsXuLhnG1P6B3tTE "Hello"
sent (id 6703931615687595749); awaiting acknowledgement...
2026-08-14T03:23:47.358250Z  INFO jeangrey::node: peer disconnected node=rohan peer=QmTgNtf77T
2026-08-14T03:24:04.953522Z  WARN jeangrey::node: dial failed node=rohan peer=Some(PeerId("12D3KooWPzc6GATvSbFU9dLH8sK8XpfzTpBKfdF1Ec42FhSuLYor")) error=Failed to negotiate transport protocol(s): [(/ip4/10.174.110.167/tcp/9000/p2p/12D3KooWPzc6GATvSbFU9dLH8sK8XpfzTpBKfdF1Ec42FhSuLYor: : No route to host (os error 113))
2026-08-14T03:24:31.543114Z  INFO jeangrey::node: listening node=rohan address=/ip4/172.20.56.223/tcp/9000   # Wi-Fi changed mid-test
^C
~ $ ./jeangrey node --bootstrap QmTgNtf77T9RyeGtHTJGUm2p8CdYaTFsXuLhnG1P6B3tTE@/ip4/172.20.56.251/tcp/9000
2026-08-14T03:25:03.753376Z  INFO jeangrey::node: listening node=rohan address=/ip4/172.20.56.223/tcp/9000
2026-08-14T03:25:10.325933Z  INFO jeangrey::node: session established (ML-KEM + ML-DSA authenticated) node=rohan peer=QmTgNtf77T conn=ConnectionId(1) user=phone device=46b91d3ae884fdf912c154a843583e7a
send QmTgNtf77T9RyeGtHTJGUm2p8CdYaTFsXuLhnG1P6B3tTE "hello"
sent (id 14170443540126089548); awaiting acknowledgement...
2026-08-14T03:25:24.236894Z  INFO jeangrey::node: acknowledged by peer node=rohan peer=QmTgNtf77T msg_id=14170443540126089548 ack_seq=0
send QmTgNtf77T9RyeGtHTJGUm2p8CdYaTFsXuLhnG1P6B3tTE "QmYKfsocNHanntrsr6dv5GrYaavSRyVrWPLwwsPLZpaQsJ"
sent (id 2623908211697780208); awaiting acknowledgement...
2026-08-14T03:26:36.631597Z  INFO jeangrey::node: acknowledged by peer node=rohan peer=QmTgNtf77T msg_id=2623908211697780208 ack_seq=1
2026-08-14T03:28:15.311758Z  INFO jeangrey::node: message: "hey" node=rohan peer=phone msg_id=1767835371371876310 ts=1786678094716
2026-08-14T03:28:39.623090Z  INFO jeangrey::node: message: "how are you?" node=rohan peer=phone msg_id=15366191217735927551 ts=1786678119031
```

Observations from the run:

- **Fully bidirectional.** Both directions delivered with authenticated acks:
  `hello` / the peer-id message (rohan → phone, `ack_seq=0..1`) and `hey` /
  `how are you?` (phone → rohan, `ack_seq=2..3`). `ack_seq` is per-session
  and shared across both directions.
- **Wi-Fi change mid-test.** Both phones moved to a new network
  (10.174.110.x → 172.20.56.x). The anchor's DHT record still advertised
  the old address, so rohan's re-dial failed with `No route to host (os
  error 113)`. Expected for a LAN-only MVP (no NAT traversal / record
  re-publication on address change); restarting rohan's node with the new
  bootstrap address recovered immediately, and the anchor re-listening on
  the new IP re-established the session on the next dial.
- **`init` idempotence.** Repeated `init` on the anchor's existing data dir
  correctly refuses ("identity already exists").
- The short-id bootstrap mistake (`QmTgNtf77T` instead of the full Peer
  ID) is rejected with `invalid peer id` — the short form is display-only.
- One REPL line on phone 1 (`invalid peer id: send`) was a keyboard/paste
  artifact; the identical retry line worked normally.

## Debugging a failed run

```sh
JEANGREY_TEST_LOG=jeangrey=debug cargo test --test integration -- messaging
```

Every log line carries `node = <name>`; transport-level lines carry the
transport Peer ID and, where relevant, the expected device. Connection
closes log their cause (`IO` / keep-alive), endpoint, and remaining
connections; session registry changes log the removed device.