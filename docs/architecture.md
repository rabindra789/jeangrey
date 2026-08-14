# JeanGrey MVP-1 — Architecture

## 1. Goals

A LAN-only prototype of a decentralized messaging system whose security
properties survive quantum computers:

- **Authenticated, encrypted, replay-protected messaging** built entirely
  on NIST post-quantum algorithms (ML-KEM-768, ML-DSA-65) plus
  ChaCha20-Poly1305.
- **No central authority**: peers discover each other through a Kademlia
  DHT and mutually authenticate directly.
- **Minimal trust in the transport**: identity is bound to ML-DSA keys,
  not to libp2p's ed25519 transport keys.

## 2. Layered design

```
┌────────────────────────────────────────────────────────────┐
│ CLI (src/cli.rs)        init | node | lookup | send | peers │
├────────────────────────────────────────────────────────────┤
│ Node (src/node.rs)      event loop, maintenance, discovery  │
│   └── NodeBehaviour = SessionBehaviour + kad::Behaviour     │
│         ├── SessionBehaviour (src/transport.rs)             │
│         │     connection handler: SessionHandler            │
│         │       ├── framing (src/framing.rs)                │
│         │       ├── handshake (src/handshake.rs)            │
│         │       └── session (src/session.rs)                │
│         └── kad (libp2p-kad)  discovery only                │
│   └── records (src/records.rs)  signed address records      │
├────────────────────────────────────────────────────────────┤
│ identity (src/identity.rs)   ML-DSA keys, Peer IDs          │
│ crypto (src/crypto.rs)       ML-KEM/ML-DSA/HKDF wrappers    │
│ storage (src/storage.rs)     identity + config on disk      │
└────────────────────────────────────────────────────────────┘
```

### Module responsibilities

| module | responsibility |
|---|---|
| `identity.rs` | device identities: ML-DSA-65 key pair, self-certifying device Peer ID (`Qm...`), per-run ed25519 transport Peer ID (`12D3KooW...`), display name |
| `crypto.rs` | `kem` (ML-KEM-768 ephemeral), `mldsa` (sign/verify), `kdf` (HKDF-SHA256 session key schedule), `aead` (ChaCha20-Poly1305 with random nonces and PqTag) |
| `framing.rs` | length-prefixed frame codec with type/len/plaintext-tag validation |
| `handshake.rs` | symmetric mutual handshake state machine (Hello/KemOffer/KemResponse/Auth/Ready), 30 s timeout, transcript signature |
| `session.rs` | per-direction sequence enforcement, message id window, replay protection, AEAD encrypt/decrypt, authenticated acks |
| `records.rs` | signed address records: build, sign, verify (ML-DSA + timestamp skew) |
| `node.rs` | swarm assembly, bootstrap, DHT publish (30 s) and lookup with retries (10×1 s), session bookkeeping, event loop |
| `transport.rs` | libp2p `ConnectionHandler` (one substream per connection) + `SessionBehaviour` (device↔transport mapping, session registry, notifications) |
| `cli.rs` | interactive REPL and one-shot commands |
| `storage.rs` | `~/.jeangrey` identity + node config, JSON, zeroizing secret keys |

## 3. Identity and key separation

```
DeviceIdentity
 ├── ML-DSA-65 secret key   (long-term, on disk, zeroized on drop)
 ├── device Peer ID         = hash(ML-DSA public key)          [Qm...]
 ├── device UUID            (random 16 bytes, per identity)
 ├── user name              (display)
 └── per-run transport key  (ephemeral ed25519)
      └── transport Peer ID = hash(ed25519 public key)          [12D3KooW...]
```

The device Peer ID is what users exchange; the transport Peer ID is what the
network addresses. The binding between the two is authenticated in the
handshake (`Hello` carries the ML-DSA key; the dialer verifies it matches
the expected device Peer ID).

## 4. Discovery

1. Every node is a Kademlia server (`Mode::Server`) and listens on all
   LAN interfaces.
2. Every 30 s a node re-publishes its signed address record
   (`records.rs`) under key `SHA-256(device_peer_id)`; see the
   "Address lifecycle" section below for when it re-publishes early.
3. A node wanting to reach an unknown peer issues `get_record`; the
   returned record must verify (signature, key, skew) or it is discarded.
4. The verified address set is dialed concurrently — all addresses in a
   single dial, first success wins, remaining in-flight dials are aborted.
5. Lookups retry (10 attempts, 1 s apart) to absorb DHT propagation
   (the integration test exercises this path).
6. Kademlia's same-key replacement means a republished record overwrites
   the previous one in the DHT, so lookups converge on the newest
   verified record for a peer.

### Address lifecycle (MVP-2 / M2.1)

Observed failure (Android ↔ Android, 2026-08-14): a peer changed Wi-Fi
networks (`10.174.110.x` → `172.20.56.x`), kept advertising the old IP,
and other peers got `No route to host` dialing it. Root cause: libp2p's
wildcard TCP listener reports new interface addresses (`NewListenAddr`)
but does not expire per-interface addresses when the OS drops them, so
the swarm kept treating the old IP as a listen address and records kept
advertising it.

The node now maintains `current_addrs`, the set of addresses it believes
are reachable:

```
NewListenAddr / ExpiredListenAddr (libp2p)
        +  periodic OS interface scan (every 5 s)
        └──> current_addrs  (listen addrs ∩ IPs still configured locally)
                 │
              change?
              /    \
           no       yes
           │         └──> sign fresh record (new issued_at)
           │              └──> DHT put_record (immediate)
           └──> periodic re-publish (30 s) keeps TTL fresh
```

- `filter_local_addrs` drops any listen address whose IP is no longer
  configured on a local interface (enumerated with
  `local_ip_address::list_afinet_netifas`, the same crate used for
  transport addresses). Loopback is always kept (it cannot go stale).
- A failed interface scan (returns `None`) is fail-safe: nothing is
  dropped.
- The interface scan runs at most every `INTERFACE_SCAN_INTERVAL` (5 s),
  so the system responds to actual network changes without aggressive
  polling.
- Record freshness/expiry is unchanged (TTL 120 s, 30 s skew); the DHT
  keeps only the newest record per key (same-key replacement), so stale
  addresses disappear from lookups as soon as the new record propagates.

## 5. Sessions

- One authenticated session per device (`sessions` map in
  `SessionBehaviour`), keyed by device Peer ID, carrying the transport id
  and connection id.
- Session establishment requires the handshake; the first frame type seen
  on the substream decides whether it is a handshake or a session stream.
- Frame delivery: `notify_peer` resolves device → transport → connection
  and targets that connection's handler. Delivery errors (closed handler)
  surface as handshake/session failures and cleanly tear down the session.
- Connection close removes the session (only if it is the one the session
  was bound to), preserving correctness when redundant connections to the
  same peer exist.

## 6. Event loop

`Node::wait_for` / `Node::run` / `run_interactive` poll the swarm and a
1-second maintenance tick:

- maintenance: address-lifecycle refresh (interface scan + stale-address
  removal + immediate republish on change), periodic record publish,
  re-dial known peers without sessions, re-issue pending discovery
  lookups.
- events: session events (established/message/ack/disconnect), DHT events,
  connection lifecycle — all with `node = <name>` log attribution.

The interactive REPL (`run_interactive`) multiplexes user commands
(send/lookup/peers/quit) with the same event loop.

## 7. Security model (MVP-1)

**Provided**

- Mutual authentication via ML-DSA; transcripts are signed; handshake fails
  closed.
- Confidentiality + integrity via ML-KEM-768 + ChaCha20-Poly1305 AEAD with
  random nonces and bind-the-header AAD.
- Replay protection: strict per-direction sequence numbers + message id
  window.
- Authenticated acks: only accepted for messages awaiting acknowledgement.
- Address records signed and timestamp-checked; DHT cannot substitute
  records (only DoS them).
- Secret keys are zeroized on drop.

**Not provided (explicit MVP-1 scope)**

- Transport key is ephemeral per run, so transport-Peer-ID impersonation is
  possible during a run by an adversary that has already broken into the
  LAN (device IDs remain authenticated).
- No store-and-forward: a peer must be online and directly reachable for
  message delivery.
- No forward secrecy at the message layer beyond per-session ephemeral
  ML-KEM (session keys persist for the connection lifetime).
- The DHT is trusted for availability only, and only within the LAN.

## 8. Failure modes handled

| failure | handling |
|---|---|
| DHT record not yet propagated | lookup retries (10 × 1 s) |
| Multiple concurrent dials to one peer | first success wins; stragglers closed |
| Redundant connections (kad dial + record dial) | session bound to one connection; stale connections closed without session loss |
| Handshake timeout / malformed frames | fail closed, close handler, surface error |
| Replayed / out-of-order / wrong-type frames | rejected at decode or session layer |
| Connection dropped with queued data | handler flush on next poll; session removed on close |
| Duplicate record puts | idempotent keyed puts; verification on get |