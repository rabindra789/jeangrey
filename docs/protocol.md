# JeanGrey MVP-1 — Protocol Specification

This document defines the wire protocol used by JeanGrey MVP-1. It is the
reference for `src/handshake.rs`, `src/framing.rs`, `src/session.rs`,
`src/records.rs` and `src/transport.rs`.

## 1. Overview

All `jeangrey` application traffic runs over a single libp2p stream protocol
`/jeangrey/session/1.0.0` multiplexed over a transport connection
(TCP + yamux). Discovery traffic runs over Kademlia with protocol name
`/jeangrey/kad/1.0.0`.

Two peer identifier spaces exist and are deliberately distinct:

| space | key type | format | purpose |
|---|---|---|---|
| device id | ML-DSA-65 public key | `Qm...` (base58) | identity, signing, sessions |
| transport id | ed25519 (libp2p) | `12D3KooW...` | network addressing |

The device Peer ID is the self-certifying hash of the ML-DSA public key
(`peer_id_of` in `src/identity.rs`). The transport Peer ID is derived from
an ephemeral ed25519 key generated per run. The mapping transport->device is
established during the handshake and used to attribute connections to
identities.

## 2. Framing

Every frame is length-prefixed, with a fixed 5-byte header:

```
+---------+---------+------------------+
| type(1) | len(4)  | payload(len)     |
+---------+---------+------------------+
```

- `type` — frame type (see below).
- `len` — big-endian u32 payload length.

Encoding rules enforced by `src/framing.rs`:

- Handshake frames (Hello, KemOffer, KemResponse, Auth, Ready) must carry a
  zero plaintext tag (`PqTag = 0`).
- Session frames (Message, Ack) must carry the plaintext tag
  `plaintext::PqTag`; any frame with a non-zero tag that is not a session
  frame is rejected.
- Payloads are limited (16 KiB) and length-checked on decode.

Frame types:

| value | name | direction |
|---|---|---|
| 1 | `Hello` | handshake |
| 2 | `KemOffer` | handshake |
| 3 | `KemResponse` | handshake |
| 4 | `Auth` | handshake |
| 5 | `Ready` | handshake |
| 6 | `Message` | session |
| 7 | `Ack` | session |

## 3. Authenticated post-quantum handshake

The handshake is fully symmetric (no initiator/responder roles) and
mutually authenticates both peers. All six payloads are exchanged in fixed
order, then hashed into a transcript that is signed by both sides.

### 3.1 Hello (type 1)

```
+-----------------+-------------+-------------+
| mldsa_pubkey(32)| device(16)  | user_name   |
+-----------------+-------------+-------------+
```

- `mldsa_pubkey` — the long-term ML-DSA-65 public key (32-byte seed
  compressed form; `mldsa::PUBKEY_LEN`).
- `device` — a random 16-byte device UUID.
- `user_name` — display name (max 64 bytes).

The receiving peer MUST verify that the presented public key hashes to the
expected device Peer ID when one is known (outbound dial to a discovered
peer). Failure aborts the handshake.

### 3.2 KemOffer (type 2)

The raw ML-KEM-768 encapsulation key (1184 bytes). Both peers generate a
fresh ephemeral ML-KEM-768 key pair per handshake.

### 3.3 KemResponse (type 3)

The ML-KEM-768 ciphertext (1088 bytes) produced by encapsulating on the
peer's encapsulation key.

After this exchange each peer holds two shared secrets:

- `ss_to_peer` — the secret this peer created by encapsulating to the peer;
- `ss_from_peer` — the secret this peer recovered by decapsulating the
  peer's ciphertext.

Both secrets (32 bytes each) are combined in canonical peer-ID order and
fed to the key schedule.

### 3.4 Auth (type 4)

```
+--------------------+------------------+
| transcript_hash(32)| signature(2420)  |
+--------------------+------------------+
```

The transcript is `SHA-256` over the canonical concatenation of all six
payloads (both Hellos, both offers, both responses) plus the domain
separation label `jeangrey/mvp1/auth/v1`. The signature is over the
transcript hash with the long-term ML-DSA key. **Verification is
mandatory**: any mismatch fails the handshake closed (no fallback).

### 3.5 Ready (type 5)

```
+------------------+
| session_id(32)   |
+------------------+
```

The session id is derived by the key schedule (below). Equality of the two
`Ready` payloads completes the handshake.

### 3.6 Key schedule

```
seed     = HKDF-SHA256(ikm = ss_from_peer || ss_to_peer,
                       salt = session_transcript_hash,
                       info = "jeangrey/mvp1/session/v1", len = 32)
send_key = HKDF-SHA256(ikm = seed, info = peer_id || my_id, len = 32)
recv_key = HKDF-SHA256(ikm = seed, info = my_id || peer_id, len = 32)
session_id = HKDF-SHA256(ikm = seed, info = "session-id", len = 32)
```

Keys are labeled with the canonical (byte-ordered) peer IDs so each side
derives complementary `send`/`recv` keys. A 30-second wall-clock timeout
aborts handshakes that stall.

## 4. Session encryption

After `Ready` both sides switch the stream to session mode. Session frames
are encrypted with ChaCha20-Poly1305:

```
plaintext = PqTag || seq(8) || payload
ciphertext = nonce(12) || AEAD(PqTag || seq || payload, aad = type || len || plaintext_tag)
```

- `PqTag` — 4-byte constant `PQ` marker proving the plaintext is post-quantum
  framed (detects protocol confusion; `plaintext::PqTag`).
- `seq` — big-endian u64 sequence number.
- The AEAD AAD binds the frame header (type, length) and the plaintext tag,
  so ciphertexts cannot be replayed into other frame types.
- Nonces are random 12-byte values (re-keyed per frame from the session
  key and a per-message random; collisions are detected and reject the
  frame rather than reuse a nonce/keystream).

### 4.1 Message (type 6)

Payload after decryption: `msg_id(8) || ts_ms(8) || body`.

- `msg_id` — random u64.
- `ts_ms` — sender wall clock (ms). Receivers reject skew > 30 s.
- Sequence numbers are enforced strictly per direction (`recv_seq` must
  match the expected value); out-of-order or replayed frames are rejected.

### 4.2 Ack (type 7)

Payload after decryption: `msg_id(8) || ack_seq(8)`, where `ack_seq` is the
sender's sequence number for the ack itself. Acks are AEAD-authenticated and
only accepted for messages currently awaiting acknowledgement; the message
id window (16) bounds replay tracking.

### 4.3 Control (type 9, MVP-2 / M2.3)

Control frames carry address-discovery and reachability-validation traffic.
They are encrypted and authenticated exactly like Message frames (same key
schedule, same AEAD, same per-direction sequence counter) — the protocol
design is otherwise unchanged.

Plaintext payloads (tag || body):

| Tag | Frame | Body |
|-----|-------|------|
| 0x03 | ObservedAddr | `ip(4\|16) \|\| source_port(2)` |
| 0x04 | DialBackReq  | `len(1) \|\| multiaddr` |
| 0x05 | DialBackRes  | `len(1) \|\| multiaddr \|\| reachable(1)` |

- ObservedAddr — sent by the acceptor of an inbound connection right after
  the handshake, reporting the dialer's source IP and ephemeral source
  port as seen from the network.
- DialBackReq — asks the recipient to dial the sender's candidate address
  back (reachability validation).
- DialBackRes — the probe outcome (`reachable` = 1 on a full handshake, 0
  on a failed dial or 30 s timeout).
- Multiaddrs are capped at `MAX_CONTROL_ADDR_BYTES` (512); longer or
  truncated payloads are rejected as malformed.

## 5. Address records (DHT)

Discovery uses Kademlia `get_record`/`put_record` under the JeanGrey
protocol name. The record value is a signed address record
(`src/records.rs`):

```
record = key(32) || addrs: [multiaddr] (max 8) || ts_secs(8) || ttl_secs(8) || signature
signature = ML-DSA over "jeangrey/mvp1/addr-record/v1" || record bytes (minus signature)
```

- Record key: `SHA-256(device_peer_id)`.
- Verification on retrieval is mandatory: signature, key match, and
  timestamp skew (max 30 s) are all checked. Unverified records are
  discarded (`verify_addr_record`).
- Records are re-published every 30 seconds with a 120-second TTL.

### 5.1 Address lifecycle (MVP-2 / M2.1)

Records are additionally re-published **immediately** whenever the node's
reachable address set changes:

- `NewListenAddr` / `ExpiredListenAddr` swarm events update the set.
- Every 5 seconds the node re-enumerates the OS interface IPs
  (`local_ip_address::list_afinet_netifas`) and drops any listen address
  whose IP is no longer configured locally (loopback is always kept). A
  failed scan keeps the current set (fail-safe).
- Any change re-signs the record (fresh `issued_at`) and publishes it
  immediately; the periodic 30 s re-publish keeps the TTL fresh.

Kademlia stores one record per key, so a republished record overwrites
the previous one; peers' lookups therefore converge on the newest
verified record, and the old (stale) address set stops being used once
the update propagates. There is no record format change — the existing
`issued_at`/`ttl_secs` freshness rules already express update semantics.

### 5.2 Stale-record handling (MVP-2 / M2.2)

When a session to a peer is lost, the node:

1. Re-dials the cached record once (`RECONNECT_DIAL_DELAY` 2 s). If the
   dial fails, the failed addresses are dropped from the cached record
   (`invalidate_candidates`) and, in parallel, a DHT lookup is scheduled
   (`RECONNECT_DELAY` 3 s).
2. The lookup is retried every `LOOKUP_RETRY_DELAY` (1 s) up to
   `MAX_LOOKUP_ATTEMPTS` (10). Verified records replace the cache when
   their `issued_at` is not older than the cached one (equal timestamps
   still re-trigger the dial, so a re-fetched record is never dropped
   silently) and are dialed immediately.
3. `DialError::WrongPeerId` — the address is live but belongs to a
   different transport id — invalidates the whole cached record, since
   the device/transport binding itself is stale.

Dials allocate a fresh ephemeral source port (`PortUse::New`); the
listener's own port is never reused for outgoing connections, avoiding
bind collisions (`WSAEADDRINUSE`) on Windows loopback.

### 5.3 External address discovery (MVP-2 / M2.3)

1. The acceptor of an inbound connection records the dialer's source
   IP:port and, right after the handshake, sends an `ObservedAddr` control
   frame (section 4.3) over the session.
2. The receiver classifies the reported IP: loopback and locally
   configured interface addresses are ignored; anything else is an
   external candidate `(IP, own listen port)`.
3. The candidate owner sends a `DialBackReq` to the reporting peer. The
   prober dials the candidate with an unknown transport Peer ID and a
   fresh source port; a full handshake answers `DialBackRes(reachable=1)`,
   a failed dial or 30 s timeout answers `reachable=0`.
4. A reachable candidate is validated and merged into the owner's signed
   DHT record (published with the same `issued_at`/TTL rules). Candidates
   get at most 3 validation attempts; validated addresses are re-validated
   every 300 s and dropped from the record when re-validation fails.

The protocol suite (ML-DSA + fresh ML-KEM + HKDF + AEAD, framing, DHT
record format) is unchanged; only the new Control frame type (9) is added.

## 6. Connection and session lifecycle

1. A node with no sessions to a peer issues a DHT lookup, verifies the
   record, and dials the returned authenticated address set (all addresses
   in a single concurrent dial; the first success wins).
2. The single stream `/jeangrey/session/1.0.0` is negotiated on the
   connection; the handshake above runs on it.
3. On success the node stores one session per device. Message/ack delivery
   uses the session's connection.
4. Connection closure removes the session and emits a peer-disconnected
   event; the node re-issues the lookup on the next maintenance tick.

### 6.1 Bootstrap

`--bootstrap PEERID@/ip4/.../tcp/PORT` seeds the Kademlia routing table.
Bootstrap nodes are also servers (`kad Mode::Server`) so lookups can be
answered. Discovery lookups retry (up to 10 attempts, 1 s apart) to absorb
DHT propagation delay.