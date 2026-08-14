# JeanGrey — Completion Report (MVP-1 / Release v1.0.120)

**Project:** JeanGrey — Post-Quantum Secure Decentralized Messaging Protocol
**Milestone:** MVP-1 (LAN implementation)
**Release:** v1.0.120
**Date:** 2026-08-13
**Status:** COMPLETE — validated on physical devices (Windows + Android, Android + Android); released as v1.0.120

## 1. Deliverables

| deliverable | location | status |
|---|---|---|
| Post-quantum messaging library + CLI | `src/`, `Cargo.toml` | complete |
| End-to-end integration tests | `tests/integration/` | passing |
| Documentation | `README.md`, `docs/architecture.md`, `docs/protocol.md`, `docs/testing.md` | complete |
| Release artifacts | GitHub release v1.0.120: `jeangrey-v1.0.120-windows-x86_64.zip`, `jeangrey-v1.0.120-android-aarch64.tar.gz`, `SHA256SUMS` | published |

## 2. Verification results

```
cargo test --all-targets    -> 58 unit + 2 integration tests, all passing
                               (messaging E2E runs in ~16 s)
cargo clippy --all-targets  -> 0 warnings
cargo fmt --check           -> clean
```

### Integration test coverage (`tests/integration/messaging.rs`)

Three real nodes over loopback, exercising the complete MVP-1 flow:

1. **Discovery** — C retrieves B's signed address record through the DHT
   (bootstrapped via A), verifies the ML-DSA signature and timestamp.
2. **Handshake** — C dials B's authenticated address set; mutual
   ML-KEM-768 + ML-DSA handshake completes on both sides.
3. **Messaging** — C sends "hello from charlie"; B receives the decrypted,
   AEAD-authenticated message and replies with an authenticated ack; C
   verifies the ack (matching message id + sequence).

### CLI verification (single host, two node processes)

```
jeangrey init --name hub      -> identity created
jeangrey node                 -> listening; DHT anchor
jeangrey init --name laptop   -> identity created
jeangrey node --bootstrap ... -> session established (ML-KEM + ML-DSA authenticated)
jeangrey send <hub> "hello from the LAN"
  -> session established ... ; acknowledged by peer ... ; delivered (id ...)
hub node log: message: hello from the LAN  (node=hub peer=laptop)
```

## 3. Notable engineering findings

1. **Handshake frame-drop bug (fixed).** `poll_read_once` originally
   decoded *all* buffered frames per poll and re-read a fixed chunk,
   discarding the tail of a partially received frame. Fixed to decode at
   most one frame per poll with exact-consumption semantics; verified by
   the passing handshake tests and E2E run.
2. **DHT propagation latency (mitigated).** A node's record must propagate
   through the DHT before discovery succeeds. Discovery lookups now retry
   (10 attempts, 1 s apart); the integration test exercises this path and
   passes reliably.
3. **Test-harness ack-drop (fixed).** The E2E test's background receiver
   stopped polling its swarm the instant its predicate matched, dropping
   the node before its queued ack could flush. The receiver now keeps
   polling after message receipt so the authenticated ack reaches the
   wire. Root-caused via per-node log attribution (every line carries
   `node = <name>`, connection closes carry their cause, endpoint and
   remaining-connection count).
4. **CLI one-shot conflict (documented).** A one-shot command must not use
   a listen port already held by another instance (dials reuse the listen
   port by design). The demo walkthrough uses separate ports.

## 2b. Physical-device validation (2026-08-13/14)

| configuration | result |
|---|---|
| Windows x86_64 ↔ Android ARM64 (Termux), home Wi-Fi | mutual ML-KEM + ML-DSA session; `send` → delivered → authenticated ack (`msg_id` matched both sides) |
| Android ARM64 ↔ Android ARM64 (Termux), Wi-Fi | bidirectional messaging with authenticated acks in both directions (`ack_seq` shared per session) |

Full annotated logs in [`docs/testing.md`](docs/testing.md).

**Known limitation observed:** when a device changes Wi-Fi networks, its
IP changes and previously published DHT address records go stale; peers
dialing the old address fail with `No route to host (os error 113)`. This
is expected for the LAN-only release — dynamic address re-publication /
lifecycle management is scheduled for the future networking phase. It is
not a cryptographic failure.

## 4. Security model (what MVP-1 provides and what it does not)

**Provides** — mutual authentication with ML-DSA-65 (transcript signed, handshake fails
closed); confidentiality and integrity via ML-KEM-768 + ChaCha20-Poly1305 AEAD with
random nonces and header-binding AAD; replay protection (strict per-direction sequence
numbers plus a message-id window); authenticated acks; signed, timestamp-checked DHT
address records; zeroization of secret keys.

**Explicitly out of scope for MVP-1** — the transport Peer ID is ephemeral per run
(device identities remain authenticated; see `docs/protocol.md` §1); no
store-and-forward or offline delivery; no message-layer forward secrecy beyond
per-session ephemeral ML-KEM; the DHT is trusted for availability only, and only
within the LAN.

## 5. How to reproduce

See `docs/testing.md` and `README.md`. Key commands:

```sh
cargo test --all-targets
cargo clippy --all-targets
JEANGREY_TEST_LOG=jeangrey=debug cargo test --test integration -- messaging
```
