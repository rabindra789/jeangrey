# Project JeanGrey — Project Context

## Formal title

Design and Implementation of a Post-Quantum Secure Decentralized Messaging Protocol

## Project identity

- Repository: `jeangrey` (GitHub)
- Current release: **v1.0.120**
- License: MIT

## Naming

JeanGrey is the project and protocol name. The end-user application name
is **TBD** (to be decided); the current CLI binary ships as `jeangrey`
(Windows `jeangrey.exe` / Android `jeangrey` for Termux).

## Status

- **MVP-1 / LAN implementation: validated** — released as **v1.0.120**
  (Git tag `v1.0.120`, release commit `a0139a0`). Tag is a frozen
  baseline; do not rewrite, retag, or force-push it.
- **MVP-2 / Internet connectivity: active development**
  (branch `feature/mvp2-internet-connectivity`)
- MVP-1 test baseline: 58 unit + 2 integration tests passing; clippy clean; fmt clean
- Cross-compiled and run on Windows x86_64 and Android ARM64 (Termux, bionic)

## MVP-2 progress

### M2.1 — Dynamic address lifecycle + DHT republishing (implemented)

- Motivating failure (real test, 2026-08-14):
  `10.174.110.x → 172.20.56.x → stale DHT record → No route to host`
- Root cause: libp2p's wildcard TCP listener reports new interface
  addresses but does not expire them when the OS drops the interface;
  the old IP kept being advertised.
- Fix: the node keeps `current_addrs` (listen addresses whose IP is still
  configured locally). An OS interface scan every 5 s
  (`local_ip_address::list_afinet_netifas`) drops stale addresses;
  `NewListenAddr`/`ExpiredListenAddr` update the set; any change re-signs
  the record (fresh `issued_at`) and republishes immediately; the 30 s
  periodic republish keeps the TTL fresh. A failed scan is fail-safe
  (nothing dropped). Record format unchanged (no compat break).
- Tests: 4 new unit tests (filter logic, change detection) + 1 new
  integration test (`address_change_is_republished_and_discovered`).
  Suite now: 62 unit + 3 integration, all passing.

### M2.2 — Dynamic rediscovery of stale records (implemented)

- Peer-side counterpart of M2.1: a node holding a stale cached record
  must recover when the remote moves. On session loss the node re-dials
  the cached address once (2 s) while scheduling a DHT lookup (3 s,
  1 s retries, ≤ 10 attempts). Dial failures (`DialError::Transport`)
  invalidate the failed candidates; `WrongPeerId` invalidates the whole
  record. A verified record replaces the cache whenever its `issued_at`
  is not older (equal timestamps still re-dial — a re-fetched record is
  never dropped silently).
- Dials allocate fresh ephemeral source ports (`PortUse::New`): on
  Windows, listener-port reuse for outgoing dials collides with the
  live listener (`WSAEADDRINUSE`). A `bootstrap_dialing` guard prevents
  duplicate dials to the same address.
- Tests: 2 new unit tests (invalidation + rediscovery dedup) + 1 new
  integration test (`stale_cached_address_recovers_via_rediscovery`,
  B1 dies → stale 9242 refused → rediscovery → B2's 9244 → session +
  authenticated ack). Suite now: 66 unit + 4 integration, all passing.

### M2.3 — External address discovery + dial-back validation (implemented)

- A node behind NAT only knows its local interface addresses. M2.3 adds
  observed-address discovery: the acceptor of an inbound connection
  captures the dialer's source IP and reports it over the authenticated
  session (new AEAD Control frame type 9 — the crypto design is
  unchanged).
- The owner classifies the IP (loopback / local interface → ignore;
  else external candidate `(IP, own listen port)`) and asks the reporter
  to dial it back. A full handshake validates the candidate, which is
  then merged into the signed DHT record and advertised alongside local
  addresses; dial failure or 30 s timeout rejects it (≤ 3 attempts,
  15 s per attempt; validated addresses re-validated every 300 s).
- Probes dial with an unknown transport Peer ID and a fresh source port,
  so they are never suppressed by existing connections or colliding with
  the listener. Only the requested prober's result is accepted.
- Tests: 12 new unit tests (classification, candidate lifecycle,
  validation/rejection/expiry, re-validation, probe dedup/timeout,
  control-frame round trips) + 1 new integration test
  (`external_address_discovery_validation_and_advertisement`: A observes
  B, B validates via dial-back and publishes, C discovers and connects
  through the advertised address). The loopback test seam
  (`NodeOptions::external_ips`) stands in for a public IP — on Windows
  the loopback source is always observed as 127.0.0.1. Suite now:
  78 unit + 5 integration, all passing; clippy and fmt clean;
  aarch64-linux-android check clean.

### Not yet started (MVP-2 remaining)

- M2.4 NAT traversal
- M2.5 relay fallback
- M2.6 reconnection
- M2.7 hardening (timeouts, retry/backoff, state machine, CLI diagnostics)

Do NOT mark mailbox/IPFS/Flutter work complete. All future phases remain
out of scope per `docs/PROJECT_CONTEXT.md` (see below).

## What the release includes

- persistent cryptographic identity (user + device model)
- self-certifying device Peer IDs
- Kademlia discovery over the LAN
- direct P2P TCP transport
- ML-DSA authentication (FIPS 204, ML-DSA-65)
- fresh ML-KEM session establishment (FIPS 203, ML-KEM-768)
- HKDF-SHA256 session-key derivation
- ChaCha20-Poly1305 AEAD encrypted bidirectional messaging
- message IDs, replay/duplicate protection
- authenticated delivery acknowledgements
- CLI: init / node / lookup / send / peers
- Windows x86_64 binary, Android ARM64 (Termux) binary

## Physical-device validation

- Windows x86_64 ↔ Android ARM64 (Termux) over Wi-Fi — session, message, authenticated ack
- Android ARM64 ↔ Android ARM64 (Termux) over Wi-Fi — bidirectional messages and acks
- Full annotated logs: `docs/testing.md`

## Known limitations (as released / MVP-2 progress)

- **NAT traversal / relay not implemented (M2.4–M2.5 pending).** Nodes
  on the same LAN or with directly reachable public addresses connect
  directly; discovery via observed addresses (M2.3) helps nodes behind
  NAT advertise their public endpoint, but no hole punching or relay
  fallback exists yet.
- **Stale DHT addresses after Wi-Fi/network change — FIXED (M2.1 + M2.2).**
  The publisher drops addresses whose IP is no longer local and
  republishes immediately (M2.1); the peer side invalidates failed
  cached addresses and redisovers the fresh record via the DHT (M2.2).
- **No offline delivery.** Messages are delivered directly over an
  established connection; no store-and-forward queue.
- **Self-send hangs.** Sending to your own Peer ID waits indefinitely for
  an acknowledgement; a send timeout is planned (M2.7).

## Release artifacts (GitHub release v1.0.120)

- `jeangrey-v1.0.120-windows-x86_64.zip` — Windows x86_64 executable (`jeangrey.exe`) + README.txt
- `jeangrey-v1.0.120-android-aarch64.tar.gz` — Android ARM64 executable (`jeangrey`) for Termux
- `SHA256SUMS` — SHA-256 checksums for both assets

## Build notes

- Host: Windows, Rust 1.95, MSVC host toolchain
- Android target: `aarch64-linux-android`, linked with NDK r27d clang
  (`aarch64-linux-android24-clang.cmd`), static bionic sysroot, runs in
  Termux only (not a standalone Android app)
- Cargo linker config for Android lives in `~/.cargo/config.toml` (user-local)

## Out of scope (future phases, NOT claimed in v1.0.120)

- Internet-wide connectivity, NAT traversal, hole punching, relay fallback
- offline mailbox / store-and-forward
- IPFS media distribution
- multi-device account synchronization
- PQ ratcheting
- anonymous routing, Sybil resistance

## Next direction

The next development phase focuses on Internet connectivity (addressing
the stale-address/NAT limitations) while preserving the secure messaging
layer.
