# Project JeanGrey — Project Context

## Formal title

Design and Implementation of a Post-Quantum Secure Decentralized Messaging Protocol

## Project identity

- Repository: `jeangrey` (GitHub)
- Current release: **v1.0.120**
- License: MIT

## Naming

JeanGrey is the project and protocol name. The end-user application is the
`jeangrey` command-line tool (Windows `jeangrey.exe` / Android `jeangrey`
for Termux) which implements the protocol. The protocol name and the
application name deliberately match.

## Status

- **MVP-1 / LAN implementation: validated**
- Released as **v1.0.120** (Git tag `v1.0.120`)
- 58 unit tests + 2 integration tests passing; clippy clean; fmt clean
- Cross-compiled and run on Windows x86_64 and Android ARM64 (Termux, bionic)

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

## Known limitations (as released)

- **LAN only.** No NAT traversal, relay, or Internet connectivity.
- **Stale DHT addresses after Wi-Fi/network change.** When a device's IP
  changes, previously published DHT address records go stale; peers dialing
  the old address fail with `No route to host (os error 113)` until
  re-publication. Address re-publishing / lifecycle management is a future
  networking phase. Not a cryptographic failure.
- **No offline delivery.** Messages are delivered directly over an
  established connection; no store-and-forward queue.
- **Self-send hangs.** Sending to your own Peer ID waits indefinitely for
  an acknowledgement; a send timeout is planned.

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
