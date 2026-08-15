# JeanGrey — Post-Quantum Secure Decentralized Messaging Protocol

**Design and Implementation of a Post-Quantum Secure Decentralized Messaging Protocol**

**Release: v1.0.120**

> This release is a LAN-focused decentralized messaging implementation.
>
> **Naming:** JeanGrey is the name of the project and of the messaging
> protocol it specifies. The end-user application name is **TBD** (to be
> decided); the current CLI binary ships as `jeangrey`. Wherever this
> README says "JeanGrey", it refers to the protocol; wherever it says
> `jeangrey`, it refers to the executable.

JeanGrey is a decentralized messaging protocol whose security is built
entirely on post-quantum primitives:

- **ML-KEM-768** (FIPS 203) for key establishment,
- **ML-DSA-65** (FIPS 204) for identity and authentication,
- **ChaCha20-Poly1305** (AEAD, nonce-misuse-resistant framing) for message
  encryption,
- **HKDF-SHA256** for key derivation.

There is no central server: peers discover each other through a Kademlia
DHT (used *only* for address discovery), verify signed address records,
connect directly, and mutually authenticate with a post-quantum handshake
before exchanging encrypted messages with authenticated acknowledgements.

## What this release includes

- persistent cryptographic device identity (user + device model)
- self-certifying device Peer IDs
- Kademlia peer discovery over the LAN
- direct P2P transport (TCP)
- ML-DSA authenticated sessions
- fresh ML-KEM session establishment
- HKDF session-key derivation
- AEAD-encrypted bidirectional messaging with message IDs
- replay/duplicate protection
- authenticated delivery acknowledgements
- observed-address discovery: peers report the public address at which
  they see you; dial-back validation confirms reachability before the
  address is advertised in your signed DHT record (M2.3)
- CLI client/node (`init`, `node`, `lookup`, `send`, `peers`)
- Windows x86_64 build and Android ARM64 (Termux) build
- LAN interoperability (Windows ↔ Android, Android ↔ Android)

## What this release does NOT include

- NAT traversal / hole punching
- relay fallback
- offline messaging / store-and-forward mailbox
- IPFS media distribution
- multi-device synchronization
- PQ ratcheting
- anonymous routing / Sybil resistance

## Installation

### Windows (x86_64)

Download `jeangrey-v1.0.120-windows-x86_64.zip` from the release, extract,
and run `jeangrey.exe` from PowerShell:

```powershell
.\jeangrey.exe init --name alice
.\jeangrey.exe node
```

### Android (ARM64, Termux)

Download `jeangrey-v1.0.120-android-aarch64.tar.gz` from the release.
Copy it into the phone (e.g. `adb push jeangrey /sdcard/Download/`), then
in Termux:

```bash
termux-setup-storage
cp /sdcard/Download/jeangrey ~/
chmod +x jeangrey
./jeangrey init --name alice
./jeangrey node
```

The binary requires Android 7+ (API 24+) and runs inside Termux.

### From source

```sh
cargo build --release
```

Requires Rust 1.75+ (built and tested with 1.95). No system dependencies.
The Android build additionally requires the Android NDK
(see [`docs/testing.md`](docs/testing.md) for the exact setup).

## Quick start (two terminals)

```sh
# Terminal 1 — create an identity and run a node
jeangrey init --name alice
jeangrey node

# Terminal 2 — create a second identity and run a node bootstrapping to the first
jeangrey init --name bob
jeangrey node --bootstrap "$(jeangrey id)@/ip4/127.0.0.1/tcp/9000"
```

In the interactive node (`jeangrey node`):

| command | meaning |
|---|---|
| `peers` | list established, authenticated sessions |
| `send <peer-id> <text>` | send a message and wait for the authenticated ack |
| `lookup <peer-id>` | fetch + verify a peer's signed address record via the DHT |
| `quit` | exit |

One-shot commands:

```sh
jeangrey lookup <peer-id>            # discover a peer's authenticated addresses
jeangrey send <peer-id> "hello"      # discover, connect, send, wait for ack
jeangrey peers                       # run 20s and print discovered sessions
```

Common options: `--data-dir <dir>` (default `~/.jeangrey`, override with
`JEANGREY_DATA_DIR`), `--listen-port <port>` (default 9000),
`--bootstrap PEERID@/ip4/ADDR/tcp/PORT` (repeatable).

### Bootstrap requires the FULL Peer ID

`init` prints both a short ID and the full device Peer ID. The short ID is
display-only; every place that takes a peer identifier (`--bootstrap`,
`send`, `lookup`) requires the full form:

```
Short ID:      QmTgNtf77T
Full Peer ID:  QmTgNtf77T9RyeGtHTJGUm2p8CdYaTFsXuLhnG1P6B3tTE
```

Using the short ID fails with `Error: invalid peer id: ...`.

## Two-machine LAN demo

1. Pick a machine as the DHT bootstrap node (any of the three works):
   `jeangrey init --name hub && jeangrey node`.
2. On the second machine: `jeangrey init --name laptop` and
   `jeangrey node --bootstrap <hub-peer-id>@/ip4/<hub-lan-ip>/tcp/9000`.
3. From either node: `peers` (after ~30s the DHT record propagates), then
   `send <peer-id> "hello from the LAN"`. The receiver's node logs the
   decrypted message and the sender receives the authenticated ack.

Tested configurations (v1.0.120):

- Windows x86_64 ↔ Android ARM64 (Termux) over Wi-Fi
- Android ARM64 ↔ Android ARM64 (Termux) over Wi-Fi

See [`docs/testing.md`](docs/testing.md) for the full walkthroughs and logs.

## Known limitations

- **NAT traversal / relay not implemented.** Nodes on the same LAN or
  with directly reachable public addresses connect directly. Nodes
  behind NAT can now discover and advertise the public address at which
  they are observed and have it dial-back validated (M2.3), but hole
  punching and relay fallback are not implemented.
- **Stale DHT addresses — fixed (M2.1 + M2.2).** When a device changes
  Wi-Fi networks and receives a new IP address, the publisher re-signs
  and republishes its record when its address set changes (M2.1), and
  peers holding a stale cached record invalidate it on dial failure and
  rediscover the fresh record via the DHT (M2.2).
- **No offline delivery.** Messages are delivered directly over an
  established connection; there is no store-and-forward queue.
- **Sending to your own Peer ID** hangs in `awaiting acknowledgement...`
  (a send timeout is planned).

## Security

JeanGrey uses established, standardized cryptographic primitives
(ML-KEM-768, ML-DSA-65, ChaCha20-Poly1305, HKDF-SHA256) and does not
implement custom cryptographic algorithms. Formal documentation of the
design and the wire protocol live in [`docs/`](docs/).

## Running the tests

```sh
cargo test --all-targets
```

The end-to-end integration test brings up three real nodes (a DHT bootstrap
node and two peers) over loopback and exercises the complete flow:
discovery -> record verification -> post-quantum handshake -> encrypted
message -> authenticated acknowledgement.

```sh
JEANGREY_TEST_LOG=jeangrey=debug cargo test --test integration -- messaging
```

prints the per-node trace of the whole run (node attribution on every line).

## Repository layout

| path | contents |
|---|---|
| `src/identity.rs` | device identities (ML-DSA keys, self-certifying Peer IDs) |
| `src/crypto.rs` | ML-KEM-768 and ML-DSA wrappers, HKDF key derivation |
| `src/handshake.rs` | mutual post-quantum handshake state machine |
| `src/session.rs` | AEAD session encryption, replay protection, authenticated acks |
| `src/framing.rs` | length-prefixed binary framing with type/length/plaintext checks |
| `src/records.rs` | signed DHT address records (verification on retrieval) |
| `src/node.rs` | swarm assembly, DHT discovery, event loop, retries |
| `src/transport.rs` | libp2p connection handler and session behaviour |
| `src/cli.rs` | command-line interface (init / node / lookup / send / peers) |
| `src/storage.rs` | on-disk identity and configuration storage |
| `docs/` | architecture, protocol, and testing documentation |
| `tests/integration/` | end-to-end integration tests |
