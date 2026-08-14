//! Project JeanGrey — post-quantum decentralized messaging (LAN, MVP-2 in
//! progress: dynamic address lifecycle).
//!
//! Library crate; the `jeangrey` binary is a thin wrapper around [`cli`].
//! See `docs/protocol.md` for the protocol and `docs/architecture.md` for the
//! module design.

pub mod cli;
pub mod crypto;
pub mod framing;
pub mod handshake;
pub mod identity;
pub mod node;
pub mod records;
pub mod session;
pub mod storage;
pub mod transport;

/// Re-exported for API consumers (CLI, tests, and the future client bridge).
pub use libp2p::Multiaddr;
