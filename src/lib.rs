//! Project JeanGrey — MVP-1: post-quantum decentralized messaging (LAN only).
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
