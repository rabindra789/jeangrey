//! Two-tier identity model.
//!
//! - **User / account identity**: a stable identifier + display name. One
//!   user may own many devices. The user identity is *not* a Peer ID; it is
//!   carried inside signed records and the session handshake so that peers
//!   learn who owns the device they talk to.
//! - **Device identity**: a persistent ML-DSA-65 signing key + device UUID,
//!   bound to the owning user.
//! - **Device Peer ID**: self-certifying — the SHA-256 multihash of the
//!   device ML-DSA public key. There is no central registry; possessing the
//!   public key of a device determines its Peer ID, so a Peer ID can never be
//!   "spoofed" without the corresponding private key. The Peer ID names the
//!   *device*, never the user.
//!
//! The libp2p transport keypair (ed25519) is a *secondary* transport-level
//! identity used by the DHT/routing machinery. The device Peer ID is the
//! identity users address; the transport Peer ID is bound to it inside the
//! signed address record and mapped back when connections arrive.

use libp2p::identity::Keypair;
use libp2p::PeerId;
use sha2::{Digest, Sha256};

use crate::crypto::mldsa;
use crate::crypto::mldsa::VerifyingKey;

/// A stable user / account identity (MVP-1: one user owns one device, but the
/// data model keeps the user tier separate from any Peer ID).
#[derive(Debug, Clone)]
pub struct UserIdentity {
    /// Stable random identifier of the account (not a Peer ID).
    pub user_id: [u8; 16],
    pub user_name: String,
}

impl UserIdentity {
    pub fn generate(user_name: &str) -> Self {
        let mut user_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut user_id);
        UserIdentity {
            user_id,
            user_name: user_name.to_string(),
        }
    }

    pub fn short_id(&self) -> String {
        hex::encode(&self.user_id[..4])
    }
}

/// A persistent device identity belonging to a [`UserIdentity`].
pub struct DeviceIdentity {
    pub user: UserIdentity,
    pub secret_key: mldsa::SecretKey,
    pub verifying_key: VerifyingKey,
    pub device_uuid: [u8; 16],
    /// Secondary transport identity (libp2p). Used only for routing/DHT
    /// bookkeeping; never for JeanGrey authentication.
    pub transport_keypair: Keypair,
    /// Self-certifying device Peer ID = multihash(sha256(ML-DSA public key)).
    pub peer_id: PeerId,
}

impl DeviceIdentity {
    pub fn generate(user_name: &str) -> Self {
        let secret_key = mldsa::SecretKey::generate();
        let verifying_key = secret_key.verifying_key();
        let mut device_uuid = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut device_uuid);
        Self::assemble(
            UserIdentity::generate(user_name),
            secret_key,
            verifying_key,
            device_uuid,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_seed(
        user_id: [u8; 16],
        user_name: String,
        seed: [u8; mldsa::SEED_LEN],
        device_uuid: [u8; 16],
        transport_keypair: Keypair,
    ) -> Self {
        let secret_key = mldsa::SecretKey::from_seed(seed);
        let verifying_key = secret_key.verifying_key();
        Self::assemble(
            UserIdentity { user_id, user_name },
            secret_key,
            verifying_key,
            device_uuid,
        )
        .with_transport(transport_keypair)
    }

    fn assemble(
        user: UserIdentity,
        secret_key: mldsa::SecretKey,
        verifying_key: VerifyingKey,
        device_uuid: [u8; 16],
    ) -> Self {
        let peer_id = peer_id_of(&verifying_key);
        let transport_keypair = Keypair::generate_ed25519();
        Self {
            user,
            secret_key,
            verifying_key,
            device_uuid,
            transport_keypair,
            peer_id,
        }
    }

    fn with_transport(mut self, transport_keypair: Keypair) -> Self {
        self.transport_keypair = transport_keypair;
        self
    }

    /// The libp2p Peer ID of this device's transport key. This is what the
    /// transport/DHT layers dial; it is mapped to the device Peer ID through
    /// the signed address record.
    pub fn transport_peer_id(&self) -> PeerId {
        PeerId::from_public_key(&self.transport_keypair.public())
    }

    pub fn public_key_bytes(&self) -> [u8; mldsa::PUBKEY_LEN] {
        mldsa::pubkey_to_bytes(&self.verifying_key)
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.secret_key.sign(message)
    }
}

/// Compute the self-certifying device Peer ID for a device public key.
pub fn peer_id_of(vk: &VerifyingKey) -> PeerId {
    let pk = mldsa::pubkey_to_bytes(vk);
    let digest = Sha256::digest(pk);
    // Multihash: 0x12 = sha2-256, 0x20 = 32-byte digest length.
    let mut bytes = Vec::with_capacity(34);
    bytes.push(0x12);
    bytes.push(0x20);
    bytes.extend_from_slice(&digest);
    PeerId::from_bytes(&bytes).expect("sha2-256 multihash is a valid PeerId")
}

/// Short human-readable form for logs (first `n` base58 chars).
pub fn short_id(peer_id: &PeerId) -> String {
    let s = peer_id.to_base58();
    let n = s.len().min(10);
    s[..n].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_is_self_certifying() {
        let a = DeviceIdentity::generate("alice");
        let b = DeviceIdentity::generate("bob");
        assert_ne!(a.peer_id, b.peer_id);
        // Same pubkey -> same peer id, regardless of the rest of the identity.
        let a2 = peer_id_of(&a.verifying_key);
        assert_eq!(a.peer_id, a2);
    }

    #[test]
    fn peer_id_recovery_from_pubkey() {
        let a = DeviceIdentity::generate("alice");
        let pk = a.public_key_bytes();
        assert_eq!(
            mldsa::pubkey_from_bytes(&pk).map(|vk| peer_id_of(&vk)),
            Some(a.peer_id)
        );
        let mut bad = pk;
        bad[0] ^= 1;
        assert_ne!(
            mldsa::pubkey_from_bytes(&bad).map(|vk| peer_id_of(&vk)),
            Some(a.peer_id)
        );
    }

    #[test]
    fn uuid_differs() {
        let a = DeviceIdentity::generate("alice");
        let b = DeviceIdentity::generate("alice");
        assert_ne!(a.device_uuid, b.device_uuid);
    }

    #[test]
    fn user_identity_is_stable_while_devices_are_not_peers() {
        let a = DeviceIdentity::generate("alice");
        let b = DeviceIdentity::generate("alice");
        // Same user name, different devices -> different Peer IDs, but the
        // user identity is distinct from the Peer ID.
        assert_ne!(a.peer_id, b.peer_id);
        assert_ne!(a.user.user_id, b.user.user_id);
        assert_eq!(a.user.user_name, b.user.user_name);
        // Transport id differs from the device Peer ID and is stable per key.
        assert_ne!(a.transport_peer_id(), a.peer_id);
        assert_eq!(
            a.transport_peer_id(),
            PeerId::from_public_key(&a.transport_keypair.public())
        );
    }
}
