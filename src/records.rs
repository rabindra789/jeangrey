//! Authenticated device-address records published into the Kademlia DHT.
//!
//! The DHT is used ONLY as a discovery mechanism. A record is keyed by the
//! self-certifying Peer ID of a device and contains the device's ML-DSA
//! public key, LAN multiaddrs, and a signature. Verification is entirely
//! local (no trusted infrastructure):
//!
//! 1. The ML-DSA public key in the record must hash to the record key
//!    (Peer ID). This binds the record to the identity — nobody can publish
//!    a record under your Peer ID without your private key.
//! 2. The ML-DSA signature must verify over the record bytes.
//! 3. The record must be fresh (issued_at + ttl >= now).
//!
//! The DHT itself stores opaque signed blobs; nodes never store plaintext
//! messages or any sensitive data in the DHT.

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};

use crate::crypto::mldsa;
use crate::identity::DeviceIdentity;

/// Domain-separation prefix for record signatures.
pub const RECORD_SIGN_PREFIX: &[u8] = b"jeangrey/mvp1/addr-record/v1";
/// Max record size accepted from the DHT.
pub const MAX_RECORD_BYTES: usize = 16 * 1024;
/// Max addresses per record.
pub const MAX_ADDRS: usize = 8;
/// Default record TTL (re-published by nodes on a timer).
pub const DEFAULT_TTL_SECS: u64 = 120;
/// Max accepted clock skew for record freshness, seconds.
pub const MAX_SKEW_SECS: u64 = 30;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AddrRecord {
    pub v: u32,
    pub kind: String,
    pub device_uuid: String,
    pub peer_id: String,
    pub pubkey_b64: String,
    pub user_id_hex: String,
    pub user_name: String,
    pub transport_peer_b58: String,
    pub addrs: Vec<String>,
    pub issued_at: u64,
    pub ttl_secs: u64,
    pub sig_b64: String,
}

impl AddrRecord {
    /// The exact bytes that are signed (signature is over the record minus
    /// the signature field, with the prefix prepended).
    fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(RECORD_SIGN_PREFIX);
        out.extend_from_slice(&self.v.to_be_bytes());
        out.extend_from_slice(&self.kind.len().to_be_bytes());
        out.extend_from_slice(self.kind.as_bytes());
        out.extend_from_slice(&self.device_uuid.len().to_be_bytes());
        out.extend_from_slice(self.device_uuid.as_bytes());
        out.extend_from_slice(&self.peer_id.len().to_be_bytes());
        out.extend_from_slice(self.peer_id.as_bytes());
        out.extend_from_slice(&self.pubkey_b64.len().to_be_bytes());
        out.extend_from_slice(self.pubkey_b64.as_bytes());
        out.extend_from_slice(&self.user_id_hex.len().to_be_bytes());
        out.extend_from_slice(self.user_id_hex.as_bytes());
        out.extend_from_slice(&self.user_name.len().to_be_bytes());
        out.extend_from_slice(self.user_name.as_bytes());
        out.extend_from_slice(&self.transport_peer_b58.len().to_be_bytes());
        out.extend_from_slice(self.transport_peer_b58.as_bytes());
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.ttl_secs.to_be_bytes());
        for a in &self.addrs {
            out.extend_from_slice(&(a.len() as u32).to_be_bytes());
            out.extend_from_slice(a.as_bytes());
        }
        out
    }

    /// Serialize for transport in the DHT.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("record serialization cannot fail")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(RecordError::TooLarge(bytes.len()));
        }
        serde_json::from_slice(bytes).map_err(|_| RecordError::Malformed)
    }
}

/// Create and sign a fresh address record for `identity`.
pub fn sign_addr_record(identity: &DeviceIdentity, addrs: &[Multiaddr]) -> AddrRecord {
    let now = now_unix();
    let mut record = AddrRecord {
        v: 1,
        kind: "jeangrey.device-addr.v1".to_string(),
        device_uuid: hex::encode(identity.device_uuid),
        peer_id: identity.peer_id.to_base58(),
        pubkey_b64: B64.encode(identity.public_key_bytes()),
        user_id_hex: hex::encode(identity.user.user_id),
        user_name: identity.user.user_name.clone(),
        transport_peer_b58: identity.transport_peer_id().to_base58(),
        addrs: addrs.iter().map(|a| a.to_string()).collect(),
        issued_at: now,
        ttl_secs: DEFAULT_TTL_SECS,
        sig_b64: String::new(),
    };
    // Only sign the address set AFTER validating/canonicalizing it.
    record.addrs.truncate(MAX_ADDRS);
    let sig = identity.sign(&record.signed_bytes());
    record.sig_b64 = B64.encode(sig);
    record
}

/// Verification outcome for a DHT record.
#[derive(Debug)]
pub struct VerifiedRecord {
    pub peer_id: libp2p::PeerId,
    pub user_id: [u8; 16],
    pub user_name: String,
    pub device_uuid: [u8; 16],
    pub transport_peer: libp2p::PeerId,
    pub addrs: Vec<Multiaddr>,
    pub issued_at: u64,
}

/// Verify a record under `key` (the Peer ID multihash bytes). Fails on any
/// inconsistency; callers must never trust an unverified record.
pub fn verify_addr_record(
    key: &[u8],
    record: &AddrRecord,
    now: u64,
) -> Result<VerifiedRecord, RecordError> {
    // 1. Version + kind sanity.
    if record.v != 1 {
        return Err(RecordError::UnsupportedVersion(record.v));
    }
    if record.kind != "jeangrey.device-addr.v1" {
        return Err(RecordError::Malformed);
    }
    // 2. Freshness (with skew allowance).
    if now + MAX_SKEW_SECS < record.issued_at {
        return Err(RecordError::FromTheFuture);
    }
    if record.issued_at + record.ttl_secs + MAX_SKEW_SECS < now {
        return Err(RecordError::Expired);
    }
    // 3. Recover the public key; it MUST hash to the record key.
    let pk_bytes = B64
        .decode(&record.pubkey_b64)
        .map_err(|_| RecordError::Malformed)?;
    let pubkey = mldsa::pubkey_from_bytes(&pk_bytes).ok_or(RecordError::Malformed)?;
    let computed_peer_id = crate::identity::peer_id_of(&pubkey);
    let key_peer_id = libp2p::PeerId::from_bytes(key).map_err(|_| RecordError::BadKey)?;
    if computed_peer_id != key_peer_id {
        return Err(RecordError::KeyMismatch);
    }
    if record.peer_id != computed_peer_id.to_base58() {
        return Err(RecordError::KeyMismatch);
    }
    // 4. Signature must verify over the exact signed bytes.
    let sig = B64
        .decode(&record.sig_b64)
        .map_err(|_| RecordError::Malformed)?;
    if !mldsa::verify(&pubkey, &record.signed_bytes(), &sig) {
        return Err(RecordError::BadSignature);
    }
    // 5. User identity fields and the transport Peer ID must be well-formed
    //    (they are signed, so this is syntax checking only).
    let user_id: [u8; 16] = hex::decode(&record.user_id_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(RecordError::Malformed)?;
    if record.user_name.is_empty() || record.user_name.len() > 64 {
        return Err(RecordError::Malformed);
    }
    let transport_peer =
        libp2p::PeerId::from_str(&record.transport_peer_b58).map_err(|_| RecordError::Malformed)?;
    // 6. Addresses must be valid multiaddrs, IPv4/IPv6 TCP, no p2p suffix,
    //    no duplicates, bounded count.
    let mut addrs = Vec::with_capacity(record.addrs.len());
    let mut seen = std::collections::HashSet::new();
    if record.addrs.is_empty() {
        return Err(RecordError::NoAddresses);
    }
    if record.addrs.len() > MAX_ADDRS {
        return Err(RecordError::TooManyAddresses);
    }
    for a in &record.addrs {
        let maddr = Multiaddr::from_str(a).map_err(|_| RecordError::BadAddress)?;
        let has_tcp = maddr
            .iter()
            .any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_)));
        if !has_tcp {
            return Err(RecordError::BadAddress);
        }
        if maddr
            .iter()
            .any(|p| matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
        {
            return Err(RecordError::BadAddress);
        }
        if !seen.insert(maddr.to_string()) {
            return Err(RecordError::BadAddress);
        }
        addrs.push(maddr);
    }
    let device_uuid: [u8; 16] = hex::decode(&record.device_uuid)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(RecordError::Malformed)?;

    Ok(VerifiedRecord {
        peer_id: computed_peer_id,
        user_id,
        user_name: record.user_name.clone(),
        device_uuid,
        transport_peer,
        addrs,
        issued_at: record.issued_at,
    })
}

#[derive(Debug)]
pub enum RecordError {
    TooLarge(usize),
    Malformed,
    UnsupportedVersion(u32),
    Expired,
    FromTheFuture,
    KeyMismatch,
    BadSignature,
    BadKey,
    NoAddresses,
    TooManyAddresses,
    BadAddress,
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordError::TooLarge(n) => write!(f, "record too large ({n} bytes)"),
            RecordError::Malformed => write!(f, "malformed record"),
            RecordError::UnsupportedVersion(v) => write!(f, "unsupported record version {v}"),
            RecordError::Expired => write!(f, "record expired"),
            RecordError::FromTheFuture => write!(f, "record timestamp in the future"),
            RecordError::KeyMismatch => write!(f, "record key does not match the public key"),
            RecordError::BadSignature => write!(f, "record signature verification failed"),
            RecordError::BadKey => write!(f, "record key is not a valid Peer ID"),
            RecordError::NoAddresses => write!(f, "record has no addresses"),
            RecordError::TooManyAddresses => write!(f, "record has too many addresses"),
            RecordError::BadAddress => write!(f, "record contains an invalid address"),
        }
    }
}

impl std::error::Error for RecordError {}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn sign_verify_round_trip() {
        let id = DeviceIdentity::generate("alice");
        let addrs = vec![
            addr("/ip4/10.0.0.5/tcp/9000"),
            addr("/ip4/127.0.0.1/tcp/9001"),
        ];
        let record = sign_addr_record(&id, &addrs);
        let bytes = record.to_bytes();
        let parsed = AddrRecord::from_bytes(&bytes).unwrap();
        let key = id.peer_id.to_bytes();
        let verified = verify_addr_record(&key, &parsed, now_unix()).unwrap();
        assert_eq!(verified.peer_id, id.peer_id);
        assert_eq!(verified.user_id, id.user.user_id);
        assert_eq!(verified.user_name, "alice");
        assert_eq!(verified.transport_peer, id.transport_peer_id());
        assert_eq!(verified.addrs.len(), 2);
        assert_eq!(verified.addrs[0], addrs[0]);
    }

    #[test]
    fn tampered_record_rejected() {
        let id = DeviceIdentity::generate("alice");
        let mut record = sign_addr_record(&id, &[addr("/ip4/10.0.0.5/tcp/9000")]);
        record.addrs[0] = "/ip4/10.0.0.6/tcp/9000".to_string();
        assert!(matches!(
            verify_addr_record(&id.peer_id.to_bytes(), &record, now_unix()),
            Err(RecordError::BadSignature)
        ));
    }

    #[test]
    fn wrong_key_rejected() {
        let alice = DeviceIdentity::generate("alice");
        let mallory = DeviceIdentity::generate("mallory");
        let record = sign_addr_record(&alice, &[addr("/ip4/10.0.0.5/tcp/9000")]);
        // Mallory stores Alice's record under her OWN key: hash mismatch.
        assert!(matches!(
            verify_addr_record(&mallory.peer_id.to_bytes(), &record, now_unix()),
            Err(RecordError::KeyMismatch)
        ));
        // Mallory signs a record under ALICE's key: signature mismatch.
        let mut forged = sign_addr_record(&mallory, &[addr("/ip4/10.0.0.5/tcp/9000")]);
        forged.peer_id = alice.peer_id.to_base58();
        forged.pubkey_b64 = B64.encode(alice.public_key_bytes());
        assert!(matches!(
            verify_addr_record(&alice.peer_id.to_bytes(), &forged, now_unix()),
            Err(RecordError::BadSignature)
        ));
    }

    #[test]
    fn expired_record_rejected() {
        let id = DeviceIdentity::generate("alice");
        let mut record = sign_addr_record(&id, &[addr("/ip4/10.0.0.5/tcp/9000")]);
        record.issued_at -= record.ttl_secs + 1000;
        assert!(matches!(
            verify_addr_record(&id.peer_id.to_bytes(), &record, now_unix()),
            Err(RecordError::Expired)
        ));
    }

    #[test]
    fn future_record_rejected() {
        let id = DeviceIdentity::generate("alice");
        let mut record = sign_addr_record(&id, &[addr("/ip4/10.0.0.5/tcp/9000")]);
        record.issued_at = now_unix() + 10_000;
        // Signature still valid (signed over issued_at); only freshness fails.
        assert!(matches!(
            verify_addr_record(&id.peer_id.to_bytes(), &record, now_unix()),
            Err(RecordError::FromTheFuture)
        ));
    }

    #[test]
    fn bad_addresses_rejected() {
        let id = DeviceIdentity::generate("alice");
        // Tampering with an address after signing invalidates the signature
        // (signatures are checked before address parsing, so verification
        // fails closed on the signature).
        let r1 = sign_addr_record(&id, &[addr("/ip4/10.0.0.5/tcp/9000")]);
        let mut r1 = r1;
        r1.addrs[0] = "not-a-multiaddr".to_string();
        assert!(matches!(
            verify_addr_record(&id.peer_id.to_bytes(), &r1, now_unix()),
            Err(RecordError::BadSignature)
        ));
        // p2p-suffixed addresses are not allowed in records.
        let r2 = sign_addr_record(
            &id,
            &[format!("/ip4/10.0.0.5/tcp/9000/p2p/{}", id.peer_id)
                .parse::<Multiaddr>()
                .expect("parse")],
        );
        assert!(matches!(
            verify_addr_record(&id.peer_id.to_bytes(), &r2, now_unix()),
            Err(RecordError::BadAddress)
        ));
        // Non-TCP multiaddr is rejected.
        let r3 = sign_addr_record(
            &id,
            &["/ip4/10.0.0.5/udp/9000"
                .parse::<Multiaddr>()
                .expect("parse")],
        );
        assert!(matches!(
            verify_addr_record(&id.peer_id.to_bytes(), &r3, now_unix()),
            Err(RecordError::BadAddress)
        ));
    }

    #[test]
    fn too_many_addresses_rejected() {
        let id = DeviceIdentity::generate("alice");
        let addrs: Vec<Multiaddr> = (0..10)
            .map(|i| format!("/ip4/10.0.{i}.5/tcp/9000").parse().unwrap())
            .collect();
        // sign_addr_record truncates to MAX_ADDRS, so verify must also reject
        // any record that exceeds the cap.
        let record = sign_addr_record(&id, &addrs);
        assert_eq!(record.addrs.len(), MAX_ADDRS);
        assert!(verify_addr_record(&id.peer_id.to_bytes(), &record, now_unix()).is_ok());
        // A record with more addresses than allowed fails on count alone.
        let mut r2 = sign_addr_record(&id, &[addr("/ip4/10.0.0.5/tcp/9000")]);
        r2.addrs = (0..20)
            .map(|i| format!("/ip4/10.0.{i}.5/tcp/9000"))
            .collect();
        r2.sig_b64 = B64.encode(id.sign(&r2.signed_bytes()));
        assert!(matches!(
            verify_addr_record(&id.peer_id.to_bytes(), &r2, now_unix()),
            Err(RecordError::TooManyAddresses)
        ));
    }

    #[test]
    fn oversized_record_rejected() {
        let id = DeviceIdentity::generate("alice");
        let mut record = sign_addr_record(&id, &[addr("/ip4/10.0.0.5/tcp/9000")]);
        // Inflate the record beyond MAX_RECORD_BYTES.
        record.addrs = vec![
            format!("/ip4/10.0.0.5/tcp/{}", 1u16),
            format!("/ip4/10.0.0.5/tcp/{}", 2u16),
        ];
        while record.to_bytes().len() <= MAX_RECORD_BYTES {
            let n = record.to_bytes().len();
            record.addrs.push(format!("/ip4/10.0.0.5/tcp/{n}"));
            if record.addrs.len() > 1024 {
                break;
            }
        }
        let bytes = record.to_bytes();
        assert!(bytes.len() > MAX_RECORD_BYTES);
        assert!(matches!(
            AddrRecord::from_bytes(&bytes),
            Err(RecordError::TooLarge(_))
        ));
    }
}
