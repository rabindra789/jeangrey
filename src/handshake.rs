//! Authenticated post-quantum key establishment (JeanGrey MVP-1 handshake).
//!
//! Design (documented in `docs/protocol.md`):
//!
//! 1. Both peers exchange `Hello` frames carrying their long-term ML-DSA
//!    public keys (Peer IDs are self-certifying hashes of those keys, so a
//!    dialed peer MUST match the expected Peer ID).
//! 2. Both peers generate a **fresh ephemeral** ML-KEM-768 key pair and send
//!    `KemOffer` (their encapsulation key).
//! 3. Both peers encapsulate on the received encapsulation key and send
//!    `KemResponse` (the ciphertext). Each side thus holds two shared
//!    secrets: one it created (encapsulation) and one it received
//!    (decapsulation). The pair is combined in a canonical peer-ID order.
//! 4. Both peers hash the full transcript (all six payloads, canonically
//!    ordered) and sign it with ML-DSA (`Auth`). Signature verification is
//!    mandatory — the handshake fails closed on any mismatch.
//! 5. Both peers send `Ready` carrying the derived session id as a
//!    cross-check; equality completes the handshake.
//!
//! The handshake is fully symmetric (no initiator/responder roles) which
//! removes deadlock and ordering risks; ML-DSA authenticates both the peers
//! and the transcript, ML-KEM supplies the shared secret, and HKDF derives
//! the session keys (see `crypto::kdf`).

use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::crypto::kdf::{self, SessionKeys};
use crate::crypto::kem::{self, KemDecap};
use crate::crypto::mldsa;
use crate::framing::{Frame, MessageType};
use crate::identity::DeviceIdentity;

/// Maximum time a handshake may take before it is aborted.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum display-name length.
pub const MAX_USER_NAME: usize = 64;

const AUTH_LABEL: &[u8] = b"jeangrey/mvp1/auth/v1";

/// Information a peer reveals about its device during the handshake.
#[derive(Debug, Clone)]
pub struct PeerHello {
    /// Parsed verifying key (for signature checks).
    pub pubkey: mldsa::VerifyingKey,
    pub device_uuid: [u8; 16],
    pub user_name: String,
}

/// The outcome of a successful handshake.
#[derive(Debug, Clone)]
pub struct HandshakeResult {
    pub my_id: libp2p::PeerId,
    pub peer_id: libp2p::PeerId,
    pub peer_hello: PeerHello,
    pub keys: SessionKeys,
    /// This party's AEAD send key for the session.
    pub send_key: [u8; 32],
    /// The peer's AEAD send key (our receive key).
    pub recv_key: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    WaitHello,
    WaitAuth,
    WaitReady,
    Established,
}

/// One side of the JeanGrey handshake state machine.
pub struct Handshake {
    my_id: libp2p::PeerId,
    /// Peer ID we expect (set when dialing a known peer). Inbound
    /// connections derive it from the presented key.
    expected_peer: Option<libp2p::PeerId>,
    step: Step,
    started_at: Instant,
    peer_id: Option<libp2p::PeerId>,
    peer_hello: Option<PeerHello>,
    my_hello_payload: Vec<u8>,
    peer_hello_payload: Option<Vec<u8>>,
    my_offer_payload: Option<Vec<u8>>,
    peer_offer_payload: Option<Vec<u8>>,
    my_response_payload: Option<Vec<u8>>,
    peer_response_payload: Option<Vec<u8>>,
    kem_dk: Option<KemDecap>,
    ss_to_peer: Option<[u8; 32]>,
    ss_from_peer: Option<[u8; 32]>,
    peer_auth_ok: bool,
    peer_ready: Option<[u8; kdf::SESSION_ID_LEN]>,
    transcript: Option<[u8; 32]>,
    keys: Option<SessionKeys>,
    result: Option<HandshakeResult>,
}

#[derive(Debug)]
pub enum HandshakeError {
    InvalidFrame(String),
    Duplicate(MessageType),
    PeerIdMismatch,
    BadSignature,
    Unexpected(MessageType),
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::InvalidFrame(m) => write!(f, "invalid handshake frame: {m}"),
            HandshakeError::Duplicate(t) => write!(f, "duplicate {t:?} frame"),
            HandshakeError::PeerIdMismatch => {
                write!(f, "peer public key does not match the expected Peer ID")
            }
            HandshakeError::BadSignature => write!(f, "ML-DSA signature verification failed"),
            HandshakeError::Unexpected(t) => write!(f, "unexpected {t:?} frame in current state"),
        }
    }
}

impl std::error::Error for HandshakeError {}

#[derive(Debug)]
pub enum HandshakeAction {
    /// Frames to transmit (in order).
    Frames(Vec<Frame>),
    /// Handshake complete.
    Established(Box<HandshakeResult>),
}

impl Handshake {
    /// Create a handshake for `identity`. If `expected_peer` is `Some` the
    /// peer must prove exactly that Peer ID.
    pub fn new(identity: &DeviceIdentity, expected_peer: Option<libp2p::PeerId>) -> (Self, Frame) {
        let hello_payload = encode_hello(identity);
        let hello = Frame::handshake(MessageType::Hello, hello_payload.clone());
        (
            Handshake {
                my_id: identity.peer_id,
                expected_peer,
                step: Step::WaitHello,
                started_at: Instant::now(),
                peer_id: None,
                peer_hello: None,
                my_hello_payload: hello_payload,
                peer_hello_payload: None,
                my_offer_payload: None,
                peer_offer_payload: None,
                my_response_payload: None,
                peer_response_payload: None,
                kem_dk: None,
                ss_to_peer: None,
                ss_from_peer: None,
                peer_auth_ok: false,
                peer_ready: None,
                transcript: None,
                keys: None,
                result: None,
            },
            hello,
        )
    }

    /// The peer id we identified (available once the Hello was received).
    #[cfg(test)]
    pub fn peer_id(&self) -> Option<libp2p::PeerId> {
        self.peer_id
    }

    pub fn timed_out(&self, now: Instant) -> bool {
        now.duration_since(self.started_at) > HANDSHAKE_TIMEOUT
    }

    /// Whether the handshake reached the `Established` state.
    #[cfg(test)]
    pub fn is_established(&self) -> bool {
        self.step == Step::Established
    }

    /// The established session result, if the handshake completed.
    #[cfg(test)]
    pub fn take_result(&mut self) -> Option<HandshakeResult> {
        self.result.take()
    }

    /// Feed an inbound handshake frame; returns frames to send or, once both
    /// sides have authenticated each other, the established result.
    pub fn on_frame(
        &mut self,
        identity: &DeviceIdentity,
        frame: &Frame,
    ) -> Result<HandshakeAction, HandshakeError> {
        if frame.flags != 0 {
            return Err(HandshakeError::InvalidFrame("flags set".into()));
        }
        match frame.msg_type {
            MessageType::Hello => self.on_hello(frame),
            MessageType::KemOffer => self.on_kem_offer(frame),
            MessageType::KemResponse => self.on_kem_response(identity, frame),
            MessageType::Auth => self.on_auth(frame),
            MessageType::Ready => self.on_ready(frame),
            _ => Err(HandshakeError::Unexpected(frame.msg_type)),
        }
    }

    fn on_hello(&mut self, frame: &Frame) -> Result<HandshakeAction, HandshakeError> {
        if self.peer_hello_payload.is_some() {
            return Err(HandshakeError::Duplicate(MessageType::Hello));
        }
        let hello = decode_hello(&frame.payload)
            .ok_or_else(|| HandshakeError::InvalidFrame("malformed Hello payload".into()))?;
        let peer_id = crate::identity::peer_id_of(&hello.pubkey);
        if let Some(expected) = self.expected_peer {
            if expected != peer_id {
                return Err(HandshakeError::PeerIdMismatch);
            }
        }
        self.peer_id = Some(peer_id);
        self.peer_hello = Some(hello);
        self.peer_hello_payload = Some(frame.payload.clone());

        // Fresh ephemeral ML-KEM per session: generate only once both sides
        // are identified.
        let (ek, dk) = kem::generate(&mut rand::rngs::OsRng);
        self.kem_dk = Some(dk);
        let offer_payload = ek;
        self.my_offer_payload = Some(offer_payload.clone());
        Ok(HandshakeAction::Frames(vec![Frame::handshake(
            MessageType::KemOffer,
            offer_payload,
        )]))
    }

    fn on_kem_offer(&mut self, frame: &Frame) -> Result<HandshakeAction, HandshakeError> {
        if self.peer_hello.is_none() {
            // Fail closed: an offer before we have the peer's identity is a
            // protocol violation (we can't bind the transcript without it).
            return Err(HandshakeError::Unexpected(MessageType::KemOffer));
        }
        if self.peer_offer_payload.is_some() {
            return Err(HandshakeError::Duplicate(MessageType::KemOffer));
        }
        let (ct, ss) = kem::encapsulate(&frame.payload)
            .map_err(|e| HandshakeError::InvalidFrame(format!("bad KemOffer payload: {e}")))?;
        self.peer_offer_payload = Some(frame.payload.clone());
        self.ss_to_peer = Some(ss);
        self.my_response_payload = Some(ct.clone());
        Ok(HandshakeAction::Frames(vec![Frame::handshake(
            MessageType::KemResponse,
            ct,
        )]))
    }

    fn on_kem_response(
        &mut self,
        identity: &DeviceIdentity,
        frame: &Frame,
    ) -> Result<HandshakeAction, HandshakeError> {
        if self.peer_hello.is_none() {
            return Err(HandshakeError::Unexpected(MessageType::KemResponse));
        }
        if self.peer_response_payload.is_some() {
            return Err(HandshakeError::Duplicate(MessageType::KemResponse));
        }
        let dk = self
            .kem_dk
            .as_ref()
            .ok_or(HandshakeError::Unexpected(MessageType::KemResponse))?;
        let ss = kem::decapsulate(dk, &frame.payload)
            .map_err(|e| HandshakeError::InvalidFrame(format!("bad KemResponse payload: {e}")))?;
        self.peer_response_payload = Some(frame.payload.clone());
        self.ss_from_peer = Some(ss);

        if self.my_response_payload.is_some() {
            self.finish_kem(identity)
        } else {
            Ok(HandshakeAction::Frames(vec![]))
        }
    }

    /// Both KEM halves are available; compute transcript + keys and sign.
    fn finish_kem(&mut self, identity: &DeviceIdentity) -> Result<HandshakeAction, HandshakeError> {
        let peer_id = self
            .peer_id
            .ok_or_else(|| HandshakeError::InvalidFrame("missing peer identity".into()))?;
        let transcript = build_transcript(
            &self.my_id,
            &peer_id,
            [
                (1u8, self.my_hello_payload.clone()),
                (2u8, self.my_offer_payload.clone().unwrap()),
                (3u8, self.my_response_payload.clone().unwrap()),
            ],
            [
                (1u8, self.peer_hello_payload.clone().unwrap()),
                (2u8, self.peer_offer_payload.clone().unwrap()),
                (3u8, self.peer_response_payload.clone().unwrap()),
            ],
        );
        self.transcript = Some(transcript);

        let ikm = combine_shared_secrets(
            &self.ss_to_peer.unwrap(),
            &self.ss_from_peer.unwrap(),
            self.my_id < peer_id,
        );
        let keys = kdf::derive_session_keys(&ikm, &transcript);
        self.keys = Some(keys.clone());

        let mut to_sign = Vec::with_capacity(AUTH_LABEL.len() + 32);
        to_sign.extend_from_slice(AUTH_LABEL);
        to_sign.extend_from_slice(&transcript);
        let sig = identity.secret_key.sign(&to_sign);
        self.step = Step::WaitAuth;
        Ok(HandshakeAction::Frames(vec![Frame::handshake(
            MessageType::Auth,
            sig,
        )]))
    }

    fn on_auth(&mut self, frame: &Frame) -> Result<HandshakeAction, HandshakeError> {
        if self.peer_auth_ok {
            return Err(HandshakeError::Duplicate(MessageType::Auth));
        }
        let transcript = self
            .transcript
            .ok_or(HandshakeError::Unexpected(MessageType::Auth))?;
        let peer_hello = self
            .peer_hello
            .as_ref()
            .ok_or(HandshakeError::Unexpected(MessageType::Auth))?;
        let mut msg = Vec::with_capacity(AUTH_LABEL.len() + 32);
        msg.extend_from_slice(AUTH_LABEL);
        msg.extend_from_slice(&transcript);
        if !mldsa::verify(&peer_hello.pubkey, &msg, &frame.payload) {
            return Err(HandshakeError::BadSignature);
        }
        self.peer_auth_ok = true;
        self.step = Step::WaitReady;
        let keys = self.keys.as_ref().unwrap();
        Ok(HandshakeAction::Frames(vec![Frame::handshake(
            MessageType::Ready,
            keys.session_id.to_vec(),
        )]))
    }

    fn on_ready(&mut self, frame: &Frame) -> Result<HandshakeAction, HandshakeError> {
        if self.peer_ready.is_some() {
            return Err(HandshakeError::Duplicate(MessageType::Ready));
        }
        if !self.peer_auth_ok {
            return Err(HandshakeError::Unexpected(MessageType::Ready));
        }
        if frame.payload.len() != kdf::SESSION_ID_LEN {
            return Err(HandshakeError::InvalidFrame("bad Ready payload".into()));
        }
        let mut sid = [0u8; kdf::SESSION_ID_LEN];
        sid.copy_from_slice(&frame.payload);
        if sid != self.keys.as_ref().unwrap().session_id {
            return Err(HandshakeError::InvalidFrame("session id mismatch".into()));
        }
        self.peer_ready = Some(sid);
        self.step = Step::Established;

        let peer_id = self.peer_id.unwrap();
        let (send_key, recv_key) = select_keys(self.keys.as_ref().unwrap(), &self.my_id, &peer_id);
        let result = HandshakeResult {
            my_id: self.my_id,
            peer_id,
            peer_hello: self.peer_hello.clone().unwrap(),
            keys: self.keys.clone().unwrap(),
            send_key,
            recv_key,
        };
        self.result = Some(result.clone());
        Ok(HandshakeAction::Established(Box::new(result)))
    }
}

/// Encode our Hello payload: [uuid 16][name_len u16][name][pubkey 1952].
fn encode_hello(identity: &DeviceIdentity) -> Vec<u8> {
    let name = identity.user.user_name.as_bytes();
    let mut out = Vec::with_capacity(16 + 2 + name.len() + mldsa::PUBKEY_LEN);
    out.extend_from_slice(&identity.device_uuid);
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&identity.public_key_bytes());
    out
}

fn decode_hello(payload: &[u8]) -> Option<PeerHello> {
    if payload.len() < 16 + 2 + mldsa::PUBKEY_LEN {
        return None;
    }
    let device_uuid: [u8; 16] = payload[..16].try_into().ok()?;
    let name_len = u16::from_be_bytes(payload[16..18].try_into().ok()?) as usize;
    if name_len > MAX_USER_NAME {
        return None;
    }
    let name_end = 18 + name_len;
    if payload.len() != 18 + name_len + mldsa::PUBKEY_LEN {
        return None;
    }
    let user_name = std::str::from_utf8(&payload[18..name_end])
        .ok()?
        .to_string();
    let pubkey_bytes: [u8; mldsa::PUBKEY_LEN] = payload[name_end..].try_into().ok()?;
    let pubkey = mldsa::pubkey_from_bytes(&pubkey_bytes)?;
    Some(PeerHello {
        pubkey,
        device_uuid,
        user_name,
    })
}

/// Build the canonical transcript digest.
///
/// The six payloads (my hello/offer/response, peer hello/offer/response)
/// are hashed in a fixed order: grouped by frame type, and within a group
/// ordered by ascending Peer ID, so both parties hash identical bytes.
fn build_transcript(
    my_id: &libp2p::PeerId,
    peer_id: &libp2p::PeerId,
    mine: [(u8, Vec<u8>); 3],
    theirs: [(u8, Vec<u8>); 3],
) -> [u8; 32] {
    let mut h = Sha256::new();
    let mine_first = my_id < peer_id;
    for i in 0..3 {
        let (my_tag, my_payload) = &mine[i];
        let (peer_tag, peer_payload) = &theirs[i];
        for (tag, payload) in if mine_first {
            [(my_tag, my_payload), (peer_tag, peer_payload)]
        } else {
            [(peer_tag, peer_payload), (my_tag, my_payload)]
        } {
            h.update([*tag]);
            h.update((payload.len() as u32).to_be_bytes());
            h.update(payload);
        }
    }
    let out = h.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

/// Combine the two KEM shared secrets in a canonical order so both parties
/// compute the same value regardless of which secret they created.
///
/// - `ss_to_peer`: the secret this party created (encapsulation).
/// - `ss_from_peer`: the secret this party received (decapsulation).
pub fn combine_shared_secrets(
    ss_to_peer: &[u8; 32],
    ss_from_peer: &[u8; 32],
    mine_is_lower: bool,
) -> [u8; 64] {
    let mut out = [0u8; 64];
    if mine_is_lower {
        out[..32].copy_from_slice(ss_from_peer);
        out[32..].copy_from_slice(ss_to_peer);
    } else {
        out[..32].copy_from_slice(ss_to_peer);
        out[32..].copy_from_slice(ss_from_peer);
    }
    out
}

/// Pick the direction-specific AEAD keys for a party.
fn select_keys(
    keys: &SessionKeys,
    my_id: &libp2p::PeerId,
    peer_id: &libp2p::PeerId,
) -> ([u8; 32], [u8; 32]) {
    if my_id < peer_id {
        (keys.a_to_b, keys.b_to_a)
    } else {
        (keys.b_to_a, keys.a_to_b)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;

    /// Deliver `frames` to `hs` and collect the frames it produces.
    fn drive(hs: &mut Handshake, id: &DeviceIdentity, frames: Vec<Frame>) -> Vec<Frame> {
        let mut out = vec![];
        for f in frames {
            match hs.on_frame(id, &f).expect("handshake frame should process") {
                HandshakeAction::Frames(mut fs) => out.append(&mut fs),
                HandshakeAction::Established(_) => {}
            }
        }
        out
    }

    /// The established result for a handshake (must have completed).
    fn result_of(hs: &mut Handshake) -> HandshakeResult {
        hs.take_result()
            .or_else(|| panic!("handshake did not complete"))
            .expect("taken")
    }

    /// Complete the full 6-round symmetric handshake between
    /// `(ha, alice)` and `(hb, bob)`.
    pub(crate) fn run_full_handshake(
        ha: &mut Handshake,
        alice: &DeviceIdentity,
        hb: &mut Handshake,
        bob: &DeviceIdentity,
    ) {
        let alice_hello = vec![Frame::handshake(MessageType::Hello, encode_hello(alice))];
        let bob_hello = vec![Frame::handshake(MessageType::Hello, encode_hello(bob))];
        // Round 1: hellos -> offers
        let a_offer = drive(ha, alice, bob_hello);
        let b_offer = drive(hb, bob, alice_hello);
        // Round 2: offers -> responses
        let a_ct = drive(ha, alice, b_offer);
        let b_ct = drive(hb, bob, a_offer);
        // Round 3: responses -> auths
        let a_auth = drive(ha, alice, b_ct);
        let b_auth = drive(hb, bob, a_ct);
        // Round 4: auths -> readys
        let a_ready = drive(ha, alice, b_auth);
        let b_ready = drive(hb, bob, a_auth);
        // Round 5: readys -> established
        let _ = drive(ha, alice, b_ready);
        let _ = drive(hb, bob, a_ready);
    }

    #[test]
    fn full_symmetric_handshake_in_memory() {
        let alice = DeviceIdentity::generate("alice");
        let bob = DeviceIdentity::generate("bob");

        let (mut ha, _) = Handshake::new(&alice, Some(bob.peer_id));
        let (mut hb, _) = Handshake::new(&bob, Some(alice.peer_id));
        run_full_handshake(&mut ha, &alice, &mut hb, &bob);

        assert!(ha.is_established());
        assert!(hb.is_established());
        assert_eq!(ha.peer_id(), Some(bob.peer_id));
        assert_eq!(hb.peer_id(), Some(alice.peer_id));
    }

    #[test]
    fn both_sides_derive_same_keys() {
        let alice = DeviceIdentity::generate("alice");
        let bob = DeviceIdentity::generate("bob");
        let (mut ha, _) = Handshake::new(&alice, Some(bob.peer_id));
        let (mut hb, _) = Handshake::new(&bob, Some(alice.peer_id));
        run_full_handshake(&mut ha, &alice, &mut hb, &bob);

        let ra = result_of(&mut ha);
        let rb = result_of(&mut hb);
        assert!(ha.is_established() && hb.is_established());
        assert_eq!(ra.keys.session_id, rb.keys.session_id);
        assert_eq!(ra.send_key, rb.recv_key);
        assert_eq!(ra.recv_key, rb.send_key);
    }

    #[test]
    fn fresh_sessions_produce_fresh_keys() {
        // Run two independent handshakes between the same identities; the
        // session keys MUST differ (fresh ephemeral ML-KEM material).
        let alice = DeviceIdentity::generate("alice");
        let bob = DeviceIdentity::generate("bob");

        let (mut ha1, _) = Handshake::new(&alice, Some(bob.peer_id));
        let (mut hb1, _) = Handshake::new(&bob, Some(alice.peer_id));
        run_full_handshake(&mut ha1, &alice, &mut hb1, &bob);

        let (mut ha2, _) = Handshake::new(&alice, Some(bob.peer_id));
        let (mut hb2, _) = Handshake::new(&bob, Some(alice.peer_id));
        run_full_handshake(&mut ha2, &alice, &mut hb2, &bob);

        let r1 = result_of(&mut ha1);
        let r2 = result_of(&mut ha2);
        assert_ne!(r1.keys.session_id, r2.keys.session_id);
        assert_ne!(r1.send_key, r2.send_key);
        assert_ne!(r1.recv_key, r2.recv_key);
    }

    #[test]
    fn send_and_recv_keys_complement() {
        // Alice's send key must equal Bob's receive key (and vice versa).
        let alice = DeviceIdentity::generate("alice");
        let bob = DeviceIdentity::generate("bob");
        let (mut ha, _) = Handshake::new(&alice, Some(bob.peer_id));
        let (mut hb, _) = Handshake::new(&bob, Some(alice.peer_id));
        run_full_handshake(&mut ha, &alice, &mut hb, &bob);

        let ra = result_of(&mut ha);
        let rb = result_of(&mut hb);
        assert_eq!(ra.send_key, rb.recv_key);
        assert_eq!(ra.recv_key, rb.send_key);
        assert_eq!(ra.keys.session_id, rb.keys.session_id);
    }

    #[test]
    fn wrong_expected_peer_fails_closed() {
        let alice = DeviceIdentity::generate("alice");
        let bob = DeviceIdentity::generate("bob");
        let mallory = DeviceIdentity::generate("mallory");

        // Alice expects Bob but Mallory answers.
        let (mut ha, _) = Handshake::new(&alice, Some(bob.peer_id));
        let (_hm, m_hello) = Handshake::new(&mallory, Some(alice.peer_id));

        // Mallory sends her Hello; Alice must reject it immediately.
        match ha.on_frame(&alice, &m_hello) {
            Err(HandshakeError::PeerIdMismatch) => {}
            _ => panic!("expected PeerIdMismatch"),
        }
    }

    #[test]
    fn tampered_handshake_fails_closed() {
        let alice = DeviceIdentity::generate("alice");
        let bob = DeviceIdentity::generate("bob");
        let (mut ha, _) = Handshake::new(&alice, Some(bob.peer_id));
        let (mut hb, _) = Handshake::new(&bob, Some(alice.peer_id));

        // Round 1: hellos -> offers
        let alice_hello = vec![Frame::handshake(MessageType::Hello, encode_hello(&alice))];
        let bob_hello = vec![Frame::handshake(MessageType::Hello, encode_hello(&bob))];
        let a_offer = drive(&mut ha, &alice, bob_hello);
        let b_offer = drive(&mut hb, &bob, alice_hello);
        // Round 2: offers -> responses
        let a_ct = drive(&mut ha, &alice, b_offer);
        let b_ct = drive(&mut hb, &bob, a_offer);
        // Round 3: Mallory tampers with Alice's KemResponse before Bob sees it.
        let mut tampered = a_ct[0].clone();
        assert_eq!(tampered.msg_type, MessageType::KemResponse);
        tampered.payload[0] ^= 0x01;
        // Alice gets Bob's genuine response (her transcript stays clean)...
        let a_auth = drive(&mut ha, &alice, b_ct);
        assert_eq!(a_auth[0].msg_type, MessageType::Auth);
        // ...while Bob derives his transcript from the tampered response.
        let b_auth = drive(&mut hb, &bob, vec![tampered]);
        assert_eq!(b_auth[0].msg_type, MessageType::Auth);
        // Round 4: Alice's Auth must be rejected by Bob (transcript mismatch).
        match hb.on_frame(&bob, &a_auth[0]) {
            Err(HandshakeError::BadSignature) => {}
            other => panic!("expected BadSignature, got {other:?}"),
        }
        assert!(!ha.is_established());
        assert!(!hb.is_established());
    }

    #[test]
    fn malformed_hello_rejected() {
        let alice = DeviceIdentity::generate("alice");
        let bob = DeviceIdentity::generate("bob");
        let (_ha, _) = Handshake::new(&alice, Some(bob.peer_id));
        let (mut hb, _) = Handshake::new(&bob, Some(alice.peer_id));
        // Give Alice a truncated/bogus hello payload.
        let bogus = Frame::handshake(MessageType::Hello, vec![1, 2, 3]);
        assert!(hb.on_frame(&bob, &bogus).is_err());
        assert!(!hb.is_established());
    }
}
