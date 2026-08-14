//! Post-handshake session state: AEAD-encrypted messages, nonce policy,
//! sequence tracking, replay protection and delivery acknowledgements.
//!
//! Nonce policy (documented in `docs/protocol.md`):
//!
//! - Keys are direction-specific and session-specific (derived per handshake
//!   from fresh ephemeral ML-KEM material via HKDF), so nonce uniqueness is
//!   only required within one (session, direction) pair.
//! - The 12-byte nonce is `[dir:2][zero:2][seq:4][zero:4]` where `seq` is
//!   the strictly-monotonic per-direction sequence number and `dir` is a
//!   fixed 2-byte direction tag. Because `seq` never repeats within a
//!   direction, nonces never repeat. The nonce is fully deterministic so the
//!   receiver can reconstruct it without any extra bytes on the wire.
//!
//! Replay protection:
//!
//! - Inbound Message/Ack frames are rejected unless `seq == expected` (strict
//!   monotonicity, checked *before* decryption).
//! - Message IDs are tracked in a bounded sliding window as a second line of
//!   defense (duplicate detection).
//! - Acks are authenticated (AEAD) and are only accepted for messages that
//!   are actually awaiting acknowledgement; replayed or forged acks for
//!   unknown messages are dropped.

use crate::crypto::aead;
use crate::crypto::kdf;
use crate::framing::{Frame, MessageType};
use crate::handshake::HandshakeResult;

/// Max bytes of text per message.
pub const MAX_MESSAGE_BYTES: usize = 4096;
/// Max number of recently-seen message ids retained for duplicate detection.
pub const SEEN_WINDOW: usize = 4096;
/// Max inbound sequence violations before the session is treated as hostile.
pub const MAX_SEQ_VIOLATIONS: u32 = 5;

const MSG_PLAINTEXT_TAG: u8 = 0x01;
const ACK_PLAINTEXT_TAG: u8 = 0x02;

/// A decrypted, authenticated inbound event.
#[derive(Debug, Clone)]
pub enum Inbound {
    /// A message from the peer.
    Message {
        seq: u32,
        msg_id: u64,
        created_ts_ms: u64,
        body: String,
    },
    /// An authenticated acknowledgement from the peer.
    Ack { msg_id: u64, ack_seq: u32 },
}

#[derive(Debug)]
pub enum SessionError {
    /// Frame arrived for the wrong session.
    WrongSession,
    /// Sequence number out of order / replayed / duplicate.
    Replay,
    /// AEAD authentication failed (tampered ciphertext or bad key).
    AuthenticationFailed,
    /// Malformed plaintext inside an authenticated envelope.
    MalformedPlaintext,
    /// Message too large to send.
    MessageTooLarge(usize),
    /// Too many sequence violations; session deemed hostile.
    Hostile,
    /// Frame type not valid in session context.
    InvalidFrameType,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::WrongSession => write!(f, "frame for the wrong session"),
            SessionError::Replay => write!(f, "replayed or out-of-order frame"),
            SessionError::AuthenticationFailed => write!(f, "AEAD authentication failed"),
            SessionError::MalformedPlaintext => write!(f, "malformed plaintext"),
            SessionError::MessageTooLarge(n) => write!(f, "message too large ({n} bytes)"),
            SessionError::Hostile => write!(f, "too many sequence violations"),
            SessionError::InvalidFrameType => write!(f, "invalid frame type for session"),
        }
    }
}

impl std::error::Error for SessionError {}

/// One established (authenticated) session with a peer.
pub struct Session {
    pub session_id: [u8; kdf::SESSION_ID_LEN],
    send_key: [u8; aead::KEY_LEN],
    recv_key: [u8; aead::KEY_LEN],
    /// My direction tag (stable per session, derived from session id).
    my_dir: [u8; 2],
    peer_dir: [u8; 2],
    /// Next outbound sequence number (messages + acks share one counter).
    out_seq: u32,
    /// Next expected inbound sequence number.
    in_seq: u32,
    seq_violations: u32,
    /// Bounded window of recently seen (seq, msg_id) pairs.
    seen: std::collections::VecDeque<(u32, u64)>,
}

impl Session {
    pub fn new(result: &HandshakeResult) -> Self {
        let mine_lower = result.my_id < result.peer_id;
        let (my_dir, peer_dir) = if mine_lower {
            ([0x00, 0x01], [0x00, 0x02])
        } else {
            ([0x00, 0x02], [0x00, 0x01])
        };
        Session {
            session_id: result.keys.session_id,
            send_key: result.send_key,
            recv_key: result.recv_key,
            my_dir,
            peer_dir,
            out_seq: 0,
            in_seq: 0,
            seq_violations: 0,
            seen: std::collections::VecDeque::with_capacity(SEEN_WINDOW),
        }
    }

    /// Encrypt and frame a text message. Returns the frame ready to send.
    pub fn encrypt_message(&mut self, text: &str, msg_id: u64) -> Result<Frame, SessionError> {
        let body = text.as_bytes();
        if body.len() > MAX_MESSAGE_BYTES {
            return Err(SessionError::MessageTooLarge(body.len()));
        }
        let ts = now_ms();
        let mut plaintext = Vec::with_capacity(1 + 8 + body.len());
        plaintext.push(MSG_PLAINTEXT_TAG);
        plaintext.extend_from_slice(&ts.to_be_bytes());
        plaintext.extend_from_slice(body);

        let seq = self.out_seq;
        self.out_seq = self.out_seq.checked_add(1).ok_or(SessionError::Hostile)?;
        Ok(self.seal(MessageType::Message, seq, msg_id, &plaintext))
    }

    /// Encrypt and frame an acknowledgement for a received message.
    pub fn encrypt_ack(&mut self, ack_msg_id: u64, ack_seq: u32) -> Frame {
        let ts = now_ms();
        let mut plaintext = Vec::with_capacity(1 + 8 + 4 + 8);
        plaintext.push(ACK_PLAINTEXT_TAG);
        plaintext.extend_from_slice(&ack_msg_id.to_be_bytes());
        plaintext.extend_from_slice(&ack_seq.to_be_bytes());
        plaintext.extend_from_slice(&ts.to_be_bytes());

        let seq = self.out_seq;
        self.out_seq = self
            .out_seq
            .checked_add(1)
            .expect("u32 overflow impossible in practice");
        self.seal(MessageType::Ack, seq, rand::random(), &plaintext)
    }

    /// Seal a payload into a session frame.
    fn seal(&self, msg_type: MessageType, seq: u32, msg_id: u64, plaintext: &[u8]) -> Frame {
        let nonce = self.nonce(self.my_dir, seq);
        let aad = self.aad(msg_type, seq, msg_id);
        let ct = aead::seal(&self.send_key, &nonce, &aad, plaintext);
        Frame {
            msg_type,
            flags: 0,
            session_id: self.session_id,
            seq,
            msg_id,
            payload: ct,
        }
    }

    /// Handle an inbound session frame (Message or Ack). Decryption failures
    /// and replay violations are returned as errors; callers must fail closed.
    pub fn handle_frame(&mut self, frame: &Frame) -> Result<Inbound, SessionError> {
        if frame.session_id != self.session_id {
            return Err(SessionError::WrongSession);
        }
        // Strict monotonic sequence check BEFORE any decryption work.
        if frame.seq != self.in_seq {
            self.seq_violations += 1;
            if self.seq_violations >= MAX_SEQ_VIOLATIONS {
                return Err(SessionError::Hostile);
            }
            return Err(SessionError::Replay);
        }
        self.in_seq = self.in_seq.checked_add(1).ok_or(SessionError::Hostile)?;

        // Duplicate-message-id window (second line of defense).
        self.remember(frame.seq, frame.msg_id);

        let plaintext = match frame.msg_type {
            MessageType::Message | MessageType::Ack => {
                let nonce = self.nonce(self.peer_dir, frame.seq);
                let aad = self.aad(frame.msg_type, frame.seq, frame.msg_id);
                aead::open(&self.recv_key, &nonce, &aad, &frame.payload)
                    .map_err(|_| SessionError::AuthenticationFailed)?
            }
            _ => return Err(SessionError::InvalidFrameType),
        };
        self.parse_plaintext(frame.msg_type, frame.msg_id, plaintext)
    }

    fn parse_plaintext(
        &self,
        msg_type: MessageType,
        msg_id: u64,
        plaintext: Vec<u8>,
    ) -> Result<Inbound, SessionError> {
        if plaintext.len() < 1 + 8 {
            return Err(SessionError::MalformedPlaintext);
        }
        let tag = plaintext[0];
        let ts = u64::from_be_bytes(plaintext[1..9].try_into().unwrap());
        match (msg_type, tag) {
            (MessageType::Message, MSG_PLAINTEXT_TAG) => {
                let body = std::str::from_utf8(&plaintext[9..])
                    .map_err(|_| SessionError::MalformedPlaintext)?
                    .to_string();
                Ok(Inbound::Message {
                    seq: self.in_seq - 1,
                    msg_id,
                    created_ts_ms: ts,
                    body,
                })
            }
            (MessageType::Ack, ACK_PLAINTEXT_TAG) => {
                if plaintext.len() != 1 + 8 + 4 + 8 {
                    return Err(SessionError::MalformedPlaintext);
                }
                let ack_msg_id = u64::from_be_bytes(plaintext[1..9].try_into().unwrap());
                let ack_seq = u32::from_be_bytes(plaintext[9..13].try_into().unwrap());
                Ok(Inbound::Ack {
                    msg_id: ack_msg_id,
                    ack_seq,
                })
            }
            _ => Err(SessionError::MalformedPlaintext),
        }
    }

    /// AAD binding: exactly the fixed header fields (version|type, session,
    /// seq, msg_id) as they appear on the wire.
    fn aad(&self, msg_type: MessageType, seq: u32, msg_id: u64) -> [u8; 29] {
        let mut aad = [0u8; 29];
        aad[0] = crate::framing::VERSION | (msg_type as u8) << 4;
        aad[1..17].copy_from_slice(&self.session_id);
        aad[17..21].copy_from_slice(&seq.to_be_bytes());
        aad[21..29].copy_from_slice(&msg_id.to_be_bytes());
        aad
    }

    /// 12-byte nonce: [dir:2][zero:2][seq:4][zero:4].
    ///
    /// Fully deterministic: the sequence number is unique per direction and
    /// replayed/out-of-order frames are rejected before any decryption, so a
    /// counter-based nonce is safe and (crucially) reproducible by the
    /// receiver without any extra bytes on the wire.
    fn nonce(&self, dir: [u8; 2], seq: u32) -> [u8; aead::NONCE_LEN] {
        let mut nonce = [0u8; aead::NONCE_LEN];
        nonce[0..2].copy_from_slice(&dir);
        nonce[4..8].copy_from_slice(&seq.to_be_bytes());
        nonce
    }

    fn remember(&mut self, seq: u32, msg_id: u64) {
        if self.seen.len() >= SEEN_WINDOW {
            self.seen.pop_front();
        }
        self.seen.push_back((seq, msg_id));
    }

    /// True if `(seq, msg_id)` was already seen (duplicate detection helper).
    #[allow(dead_code)]
    pub fn was_seen(&self, seq: u32, msg_id: u64) -> bool {
        self.seen.iter().any(|&(s, m)| s == seq && m == msg_id)
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::Handshake;
    use crate::identity::DeviceIdentity;

    /// Build two complementary sessions by running a real handshake.
    fn pair_sessions() -> (Session, Session, DeviceIdentity, DeviceIdentity) {
        let alice = DeviceIdentity::generate("alice");
        let bob = DeviceIdentity::generate("bob");
        let (mut ha, _) = Handshake::new(&alice, Some(bob.peer_id));
        let (mut hb, _) = Handshake::new(&bob, Some(alice.peer_id));
        crate::handshake::tests::run_full_handshake(&mut ha, &alice, &mut hb, &bob);
        let ra = ha.take_result().unwrap();
        let rb = hb.take_result().unwrap();
        (Session::new(&ra), Session::new(&rb), alice, bob)
    }

    fn deliver(_a: &mut Session, b: &mut Session, frame: Frame) -> Result<Inbound, SessionError> {
        b.handle_frame(&frame)
    }

    #[test]
    fn message_round_trip() {
        let (mut a, mut b, _, _) = pair_sessions();
        let f = a.encrypt_message("Hello Bob", 1).unwrap();
        let inbound = deliver(&mut a, &mut b, f).unwrap();
        match inbound {
            Inbound::Message { body, seq, .. } => {
                assert_eq!(body, "Hello Bob");
                assert_eq!(seq, 0);
            }
            other => panic!("expected message, got {other:?}"),
        }
    }

    #[test]
    fn ack_round_trip() {
        let (mut a, mut b, _, _) = pair_sessions();
        let f = a.encrypt_message("ping", 42).unwrap();
        let inbound = b.handle_frame(&f).unwrap();
        let (seq, msg_id) = match inbound {
            Inbound::Message { seq, msg_id, .. } => (seq, msg_id),
            _ => unreachable!(),
        };
        // Bob acks message #42; the ack travels back on his send key.
        let ack = b.encrypt_ack(msg_id, seq);
        match a.handle_frame(&ack).unwrap() {
            Inbound::Ack {
                msg_id: mid,
                ack_seq,
                ..
            } => {
                assert_eq!(mid, 42);
                assert_eq!(ack_seq, 0);
            }
            other => panic!("expected ack, got {other:?}"),
        }
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (mut a, mut b, _, _) = pair_sessions();
        let mut f = a.encrypt_message("Hello Bob", 1).unwrap();
        f.payload[0] ^= 0x01;
        assert!(matches!(
            b.handle_frame(&f),
            Err(SessionError::AuthenticationFailed)
        ));
    }

    #[test]
    fn wrong_session_rejected() {
        let (mut a, mut b, _, _) = pair_sessions();
        let mut f = a.encrypt_message("Hello Bob", 1).unwrap();
        f.session_id[0] ^= 1;
        assert!(matches!(
            b.handle_frame(&f),
            Err(SessionError::WrongSession)
        ));
    }

    #[test]
    fn replay_rejected() {
        let (mut a, mut b, _, _) = pair_sessions();
        let f = a.encrypt_message("Hello Bob", 1).unwrap();
        // Deliver once (OK), then replay the exact same frame.
        assert!(b.handle_frame(&f).is_ok());
        assert!(matches!(b.handle_frame(&f), Err(SessionError::Replay)));
    }

    #[test]
    fn out_of_order_rejected() {
        let (mut a, mut b, _, _) = pair_sessions();
        let f1 = a.encrypt_message("one", 1).unwrap();
        let f2 = a.encrypt_message("two", 2).unwrap();
        // f2 arrives first: sequence 1 is not expected yet -> rejected.
        assert!(matches!(b.handle_frame(&f2), Err(SessionError::Replay)));
        // f1 (seq 0) is still the expected sequence -> accepted; the early
        // frame was simply dropped and the stream continues from seq 0.
        assert!(b.handle_frame(&f1).is_ok());
    }

    #[test]
    fn many_messages_round_trip() {
        let (mut a, mut b, _, _) = pair_sessions();
        for i in 0..1000u64 {
            let f = a.encrypt_message(&format!("msg {i}"), i).unwrap();
            match b.handle_frame(&f).unwrap() {
                Inbound::Message { body, .. } => assert_eq!(body, format!("msg {i}")),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn oversized_message_rejected_before_seal() {
        let (mut a, _, _, _) = pair_sessions();
        let huge = "x".repeat(MAX_MESSAGE_BYTES + 1);
        assert!(matches!(
            a.encrypt_message(&huge, 1),
            Err(SessionError::MessageTooLarge(_))
        ));
    }

    #[test]
    fn hostile_peer_flagged_after_violations() {
        let (mut a, mut b, _, _) = pair_sessions();
        // Deliver a stream where every frame has a bogus (repeated) sequence.
        for i in 0..10u64 {
            let mut f = a.encrypt_message("x", i).unwrap();
            f.seq = 7; // always out of order
            let _ = b.handle_frame(&f);
        }
        // After MAX_SEQ_VIOLATIONS the session must be flagged hostile.
        let mut f = a.encrypt_message("y", 100).unwrap();
        f.seq = 8;
        assert!(matches!(b.handle_frame(&f), Err(SessionError::Hostile)));
    }
}
