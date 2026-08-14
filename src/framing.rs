//! Versioned, length-prefixed JeanGrey wire frames.
//!
//! Wire layout (all integers big-endian):
//!
//! ```text
//! magic        [2]  0x4A 0x47 ("JG")
//! version      [1]  protocol version (currently 1)
//! msg_type     [1]  MessageType
//! flags        [1]  reserved, must be 0
//! session_id  [16]  zeroed for handshake frames
//! seq          [4]  zeroed for handshake frames
//! msg_id       [8]  zeroed for handshake frames
//! payload_len  [4]  max 65536
//! payload  [payload_len]
//! ```
//!
//! Malformed frames (bad magic, unsupported version, oversized payloads,
//! unknown types) are rejected during decode; this module is the first line
//! of defense against garbage on the wire.

/// Two-byte magic identifying JeanGrey frames.
pub const MAGIC: [u8; 2] = [0x4A, 0x47];
/// Current protocol version.
pub const VERSION: u8 = 1;
/// Maximum accepted payload size in bytes.
pub const MAX_PAYLOAD: usize = 65536;
/// Fixed header length (everything before the payload).
pub const HEADER_LEN: usize = 2 + 1 + 1 + 1 + 16 + 4 + 8 + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Hello = 1,
    KemOffer = 2,
    KemResponse = 3,
    Auth = 4,
    Ready = 5,
    Message = 6,
    Ack = 7,
    Error = 8,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(MessageType::Hello),
            2 => Some(MessageType::KemOffer),
            3 => Some(MessageType::KemResponse),
            4 => Some(MessageType::Auth),
            5 => Some(MessageType::Ready),
            6 => Some(MessageType::Message),
            7 => Some(MessageType::Ack),
            8 => Some(MessageType::Error),
            _ => None,
        }
    }
}

/// A parsed frame. `session_id`, `seq`, `msg_id` are only meaningful for
/// session frames (Message/Ack); handshake frames carry zeros.
#[derive(Debug, Clone)]
pub struct Frame {
    pub msg_type: MessageType,
    pub flags: u8,
    pub session_id: [u8; 16],
    pub seq: u32,
    pub msg_id: u64,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn handshake(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Frame {
            msg_type,
            flags: 0,
            session_id: [0u8; 16],
            seq: 0,
            msg_id: 0,
            payload,
        }
    }

    pub fn is_session_frame(&self) -> bool {
        matches!(self.msg_type, MessageType::Message | MessageType::Ack)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    BadMagic,
    UnsupportedVersion(u8),
    UnknownType(u8),
    ReservedFlags(u8),
    PayloadTooLarge(usize),
    Truncated,
    SessionFieldsOnHandshakeFrame,
    HandshakeFieldsOnSessionFrame,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::BadMagic => write!(f, "bad magic"),
            FrameError::UnsupportedVersion(v) => write!(f, "unsupported protocol version {v}"),
            FrameError::UnknownType(t) => write!(f, "unknown message type {t}"),
            FrameError::ReservedFlags(fl) => write!(f, "reserved flags set: {fl:#x}"),
            FrameError::PayloadTooLarge(n) => write!(f, "payload too large: {n}"),
            FrameError::Truncated => write!(f, "truncated frame"),
            FrameError::SessionFieldsOnHandshakeFrame => {
                write!(f, "session fields on handshake frame")
            }
            FrameError::HandshakeFieldsOnSessionFrame => {
                write!(f, "handshake fields on session frame")
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// Encode a frame into its wire representation (without length prefix; the
/// length prefix is applied by the transport).
pub fn encode(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + frame.payload.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(frame.msg_type as u8);
    out.push(frame.flags);
    out.extend_from_slice(&frame.session_id);
    out.extend_from_slice(&frame.seq.to_be_bytes());
    out.extend_from_slice(&frame.msg_id.to_be_bytes());
    out.extend_from_slice(&(frame.payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&frame.payload);
    out
}

/// Decode a single frame from raw wire bytes. Rejects malformed input.
pub fn decode(buf: &[u8]) -> Result<Frame, FrameError> {
    if buf.len() < HEADER_LEN {
        return Err(FrameError::Truncated);
    }
    if buf[0] != MAGIC[0] || buf[1] != MAGIC[1] {
        return Err(FrameError::BadMagic);
    }
    if buf[2] != VERSION {
        return Err(FrameError::UnsupportedVersion(buf[2]));
    }
    let msg_type = MessageType::from_u8(buf[3]).ok_or(FrameError::UnknownType(buf[3]))?;
    let flags = buf[4];
    if flags != 0 {
        return Err(FrameError::ReservedFlags(flags));
    }
    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&buf[5..21]);
    let seq = u32::from_be_bytes(buf[21..25].try_into().unwrap());
    let msg_id = u64::from_be_bytes(buf[25..33].try_into().unwrap());
    let payload_len = u32::from_be_bytes(buf[33..37].try_into().unwrap()) as usize;
    if payload_len > MAX_PAYLOAD {
        return Err(FrameError::PayloadTooLarge(payload_len));
    }
    if buf.len() < HEADER_LEN + payload_len {
        return Err(FrameError::Truncated);
    }
    let payload = buf[HEADER_LEN..HEADER_LEN + payload_len].to_vec();

    let is_hs = matches!(
        msg_type,
        MessageType::Hello
            | MessageType::KemOffer
            | MessageType::KemResponse
            | MessageType::Auth
            | MessageType::Ready
            | MessageType::Error
    );
    if is_hs {
        if session_id != [0u8; 16] || seq != 0 || msg_id != 0 {
            return Err(FrameError::SessionFieldsOnHandshakeFrame);
        }
    } else if session_id == [0u8; 16] {
        return Err(FrameError::HandshakeFieldsOnSessionFrame);
    }

    Ok(Frame {
        msg_type,
        flags,
        session_id,
        seq,
        msg_id,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_handshake() {
        let f = Frame::handshake(MessageType::Hello, vec![1, 2, 3]);
        let bytes = encode(&f);
        assert_eq!(decode(&bytes).unwrap().msg_type, MessageType::Hello);
    }

    #[test]
    fn round_trip_session() {
        let f = Frame {
            msg_type: MessageType::Message,
            flags: 0,
            session_id: [7u8; 16],
            seq: 42,
            msg_id: 999,
            payload: vec![0u8; 100],
        };
        let bytes = encode(&f);
        let d = decode(&bytes).unwrap();
        assert_eq!(d.session_id, [7u8; 16]);
        assert_eq!(d.seq, 42);
        assert_eq!(d.msg_id, 999);
    }

    #[test]
    fn rejects_bad_magic() {
        let f = Frame::handshake(MessageType::Hello, vec![]);
        let mut bytes = encode(&f);
        bytes[0] ^= 1;
        assert_eq!(decode(&bytes).unwrap_err(), FrameError::BadMagic);
    }

    #[test]
    fn rejects_bad_version() {
        let f = Frame::handshake(MessageType::Hello, vec![]);
        let mut bytes = encode(&f);
        bytes[2] = 99;
        assert!(matches!(
            decode(&bytes),
            Err(FrameError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn rejects_unknown_type() {
        let f = Frame::handshake(MessageType::Hello, vec![]);
        let mut bytes = encode(&f);
        bytes[3] = 0x55;
        assert!(matches!(decode(&bytes), Err(FrameError::UnknownType(0x55))));
    }

    #[test]
    fn rejects_flags() {
        let f = Frame::handshake(MessageType::Hello, vec![]);
        let mut bytes = encode(&f);
        bytes[4] = 1;
        assert!(matches!(decode(&bytes), Err(FrameError::ReservedFlags(_))));
    }

    #[test]
    fn rejects_oversized_payload() {
        // Craft a header claiming a giant payload but truncated buffer.
        let mut bytes = encode(&Frame::handshake(MessageType::Hello, vec![]));
        bytes.truncate(HEADER_LEN);
        bytes[33..37].copy_from_slice(&(u32::MAX).to_be_bytes());
        assert!(matches!(
            decode(&bytes),
            Err(FrameError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn rejects_truncated() {
        let f = Frame::handshake(MessageType::Hello, vec![1, 2, 3, 4, 5]);
        let bytes = encode(&f);
        assert_eq!(
            decode(&bytes[..bytes.len() - 2]).unwrap_err(),
            FrameError::Truncated
        );
        assert!(decode(&bytes[..5]).is_err());
    }

    #[test]
    fn rejects_session_fields_on_handshake() {
        let mut f = Frame::handshake(MessageType::Hello, vec![]);
        f.session_id = [1u8; 16];
        assert_eq!(
            decode(&encode(&f)).unwrap_err(),
            FrameError::SessionFieldsOnHandshakeFrame
        );
    }

    #[test]
    fn rejects_handshake_fields_on_session() {
        let f = Frame {
            msg_type: MessageType::Message,
            flags: 0,
            session_id: [0u8; 16],
            seq: 1,
            msg_id: 2,
            payload: vec![],
        };
        assert_eq!(
            decode(&encode(&f)).unwrap_err(),
            FrameError::HandshakeFieldsOnSessionFrame
        );
    }

    #[test]
    fn accepts_max_payload() {
        let f = Frame {
            msg_type: MessageType::Message,
            flags: 0,
            session_id: [1u8; 16],
            seq: 0,
            msg_id: 0,
            payload: vec![0u8; MAX_PAYLOAD],
        };
        assert!(decode(&encode(&f)).is_ok());
    }
}
