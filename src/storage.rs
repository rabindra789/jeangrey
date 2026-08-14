//! On-disk persistence for JeanGrey MVP-1.
//!
//! Nothing sensitive is ever stored in plaintext beyond what the operator
//! chooses: `identity.json` holds the ML-DSA seed and the transport keypair
//! (the keys of the device) and `history.jsonl` holds only message metadata
//! (timestamps, peer, msg id, delivery status) — never message bodies.
//!
//! File layout under the data dir:
//!
//! - `identity.json` — the device identity (see `identity.rs`).
//! - `config.json`   — non-secret node configuration.
//! - `history.jsonl` — append-only metadata log.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use libp2p::identity::Keypair;
use serde::{Deserialize, Serialize};

use crate::crypto::mldsa;
use crate::identity::DeviceIdentity;

/// The device identity file name.
pub const IDENTITY_FILE: &str = "identity.json";
/// The config file name.
pub const CONFIG_FILE: &str = "config.json";
/// The message metadata log file name.
pub const HISTORY_FILE: &str = "history.jsonl";

/// A serialized device identity. The seed is the only secret; it is written
/// with restrictive permissions on Unix (best effort on Windows).
#[derive(Debug, Serialize, Deserialize)]
struct IdentityFile {
    v: u32,
    user_id_hex: String,
    user_name: String,
    device_uuid_hex: String,
    mldsa_seed_b64: String,
    transport_keypair_b64: String,
    peer_id_b58: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeConfig {
    pub listen_port: u16,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig { listen_port: 9000 }
    }
}

#[derive(Debug, Clone)]
pub enum HistoryKind {
    Sent {
        peer: String,
        msg_id: u64,
        status: String,
    },
    Received {
        peer: String,
        msg_id: u64,
    },
}

impl HistoryKind {
    fn as_json(&self) -> String {
        match self {
            HistoryKind::Sent { peer, msg_id, status } => format!(
                "{{\"event\":\"sent\",\"peer\":\"{}\",\"msg_id\":{},\"status\":\"{}\",\"ts_ms\":{}}}",
                peer, msg_id, status, now_ms()
            ),
            HistoryKind::Received { peer, msg_id } => format!(
                "{{\"event\":\"received\",\"peer\":\"{}\",\"msg_id\":{},\"ts_ms\":{}}}",
                peer, msg_id, now_ms()
            ),
        }
    }
}

pub struct Storage {
    dir: PathBuf,
}

impl Storage {
    pub fn new(dir: PathBuf) -> Self {
        Storage { dir }
    }

    pub fn ensure(&self) -> Result<(), StorageError> {
        fs::create_dir_all(&self.dir).map_err(StorageError::Io)?;
        Ok(())
    }

    /// Load the device identity, or `None` if not initialized.
    pub fn load_identity(&self) -> Result<Option<DeviceIdentity>, StorageError> {
        let path = self.dir.join(IDENTITY_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let text = fs::read_to_string(&path).map_err(StorageError::Io)?;
        let file: IdentityFile = serde_json::from_str(&text).map_err(|_| StorageError::Corrupt)?;
        let seed_bytes = B64
            .decode(&file.mldsa_seed_b64)
            .map_err(|_| StorageError::Corrupt)?;
        let seed: [u8; mldsa::SEED_LEN] =
            seed_bytes.try_into().map_err(|_| StorageError::Corrupt)?;
        let uuid_bytes = hex::decode(&file.device_uuid_hex).map_err(|_| StorageError::Corrupt)?;
        let device_uuid: [u8; 16] = uuid_bytes.try_into().map_err(|_| StorageError::Corrupt)?;
        let user_id_bytes = hex::decode(&file.user_id_hex).map_err(|_| StorageError::Corrupt)?;
        let user_id: [u8; 16] = user_id_bytes
            .try_into()
            .map_err(|_| StorageError::Corrupt)?;
        let transport_keypair =
            decode_keypair(&file.transport_keypair_b64).ok_or(StorageError::Corrupt)?;
        let identity = DeviceIdentity::from_seed(
            user_id,
            file.user_name.clone(),
            seed,
            device_uuid,
            transport_keypair,
        );
        // Self-check: the stored peer id must match the self-certifying id.
        if identity.peer_id.to_base58() != file.peer_id_b58 {
            return Err(StorageError::Corrupt);
        }
        Ok(Some(identity))
    }

    /// Persist a device identity (creates `identity.json`).
    pub fn save_identity(&self, identity: &DeviceIdentity) -> Result<(), StorageError> {
        self.ensure()?;
        let file = IdentityFile {
            v: 1,
            user_id_hex: hex::encode(identity.user.user_id),
            user_name: identity.user.user_name.clone(),
            device_uuid_hex: hex::encode(identity.device_uuid),
            mldsa_seed_b64: B64.encode(identity.secret_key.seed()),
            transport_keypair_b64: encode_keypair(&identity.transport_keypair),
            peer_id_b58: identity.peer_id.to_base58(),
        };
        let json = serde_json::to_string_pretty(&file).map_err(|_| StorageError::Corrupt)?;
        let path = self.dir.join(IDENTITY_FILE);
        write_atomic(&path, json.as_bytes())?;
        Ok(())
    }

    pub fn load_config(&self) -> Result<NodeConfig, StorageError> {
        let path = self.dir.join(CONFIG_FILE);
        if !path.exists() {
            return Ok(NodeConfig::default());
        }
        let text = fs::read_to_string(&path).map_err(StorageError::Io)?;
        serde_json::from_str(&text).map_err(|_| StorageError::Corrupt)
    }

    pub fn save_config(&self, config: &NodeConfig) -> Result<(), StorageError> {
        self.ensure()?;
        let json = serde_json::to_string_pretty(config).map_err(|_| StorageError::Corrupt)?;
        write_atomic(&self.dir.join(CONFIG_FILE), json.as_bytes())?;
        Ok(())
    }

    /// Append a metadata-only history entry.
    pub fn append_history(&self, entry: HistoryKind) -> Result<(), StorageError> {
        self.ensure()?;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(HISTORY_FILE))
            .map_err(StorageError::Io)?;
        writeln!(file, "{}", entry.as_json()).map_err(StorageError::Io)?;
        Ok(())
    }
}

fn encode_keypair(kp: &Keypair) -> String {
    let bytes = kp
        .to_protobuf_encoding()
        .expect("in-memory keypair protobuf encoding is infallible");
    B64.encode(bytes)
}

fn decode_keypair(b64: &str) -> Option<Keypair> {
    let bytes = B64.decode(b64).ok()?;
    Keypair::from_protobuf_encoding(&bytes).ok()
}

/// Write a file atomically (write to temp, then rename).
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp).map_err(StorageError::Io)?;
        f.write_all(bytes).map_err(StorageError::Io)?;
        f.sync_all().map_err(StorageError::Io)?;
    }
    fs::rename(&tmp, path).map_err(StorageError::Io)?;
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    Corrupt,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "io error: {e}"),
            StorageError::Corrupt => write!(f, "corrupt or tampered storage file"),
        }
    }
}

impl std::error::Error for StorageError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("jeangrey-test-{}-{}", name, rand::random::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn identity_round_trip() {
        let dir = temp_dir("identity");
        let storage = Storage::new(dir.clone());
        let id = DeviceIdentity::generate("alice");
        storage.save_identity(&id).unwrap();
        let loaded = storage.load_identity().unwrap().unwrap();
        assert_eq!(loaded.peer_id, id.peer_id);
        assert_eq!(loaded.user.user_name, "alice");
        assert_eq!(loaded.user.user_id, id.user.user_id);
        assert_eq!(loaded.transport_peer_id(), id.transport_peer_id());
        assert_eq!(loaded.device_uuid, id.device_uuid);
        assert_eq!(loaded.public_key_bytes(), id.public_key_bytes());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_identity_is_none() {
        let dir = temp_dir("missing");
        let storage = Storage::new(dir.clone());
        assert!(storage.load_identity().unwrap().is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tampered_identity_rejected() {
        let dir = temp_dir("tampered");
        let storage = Storage::new(dir.clone());
        let id = DeviceIdentity::generate("alice");
        storage.save_identity(&id).unwrap();
        // Flip a byte in the seed.
        let path = dir.join(IDENTITY_FILE);
        let text = fs::read_to_string(&path).unwrap();
        let mut file: IdentityFile = serde_json::from_str(&text).unwrap();
        let mut seed = B64.decode(&file.mldsa_seed_b64).unwrap();
        seed[0] ^= 1;
        file.mldsa_seed_b64 = B64.encode(&seed);
        fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();
        assert!(storage.load_identity().is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn config_round_trip() {
        let dir = temp_dir("config");
        let storage = Storage::new(dir.clone());
        let cfg = NodeConfig { listen_port: 9123 };
        storage.save_config(&cfg).unwrap();
        assert_eq!(storage.load_config().unwrap(), cfg);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn history_appends() {
        let dir = temp_dir("history");
        let storage = Storage::new(dir.clone());
        storage
            .append_history(HistoryKind::Sent {
                peer: "12D3KooWX".into(),
                msg_id: 7,
                status: "delivered".into(),
            })
            .unwrap();
        storage
            .append_history(HistoryKind::Received {
                peer: "12D3KooWY".into(),
                msg_id: 8,
            })
            .unwrap();
        let text = fs::read_to_string(dir.join(HISTORY_FILE)).unwrap();
        assert_eq!(text.lines().count(), 2);
        fs::remove_dir_all(&dir).ok();
    }
}
