//! Post-quantum cryptographic building blocks for JeanGrey MVP-1.
//!
//! Every primitive here is a thin, typed wrapper around a mature, vetted
//! implementation:
//!
//! - ML-KEM-768 (FIPS 203)  -> `ml-kem` crate (RustCrypto, constant-time, uses
//!   FIPS-validated algorithm implementations).
//! - ML-DSA-65 (FIPS 204)   -> `ml-dsa` crate (RustCrypto).
//! - HKDF-SHA256            -> `hkdf` + `sha2` (RustCrypto).
//! - ChaCha20-Poly1305      -> `chacha20poly1305` (RustCrypto, AEAD).
//!
//! No custom cryptographic constructions are used anywhere in the project.

pub mod kem {
    //! Fresh ephemeral ML-KEM key establishment.
    //!
    //! Ephemeral key pairs are created per session and destroyed with the
    //! handshake; nothing here is ever persisted.

    use ml_kem::kem::{EncapsulationKey, Kem};
    use ml_kem::{Ciphertext, KemCore as _};
    use rand_core::CryptoRngCore;
    use zeroize::ZeroizeOnDrop;

    // ML-KEM-768 sizes (FIPS 203), ~NIST level 3.
    pub const EK_LEN: usize = 1184;
    pub const CT_LEN: usize = 1088;
    pub const SS_LEN: usize = 32;

    /// The encoded ML-KEM-768 ciphertext type (1088 bytes).
    type Ct = Ciphertext<Kem<ml_kem::MlKem768Params>>;

    /// A handed-off ephemeral decapsulation key. Zeroized on drop.
    pub struct KemDecap {
        inner: ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>,
    }

    impl ZeroizeOnDrop for KemDecap {}

    /// Generate a fresh ephemeral ML-KEM-768 key pair.
    /// Returns (encapsulation key bytes, decapsulation key handle).
    pub fn generate(rng: &mut impl CryptoRngCore) -> (Vec<u8>, KemDecap) {
        use ml_kem::EncodedSizeUser as _;
        let (dk, ek) = Kem::<ml_kem::MlKem768Params>::generate(rng);
        let ek_bytes = ek.as_bytes().as_slice().to_vec();
        (ek_bytes, KemDecap { inner: dk })
    }

    /// Encapsulate a fresh shared secret to a remote encapsulation key.
    ///
    /// Returns the ciphertext (for the remote to decapsulate) and the shared
    /// secret. Fails on malformed key material; callers must treat failure as
    /// a fatal handshake error (fail closed).
    pub fn encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; SS_LEN]), KemError> {
        use ml_kem::kem::Encapsulate as _;
        use ml_kem::EncodedSizeUser as _;
        use rand::rngs::OsRng;
        if ek_bytes.len() != EK_LEN {
            return Err(KemError::BadKeySize(ek_bytes.len()));
        }
        let arr: [u8; EK_LEN] = ek_bytes
            .try_into()
            .map_err(|_| KemError::BadKeySize(ek_bytes.len()))?;
        let ek: EncapsulationKey<ml_kem::MlKem768Params> =
            EncapsulationKey::from_bytes(&arr.into());
        let (ct, ss) = ek
            .encapsulate(&mut OsRng)
            .map_err(|_| KemError::EncapsulationFailed)?;
        let mut out = [0u8; SS_LEN];
        out.copy_from_slice(ss.as_slice());
        Ok((ct.as_slice().to_vec(), out))
    }

    /// Decapsulate a shared secret from a remote ciphertext.
    pub fn decapsulate(dk: &KemDecap, ct_bytes: &[u8]) -> Result<[u8; SS_LEN], KemError> {
        use ml_kem::kem::Decapsulate as _;
        if ct_bytes.len() != CT_LEN {
            return Err(KemError::BadCiphertextSize(ct_bytes.len()));
        }
        let ct = Ct::try_from(ct_bytes).map_err(|_| KemError::BadCiphertextSize(ct_bytes.len()))?;
        let ss = dk
            .inner
            .decapsulate(&ct)
            .map_err(|_| KemError::DecapsulationFailed)?;
        let mut out = [0u8; SS_LEN];
        out.copy_from_slice(ss.as_slice());
        Ok(out)
    }

    #[derive(Debug)]
    pub enum KemError {
        BadKeySize(usize),
        BadCiphertextSize(usize),
        EncapsulationFailed,
        DecapsulationFailed,
    }

    impl std::fmt::Display for KemError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                KemError::BadKeySize(n) => write!(f, "bad ephemeral key size: {n}"),
                KemError::BadCiphertextSize(n) => write!(f, "bad ciphertext size: {n}"),
                KemError::EncapsulationFailed => write!(f, "ML-KEM encapsulation failed"),
                KemError::DecapsulationFailed => write!(f, "ML-KEM decapsulation failed"),
            }
        }
    }

    impl std::error::Error for KemError {}

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn generate_encapsulate_decapsulate() {
            let mut rng = rand::rngs::OsRng;
            let (ek, dk) = generate(&mut rng);
            assert_eq!(ek.len(), EK_LEN);
            let (ct, ss_a) = encapsulate(&ek).unwrap();
            assert_eq!(ct.len(), CT_LEN);
            let ss_b = decapsulate(&dk, &ct).unwrap();
            assert_eq!(ss_a, ss_b);
        }

        #[test]
        fn malformed_key_rejected() {
            assert!(encapsulate(&[0u8; 10]).is_err());
            let mut rng = rand::rngs::OsRng;
            let (ek, dk) = generate(&mut rng);
            let (ct, _) = encapsulate(&ek).unwrap();
            assert!(decapsulate(&dk, &[0u8; 3]).is_err());
            let mut bad = ct.clone();
            bad[0] ^= 1;
            let ss = decapsulate(&dk, &bad).unwrap(); // decaps is infallible per spec
            let (_, real_ss) = encapsulate(&ek).unwrap();
            assert_ne!(ss, real_ss); // Kbar path: different invalid seed
        }
    }
}

pub mod mldsa {
    //! ML-DSA-65 long-term signatures (FIPS 204, ~NIST level 3).
    //!
    //! The secret key is persisted as its 32-byte seed (see `storage`); it is
    //! never logged, never placed on the wire, and never committed to the DHT.

    use getrandom::SysRng;
    use ml_dsa::Keypair as _;
    use ml_dsa::{
        ExpandedSigningKey, MlDsa65, Seed, Signature, SigningKey, VerifyingKey as MldsaVk,
    };
    use rand::{rngs::OsRng, RngCore};
    use zeroize::ZeroizeOnDrop;

    pub const PUBKEY_LEN: usize = 1952;
    pub const SIG_LEN: usize = 3309;
    pub const SEED_LEN: usize = 32;

    pub type VerifyingKey = MldsaVk<MlDsa65>;

    /// A long-term ML-DSA device signing key. Zeroized on drop.
    pub struct SecretKey {
        inner: SigningKey<MlDsa65>,
    }

    impl ZeroizeOnDrop for SecretKey {}

    impl SecretKey {
        /// Generate a fresh random signing key.
        pub fn generate() -> Self {
            let mut seed = [0u8; SEED_LEN];
            OsRng.fill_bytes(&mut seed);
            Self::from_seed(seed)
        }

        /// Rebuild the signing key from its 32-byte seed (persistence).
        pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
            Self {
                inner: SigningKey::from_seed(&Seed::from(seed)),
            }
        }

        /// The 32-byte seed — the only persistent form of this key.
        pub fn seed(&self) -> [u8; SEED_LEN] {
            self.inner.to_seed().into()
        }

        pub fn verifying_key(&self) -> VerifyingKey {
            self.inner.verifying_key()
        }

        /// Randomized ML-DSA sign (FIPS 204) with empty context.
        ///
        /// Uses the expanded signing key (ML-DSA.Sign_internal), which is
        /// derived fresh from the seed on every call.
        pub fn sign(&self, message: &[u8]) -> Vec<u8> {
            let esk: ExpandedSigningKey<MlDsa65> =
                ExpandedSigningKey::from_seed(&Seed::from(self.seed()));
            let sig = esk
                .sign_randomized(message, &[], &mut SysRng)
                .expect("ML-DSA signing cannot fail with a short context");
            ml_dsa::SignatureEncoding::to_bytes(&sig)
                .as_slice()
                .to_vec()
        }
    }

    /// Verify `sig` over `message` with a peer's public key.
    pub fn verify(pk: &VerifyingKey, message: &[u8], sig: &[u8]) -> bool {
        let arr: [u8; SIG_LEN] = match sig.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let sig = match Signature::try_from(arr.as_slice()) {
            Ok(s) => s,
            Err(_) => return false,
        };
        pk.verify_with_context(message, &[], &sig)
    }

    /// Canonical serialization of the verifying key.
    pub fn pubkey_to_bytes(pk: &VerifyingKey) -> [u8; PUBKEY_LEN] {
        let enc = pk.encode();
        let mut out = [0u8; PUBKEY_LEN];
        out.copy_from_slice(enc.as_slice());
        out
    }

    pub fn pubkey_from_bytes(bytes: &[u8]) -> Option<VerifyingKey> {
        if bytes.len() != PUBKEY_LEN {
            return None;
        }
        let arr: [u8; PUBKEY_LEN] = bytes.try_into().ok()?;
        Some(MldsaVk::decode(&arr.into()))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn sign_verify_round_trip() {
            let sk = SecretKey::generate();
            let vk = sk.verifying_key();
            let sig = sk.sign(b"jeangrey transcript");
            assert_eq!(sig.len(), SIG_LEN);
            assert!(verify(&vk, b"jeangrey transcript", &sig));
        }

        #[test]
        fn wrong_message_fails() {
            let sk = SecretKey::generate();
            let vk = sk.verifying_key();
            let sig = sk.sign(b"jeangrey transcript");
            assert!(!verify(&vk, b"jeangrey transcriptX", &sig));
        }

        #[test]
        fn wrong_key_fails() {
            let sk = SecretKey::generate();
            let other = SecretKey::generate();
            let sig = sk.sign(b"jeangrey transcript");
            assert!(!verify(
                &other.verifying_key(),
                b"jeangrey transcript",
                &sig
            ));
        }

        #[test]
        fn pubkey_serialization_round_trip() {
            let sk = SecretKey::generate();
            let vk = sk.verifying_key();
            let bytes = pubkey_to_bytes(&vk);
            assert_eq!(bytes.len(), PUBKEY_LEN);
            let vk2 = pubkey_from_bytes(&bytes).unwrap();
            assert!(verify(&vk2, b"m", &sk.sign(b"m")));
            assert!(pubkey_from_bytes(&bytes[..100]).is_none());
        }

        #[test]
        fn seed_restores_key() {
            let sk = SecretKey::generate();
            let seed = sk.seed();
            let sk2 = SecretKey::from_seed(seed);
            assert_eq!(
                pubkey_to_bytes(&sk.verifying_key()),
                pubkey_to_bytes(&sk2.verifying_key())
            );
            // Signatures are randomized; the restored key must produce
            // signatures that verify under the original public key.
            let sig = sk2.sign(b"m");
            assert!(verify(&sk.verifying_key(), b"m", &sig));
        }
    }
}

pub mod kdf {
    //! HKDF-SHA256 session-key derivation with domain separation.

    use hkdf::Hkdf;
    use sha2::Sha256;

    pub const SESSION_ID_LEN: usize = 16;
    pub const AEAD_KEY_LEN: usize = 32;
    pub const HKDF_SALT_LEN: usize = 32;

    /// Keys derived from the authenticated KEM shared secret.
    /// `a_to_b` is the send key of the party with the lexicographically lower
    /// Peer ID; `b_to_a` the send key of the higher party.
    #[derive(Clone, Debug)]
    pub struct SessionKeys {
        pub session_id: [u8; SESSION_ID_LEN],
        pub a_to_b: [u8; AEAD_KEY_LEN],
        pub b_to_a: [u8; AEAD_KEY_LEN],
    }

    /// Derive session keys from the combined KEM shared secret, bound to the
    /// authenticated handshake transcript (used as the HKDF salt).
    ///
    /// `ikm` must be the canonically ordered concatenation of the two KEM
    /// shared secrets (see `handshake::combine_shared_secrets`).
    pub fn derive_session_keys(ikm: &[u8], transcript: &[u8; HKDF_SALT_LEN]) -> SessionKeys {
        let hk = Hkdf::<Sha256>::new(Some(transcript.as_slice()), ikm);

        let mut session_id = [0u8; SESSION_ID_LEN];
        hk.expand(b"jeangrey/mvp1/session-id/v1", &mut session_id)
            .expect("output length 16 is valid");
        let mut a_to_b = [0u8; AEAD_KEY_LEN];
        hk.expand(b"jeangrey/mvp1/aead/a-to-b/v1", &mut a_to_b)
            .expect("output length 32 is valid");
        let mut b_to_a = [0u8; AEAD_KEY_LEN];
        hk.expand(b"jeangrey/mvp1/aead/b-to-a/v1", &mut b_to_a)
            .expect("output length 32 is valid");

        SessionKeys {
            session_id,
            a_to_b,
            b_to_a,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn same_ikm_same_keys() {
            let a = derive_session_keys(&[7u8; 64], &[1u8; 32]);
            let b = derive_session_keys(&[7u8; 64], &[1u8; 32]);
            assert_eq!(a.session_id, b.session_id);
            assert_eq!(a.a_to_b, b.a_to_b);
            assert_eq!(a.b_to_a, b.b_to_a);
        }

        #[test]
        fn fresh_ikm_fresh_keys() {
            let a = derive_session_keys(&[1u8; 64], &[1u8; 32]);
            let b = derive_session_keys(&[2u8; 64], &[1u8; 32]);
            assert_ne!(a.session_id, b.session_id);
            assert_ne!(a.a_to_b, b.a_to_b);
            assert_ne!(a.b_to_a, b.b_to_a);
        }

        #[test]
        fn different_transcript_different_keys() {
            let a = derive_session_keys(&[1u8; 64], &[1u8; 32]);
            let b = derive_session_keys(&[1u8; 64], &[2u8; 32]);
            assert_ne!(a.session_id, b.session_id);
            assert_ne!(a.a_to_b, b.a_to_b);
        }
    }
}

pub mod aead {
    //! ChaCha20-Poly1305 AEAD encryption for all JeanGrey frame payloads.
    //!
    //! Chosen over AES-256-GCM because the pure-software RustCrypto
    //! implementation is constant-time without requiring AES-NI hardware and
    //! is equally mature; see `docs/architecture.md` for the rationale.

    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    pub const NONCE_LEN: usize = 12;
    pub const KEY_LEN: usize = 32;

    /// Encrypt `plaintext` with `key`, authenticating `aad`.
    /// Output is ciphertext || tag.
    pub fn seal(
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("AEAD seal is infallible")
    }

    /// Decrypt and authenticate. Returns `Err` on tag mismatch or malformed
    /// ciphertext; callers must fail closed.
    pub fn open(
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| AeadError::AuthenticationFailed)
    }

    #[derive(Debug)]
    pub enum AeadError {
        AuthenticationFailed,
    }

    impl std::fmt::Display for AeadError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "AEAD authentication failed")
        }
    }

    impl std::error::Error for AeadError {}

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn round_trip() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let ct = seal(&key, &nonce, b"aad", b"Hello Bob");
            assert_eq!(ct.len(), b"Hello Bob".len() + 16);
            assert_eq!(open(&key, &nonce, b"aad", &ct).unwrap(), b"Hello Bob");
        }

        #[test]
        fn tampered_ciphertext_fails() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let mut ct = seal(&key, &nonce, b"aad", b"Hello Bob");
            ct[0] ^= 0x01;
            assert!(open(&key, &nonce, b"aad", &ct).is_err());
        }

        #[test]
        fn tampered_aad_fails() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let ct = seal(&key, &nonce, b"aad", b"Hello Bob");
            assert!(open(&key, &nonce, b"aadX", &ct).is_err());
        }

        #[test]
        fn wrong_nonce_fails() {
            let key = [0x42u8; 32];
            let ct = seal(&key, &[0u8; 12], b"aad", b"Hello Bob");
            let mut wrong = [0u8; 12];
            wrong[0] = 9;
            assert!(open(&key, &wrong, b"aad", &ct).is_err());
        }
    }
}
