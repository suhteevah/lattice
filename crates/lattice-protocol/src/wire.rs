//! Cap'n Proto-backed wire types.
//!
//! These are the binary wire contracts for MLS framing, sealed sender,
//! identity claims, and membership attribution. Each type below is a
//! plain Rust struct; the on-wire encoding is Cap'n Proto packed
//! format, generated from `schema/lattice.capnp`. The serde-derived
//! types at crate root (`Envelope`, `Recipient`, etc.) still wrap
//! these for JSON-friendly HTTP transport; only the binary inner
//! content changed format.
//!
//! ## Why the rewrite (M5, 2026-05-11)
//!
//! Prost was the interim wire format used through M2 / M3 / M4 while
//! the schema stabilized. ROADMAP §M5 called for the swap to Cap'n
//! Proto for zero-copy decode + schema-evolution-friendly fields.
//! `WIRE_VERSION` bumped 2 → 3 with this migration.
//!
//! ## Encode / decode helpers
//!
//! Every wire type implements [`WireType`], whose `encode_capnp` /
//! `decode_capnp` methods do the Cap'n Proto serialization /
//! deserialization. The crate-level [`encode`] / [`decode`] free
//! functions stay as ergonomic shorthand for callsites that don't
//! want to import the trait.

use crate::lattice_capnp;

/// Hybrid identity signature on the wire.
///
/// Mirrors `lattice_crypto::identity::HybridSignature` but laid out
/// for stable Cap'n Proto encoding. Convert via `From`/`TryFrom`
/// impls below.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HybridSignatureWire {
    /// ML-DSA-65 signature (3309 bytes per FIPS 204).
    pub ml_dsa_sig: Vec<u8>,
    /// Ed25519 signature (64 bytes).
    pub ed25519_sig: Vec<u8>,
}

impl From<lattice_crypto::identity::HybridSignature> for HybridSignatureWire {
    fn from(s: lattice_crypto::identity::HybridSignature) -> Self {
        Self {
            ml_dsa_sig: s.ml_dsa_sig,
            ed25519_sig: s.ed25519_sig.to_vec(),
        }
    }
}

impl TryFrom<HybridSignatureWire> for lattice_crypto::identity::HybridSignature {
    type Error = crate::Error;
    fn try_from(w: HybridSignatureWire) -> crate::Result<Self> {
        let ed25519_sig: [u8; 64] = w
            .ed25519_sig
            .as_slice()
            .try_into()
            .map_err(|_| crate::Error::Decode("ed25519 sig wrong length".into()))?;
        Ok(Self {
            ml_dsa_sig: w.ml_dsa_sig,
            ed25519_sig,
        })
    }
}

/// Identity claim published by a user, signed by their hybrid identity key.
///
/// The wire bytes that get signed are this struct encoded with `signature`
/// set to `None`. Verifiers re-encode with `signature: None` to obtain the
/// same byte string and verify the hybrid signature against it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityClaim {
    /// User UUID v7 (16 bytes).
    pub user_id: Vec<u8>,
    /// Device UUID v7 (16 bytes).
    pub device_id: Vec<u8>,
    /// ML-DSA-65 verifying key (1952 bytes).
    pub ml_dsa_pub: Vec<u8>,
    /// Ed25519 verifying key (32 bytes).
    pub ed25519_pub: Vec<u8>,
    /// Unix epoch seconds when this claim was issued.
    pub issued_at: i64,
    /// Unix epoch seconds after which this claim is no longer valid.
    pub valid_until: i64,
    /// Hybrid signature over the canonical encoding of every other field.
    pub signature: Option<HybridSignatureWire>,
}

/// Server-issued attribution cert for sealed sender (D-05).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MembershipCert {
    /// MLS group ID (16 bytes UUID).
    pub group_id: Vec<u8>,
    /// MLS epoch this cert is valid in.
    pub epoch: u64,
    /// Ed25519 ephemeral sender pubkey (32 bytes).
    pub ephemeral_sender_pubkey: Vec<u8>,
    /// Unix epoch seconds when the cert expires.
    pub valid_until: i64,
    /// Ed25519 server signature over the canonical encoding of every
    /// other field (64 bytes).
    pub server_sig: Vec<u8>,
}

/// Sealed-sender envelope (D-05).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SealedEnvelope {
    /// MLS group ID this envelope routes to.
    pub group_id: Vec<u8>,
    /// MLS epoch. Must match the cert's epoch.
    pub epoch: u64,
    /// Server-issued membership cert authorizing this send.
    pub membership_cert: Option<MembershipCert>,
    /// Inner MLS application message ciphertext. Opaque to the server.
    pub inner_ciphertext: Vec<u8>,
    /// Ed25519 signature over `inner_ciphertext`, produced by the private
    /// key matching `membership_cert.ephemeral_sender_pubkey`.
    pub envelope_sig: Vec<u8>,
}

/// Lattice KeyPackage: an MLS KeyPackage wrapped with the user's
/// hybrid identity claim.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyPackage {
    /// User's hybrid identity claim.
    pub identity: Option<IdentityClaim>,
    /// Serialized `mls_rs::MlsMessage` containing the KeyPackage.
    pub mls_key_package: Vec<u8>,
}

/// MLS Welcome message wrapper.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Welcome {
    /// Serialized `mls_rs::MlsMessage` containing the Welcome.
    pub mls_welcome: Vec<u8>,
}

/// MLS Commit message wrapper.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Commit {
    /// Serialized `mls_rs::MlsMessage` containing the Commit.
    pub mls_commit: Vec<u8>,
}

/// MLS application message wrapper.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApplicationMessage {
    /// Serialized `mls_rs::MlsMessage` containing the application data.
    pub mls_application_message: Vec<u8>,
}

/// Trait implemented by every wire type — encode to / decode from a
/// Cap'n Proto packed byte string.
pub trait WireType: Sized {
    /// Encode `self` to a Cap'n Proto packed byte string.
    fn encode_capnp(&self) -> Vec<u8>;
    /// Decode a Cap'n Proto packed byte string back into `Self`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Decode`] on malformed bytes or
    /// schema mismatch.
    fn decode_capnp(bytes: &[u8]) -> crate::Result<Self>;
}

/// Ergonomic free function: encode any [`WireType`] to bytes.
#[must_use]
pub fn encode<M: WireType>(msg: &M) -> Vec<u8> {
    msg.encode_capnp()
}

/// Ergonomic free function: decode bytes into any [`WireType`].
///
/// # Errors
///
/// Returns [`crate::Error::Decode`] on malformed bytes or schema
/// mismatch.
pub fn decode<M: WireType>(buf: &[u8]) -> crate::Result<M> {
    M::decode_capnp(buf)
}

// ===== Encode / decode impls =====

fn write_message(message: &capnp::message::Builder<capnp::message::HeapAllocator>) -> Vec<u8> {
    let mut buf = Vec::new();
    capnp::serialize_packed::write_message(&mut buf, message)
        .expect("capnp write to in-memory Vec is infallible");
    buf
}

fn read_message<'a>(
    buf: &'a [u8],
) -> crate::Result<capnp::message::Reader<capnp::serialize::OwnedSegments>> {
    capnp::serialize_packed::read_message(buf, capnp::message::ReaderOptions::new())
        .map_err(|e| crate::Error::Decode(format!("capnp read: {e}")))
}

impl WireType for HybridSignatureWire {
    fn encode_capnp(&self) -> Vec<u8> {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut root = message.init_root::<lattice_capnp::hybrid_signature_wire::Builder>();
            root.set_ml_dsa_sig(&self.ml_dsa_sig);
            root.set_ed25519_sig(&self.ed25519_sig);
        }
        write_message(&message)
    }
    fn decode_capnp(bytes: &[u8]) -> crate::Result<Self> {
        let reader = read_message(bytes)?;
        let root = reader
            .get_root::<lattice_capnp::hybrid_signature_wire::Reader>()
            .map_err(|e| crate::Error::Decode(format!("hybrid sig root: {e}")))?;
        Ok(Self {
            ml_dsa_sig: root
                .get_ml_dsa_sig()
                .map_err(|e| crate::Error::Decode(format!("ml_dsa_sig: {e}")))?
                .to_vec(),
            ed25519_sig: root
                .get_ed25519_sig()
                .map_err(|e| crate::Error::Decode(format!("ed25519_sig: {e}")))?
                .to_vec(),
        })
    }
}

fn build_identity_claim(
    src: &IdentityClaim,
    mut builder: lattice_capnp::identity_claim::Builder,
) {
    builder.set_user_id(&src.user_id);
    builder.set_device_id(&src.device_id);
    builder.set_ml_dsa_pub(&src.ml_dsa_pub);
    builder.set_ed25519_pub(&src.ed25519_pub);
    builder.set_issued_at(src.issued_at);
    builder.set_valid_until(src.valid_until);
    let mut sig_b = builder.init_signature();
    match &src.signature {
        None => {
            sig_b.set_none(());
        }
        Some(sig) => {
            let mut present = sig_b.init_present();
            present.set_ml_dsa_sig(&sig.ml_dsa_sig);
            present.set_ed25519_sig(&sig.ed25519_sig);
        }
    }
}

fn read_identity_claim(
    r: lattice_capnp::identity_claim::Reader,
) -> crate::Result<IdentityClaim> {
    use lattice_capnp::identity_claim::signature::Which as SigWhich;
    let user_id = r
        .get_user_id()
        .map_err(|e| crate::Error::Decode(format!("user_id: {e}")))?
        .to_vec();
    let device_id = r
        .get_device_id()
        .map_err(|e| crate::Error::Decode(format!("device_id: {e}")))?
        .to_vec();
    let ml_dsa_pub = r
        .get_ml_dsa_pub()
        .map_err(|e| crate::Error::Decode(format!("ml_dsa_pub: {e}")))?
        .to_vec();
    let ed25519_pub = r
        .get_ed25519_pub()
        .map_err(|e| crate::Error::Decode(format!("ed25519_pub: {e}")))?
        .to_vec();
    let signature = match r
        .get_signature()
        .which()
        .map_err(|e| crate::Error::Decode(format!("signature union: {e}")))?
    {
        SigWhich::None(()) => None,
        SigWhich::Present(p) => {
            let p = p.map_err(|e| crate::Error::Decode(format!("signature present: {e}")))?;
            Some(HybridSignatureWire {
                ml_dsa_sig: p
                    .get_ml_dsa_sig()
                    .map_err(|e| crate::Error::Decode(format!("present ml_dsa: {e}")))?
                    .to_vec(),
                ed25519_sig: p
                    .get_ed25519_sig()
                    .map_err(|e| crate::Error::Decode(format!("present ed25519: {e}")))?
                    .to_vec(),
            })
        }
    };
    Ok(IdentityClaim {
        user_id,
        device_id,
        ml_dsa_pub,
        ed25519_pub,
        issued_at: r.get_issued_at(),
        valid_until: r.get_valid_until(),
        signature,
    })
}

impl WireType for IdentityClaim {
    fn encode_capnp(&self) -> Vec<u8> {
        let mut message = capnp::message::Builder::new_default();
        {
            let root = message.init_root::<lattice_capnp::identity_claim::Builder>();
            build_identity_claim(self, root);
        }
        write_message(&message)
    }
    fn decode_capnp(bytes: &[u8]) -> crate::Result<Self> {
        let reader = read_message(bytes)?;
        let root = reader
            .get_root::<lattice_capnp::identity_claim::Reader>()
            .map_err(|e| crate::Error::Decode(format!("identity_claim root: {e}")))?;
        read_identity_claim(root)
    }
}

fn build_cert(src: &MembershipCert, mut builder: lattice_capnp::membership_cert::Builder) {
    builder.set_group_id(&src.group_id);
    builder.set_epoch(src.epoch);
    builder.set_ephemeral_sender_pubkey(&src.ephemeral_sender_pubkey);
    builder.set_valid_until(src.valid_until);
    builder.set_server_sig(&src.server_sig);
}

fn read_cert(r: lattice_capnp::membership_cert::Reader) -> crate::Result<MembershipCert> {
    Ok(MembershipCert {
        group_id: r
            .get_group_id()
            .map_err(|e| crate::Error::Decode(format!("group_id: {e}")))?
            .to_vec(),
        epoch: r.get_epoch(),
        ephemeral_sender_pubkey: r
            .get_ephemeral_sender_pubkey()
            .map_err(|e| crate::Error::Decode(format!("ephemeral_sender_pubkey: {e}")))?
            .to_vec(),
        valid_until: r.get_valid_until(),
        server_sig: r
            .get_server_sig()
            .map_err(|e| crate::Error::Decode(format!("server_sig: {e}")))?
            .to_vec(),
    })
}

impl WireType for MembershipCert {
    fn encode_capnp(&self) -> Vec<u8> {
        let mut message = capnp::message::Builder::new_default();
        {
            let root = message.init_root::<lattice_capnp::membership_cert::Builder>();
            build_cert(self, root);
        }
        write_message(&message)
    }
    fn decode_capnp(bytes: &[u8]) -> crate::Result<Self> {
        let reader = read_message(bytes)?;
        let root = reader
            .get_root::<lattice_capnp::membership_cert::Reader>()
            .map_err(|e| crate::Error::Decode(format!("membership_cert root: {e}")))?;
        read_cert(root)
    }
}

impl WireType for SealedEnvelope {
    fn encode_capnp(&self) -> Vec<u8> {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut root = message.init_root::<lattice_capnp::sealed_envelope::Builder>();
            root.set_group_id(&self.group_id);
            root.set_epoch(self.epoch);
            root.set_inner_ciphertext(&self.inner_ciphertext);
            root.set_envelope_sig(&self.envelope_sig);
            let mut cert_b = root.reborrow().init_membership_cert();
            match &self.membership_cert {
                None => {
                    cert_b.set_none(());
                }
                Some(cert) => {
                    build_cert(cert, cert_b.init_present());
                }
            }
        }
        write_message(&message)
    }
    fn decode_capnp(bytes: &[u8]) -> crate::Result<Self> {
        use lattice_capnp::sealed_envelope::membership_cert::Which as CertWhich;
        let reader = read_message(bytes)?;
        let root = reader
            .get_root::<lattice_capnp::sealed_envelope::Reader>()
            .map_err(|e| crate::Error::Decode(format!("sealed_envelope root: {e}")))?;
        let cert = match root
            .get_membership_cert()
            .which()
            .map_err(|e| crate::Error::Decode(format!("cert union: {e}")))?
        {
            CertWhich::None(()) => None,
            CertWhich::Present(p) => {
                let p = p.map_err(|e| crate::Error::Decode(format!("cert present: {e}")))?;
                Some(read_cert(p)?)
            }
        };
        Ok(SealedEnvelope {
            group_id: root
                .get_group_id()
                .map_err(|e| crate::Error::Decode(format!("group_id: {e}")))?
                .to_vec(),
            epoch: root.get_epoch(),
            membership_cert: cert,
            inner_ciphertext: root
                .get_inner_ciphertext()
                .map_err(|e| crate::Error::Decode(format!("inner_ciphertext: {e}")))?
                .to_vec(),
            envelope_sig: root
                .get_envelope_sig()
                .map_err(|e| crate::Error::Decode(format!("envelope_sig: {e}")))?
                .to_vec(),
        })
    }
}

impl WireType for KeyPackage {
    fn encode_capnp(&self) -> Vec<u8> {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut root = message.init_root::<lattice_capnp::key_package::Builder>();
            root.set_mls_key_package(&self.mls_key_package);
            let mut id_b = root.reborrow().init_identity();
            match &self.identity {
                None => {
                    id_b.set_none(());
                }
                Some(claim) => {
                    build_identity_claim(claim, id_b.init_present());
                }
            }
        }
        write_message(&message)
    }
    fn decode_capnp(bytes: &[u8]) -> crate::Result<Self> {
        use lattice_capnp::key_package::identity::Which as IdWhich;
        let reader = read_message(bytes)?;
        let root = reader
            .get_root::<lattice_capnp::key_package::Reader>()
            .map_err(|e| crate::Error::Decode(format!("key_package root: {e}")))?;
        let identity = match root
            .get_identity()
            .which()
            .map_err(|e| crate::Error::Decode(format!("identity union: {e}")))?
        {
            IdWhich::None(()) => None,
            IdWhich::Present(p) => {
                let p =
                    p.map_err(|e| crate::Error::Decode(format!("identity present: {e}")))?;
                Some(read_identity_claim(p)?)
            }
        };
        Ok(KeyPackage {
            identity,
            mls_key_package: root
                .get_mls_key_package()
                .map_err(|e| crate::Error::Decode(format!("mls_key_package: {e}")))?
                .to_vec(),
        })
    }
}

impl WireType for Welcome {
    fn encode_capnp(&self) -> Vec<u8> {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut root = message.init_root::<lattice_capnp::welcome::Builder>();
            root.set_mls_welcome(&self.mls_welcome);
        }
        write_message(&message)
    }
    fn decode_capnp(bytes: &[u8]) -> crate::Result<Self> {
        let reader = read_message(bytes)?;
        let root = reader
            .get_root::<lattice_capnp::welcome::Reader>()
            .map_err(|e| crate::Error::Decode(format!("welcome root: {e}")))?;
        Ok(Welcome {
            mls_welcome: root
                .get_mls_welcome()
                .map_err(|e| crate::Error::Decode(format!("mls_welcome: {e}")))?
                .to_vec(),
        })
    }
}

impl WireType for Commit {
    fn encode_capnp(&self) -> Vec<u8> {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut root = message.init_root::<lattice_capnp::commit::Builder>();
            root.set_mls_commit(&self.mls_commit);
        }
        write_message(&message)
    }
    fn decode_capnp(bytes: &[u8]) -> crate::Result<Self> {
        let reader = read_message(bytes)?;
        let root = reader
            .get_root::<lattice_capnp::commit::Reader>()
            .map_err(|e| crate::Error::Decode(format!("commit root: {e}")))?;
        Ok(Commit {
            mls_commit: root
                .get_mls_commit()
                .map_err(|e| crate::Error::Decode(format!("mls_commit: {e}")))?
                .to_vec(),
        })
    }
}

impl WireType for ApplicationMessage {
    fn encode_capnp(&self) -> Vec<u8> {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut root = message.init_root::<lattice_capnp::application_message::Builder>();
            root.set_mls_application_message(&self.mls_application_message);
        }
        write_message(&message)
    }
    fn decode_capnp(bytes: &[u8]) -> crate::Result<Self> {
        let reader = read_message(bytes)?;
        let root = reader
            .get_root::<lattice_capnp::application_message::Reader>()
            .map_err(|e| crate::Error::Decode(format!("application_message root: {e}")))?;
        Ok(ApplicationMessage {
            mls_application_message: root
                .get_mls_application_message()
                .map_err(|e| crate::Error::Decode(format!("mls_application_message: {e}")))?
                .to_vec(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_hybrid_sig() -> HybridSignatureWire {
        HybridSignatureWire {
            ml_dsa_sig: vec![0xAA; 3309],
            ed25519_sig: vec![0xBB; 64],
        }
    }

    #[test]
    fn hybrid_sig_round_trip() {
        let original = sample_hybrid_sig();
        let bytes = encode(&original);
        let decoded: HybridSignatureWire = decode(&bytes).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn identity_claim_round_trip() {
        let claim = IdentityClaim {
            user_id: vec![1; 16],
            device_id: vec![2; 16],
            ml_dsa_pub: vec![3; 1952],
            ed25519_pub: vec![4; 32],
            issued_at: 1_700_000_000,
            valid_until: 1_700_086_400,
            signature: Some(sample_hybrid_sig()),
        };
        let bytes = encode(&claim);
        let decoded: IdentityClaim = decode(&bytes).expect("decode");
        assert_eq!(decoded, claim);
    }

    #[test]
    fn identity_claim_no_sig_round_trip() {
        let claim = IdentityClaim {
            user_id: vec![1; 16],
            device_id: vec![2; 16],
            ml_dsa_pub: vec![3; 1952],
            ed25519_pub: vec![4; 32],
            issued_at: 1,
            valid_until: 2,
            signature: None,
        };
        let bytes = encode(&claim);
        let decoded: IdentityClaim = decode(&bytes).expect("decode");
        assert_eq!(decoded, claim);
    }

    #[test]
    fn membership_cert_round_trip() {
        let cert = MembershipCert {
            group_id: vec![5; 16],
            epoch: 42,
            ephemeral_sender_pubkey: vec![6; 32],
            valid_until: 1_700_000_000,
            server_sig: vec![7; 64],
        };
        let bytes = encode(&cert);
        let decoded: MembershipCert = decode(&bytes).expect("decode");
        assert_eq!(decoded, cert);
    }

    #[test]
    fn sealed_envelope_round_trip() {
        let env = SealedEnvelope {
            group_id: vec![8; 16],
            epoch: 7,
            membership_cert: Some(MembershipCert {
                group_id: vec![8; 16],
                epoch: 7,
                ephemeral_sender_pubkey: vec![9; 32],
                valid_until: 1_700_000_000,
                server_sig: vec![10; 64],
            }),
            inner_ciphertext: b"opaque ciphertext payload".to_vec(),
            envelope_sig: vec![11; 64],
        };
        let bytes = encode(&env);
        let decoded: SealedEnvelope = decode(&bytes).expect("decode");
        assert_eq!(decoded, env);
    }

    #[test]
    fn key_package_round_trip() {
        let kp = KeyPackage {
            identity: Some(IdentityClaim {
                user_id: vec![1; 16],
                device_id: vec![2; 16],
                ml_dsa_pub: vec![3; 1952],
                ed25519_pub: vec![4; 32],
                issued_at: 1,
                valid_until: 2,
                signature: Some(sample_hybrid_sig()),
            }),
            mls_key_package: b"mls bytes here".to_vec(),
        };
        let bytes = encode(&kp);
        let decoded: KeyPackage = decode(&bytes).expect("decode");
        assert_eq!(decoded, kp);
    }

    #[test]
    fn welcome_round_trip() {
        let w = Welcome {
            mls_welcome: b"welcome bytes".to_vec(),
        };
        let bytes = encode(&w);
        let decoded: Welcome = decode(&bytes).expect("decode");
        assert_eq!(decoded, w);
    }

    #[test]
    fn commit_round_trip() {
        let c = Commit {
            mls_commit: b"commit bytes".to_vec(),
        };
        let bytes = encode(&c);
        let decoded: Commit = decode(&bytes).expect("decode");
        assert_eq!(decoded, c);
    }

    #[test]
    fn application_message_round_trip() {
        let am = ApplicationMessage {
            mls_application_message: b"mls app msg ciphertext".to_vec(),
        };
        let bytes = encode(&am);
        let decoded: ApplicationMessage = decode(&bytes).expect("decode");
        assert_eq!(decoded, am);
    }

    #[test]
    fn hybrid_sig_conversion_round_trip() {
        let crypto_sig = lattice_crypto::identity::HybridSignature {
            ml_dsa_sig: vec![0xCC; 3309],
            ed25519_sig: [0xDD; 64],
        };
        let wire: HybridSignatureWire = crypto_sig.clone().into();
        let back: lattice_crypto::identity::HybridSignature = wire.try_into().expect("try_into");
        assert_eq!(back.ml_dsa_sig, crypto_sig.ml_dsa_sig);
        assert_eq!(back.ed25519_sig, crypto_sig.ed25519_sig);
    }

    #[test]
    fn hybrid_sig_conversion_rejects_short_ed25519() {
        let wire = HybridSignatureWire {
            ml_dsa_sig: vec![0xEE; 3309],
            ed25519_sig: vec![0xFF; 63],
        };
        let result: crate::Result<lattice_crypto::identity::HybridSignature> = wire.try_into();
        assert!(matches!(result, Err(crate::Error::Decode(_))));
    }

    #[test]
    fn decode_rejects_garbage() {
        let result: crate::Result<IdentityClaim> = decode(b"not capnp");
        assert!(matches!(result, Err(crate::Error::Decode(_))));
    }
}
