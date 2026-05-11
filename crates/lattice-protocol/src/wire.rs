//! Prost-encoded wire types.
//!
//! These are the binary wire contracts for MLS framing, sealed sender,
//! identity claims, and membership attribution. The serde types at crate
//! root (`Envelope`, `Recipient`, etc.) wrap these for JSON-friendly
//! transport (HTTP, `.well-known` discovery); the types in this module
//! are for the binary inner content.
//!
//! Field tags are stable — changing a tag is a wire-breaking change that
//! requires bumping `WIRE_VERSION` at the crate root.

use prost::Message;

/// Hybrid identity signature on the wire (Prost form).
///
/// Mirrors `lattice_crypto::identity::HybridSignature` but laid out for
/// stable Protobuf encoding. Convert via `From`/`TryFrom` impls below.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct HybridSignatureWire {
    /// ML-DSA-65 signature (3309 bytes per FIPS 204).
    #[prost(bytes = "vec", tag = "1")]
    pub ml_dsa_sig: Vec<u8>,
    /// Ed25519 signature (64 bytes).
    #[prost(bytes = "vec", tag = "2")]
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
#[derive(Clone, PartialEq, Eq, Message)]
pub struct IdentityClaim {
    /// User UUID v7 (16 bytes).
    #[prost(bytes = "vec", tag = "1")]
    pub user_id: Vec<u8>,
    /// Device UUID v7 (16 bytes).
    #[prost(bytes = "vec", tag = "2")]
    pub device_id: Vec<u8>,
    /// ML-DSA-65 verifying key (1952 bytes).
    #[prost(bytes = "vec", tag = "3")]
    pub ml_dsa_pub: Vec<u8>,
    /// Ed25519 verifying key (32 bytes).
    #[prost(bytes = "vec", tag = "4")]
    pub ed25519_pub: Vec<u8>,
    /// Unix epoch seconds when this claim was issued.
    #[prost(int64, tag = "5")]
    pub issued_at: i64,
    /// Unix epoch seconds after which this claim is no longer valid.
    #[prost(int64, tag = "6")]
    pub valid_until: i64,
    /// Hybrid signature over the canonical encoding of every other field.
    #[prost(message, optional, tag = "7")]
    pub signature: Option<HybridSignatureWire>,
}

/// Server-issued attribution cert for sealed sender (D-05).
///
/// The server signs (group_id, epoch, ephemeral_sender_pubkey, valid_until)
/// with its identity Ed25519 key. Members present the cert when sending
/// sealed envelopes; the routing server verifies the cert + the envelope
/// signature against `ephemeral_sender_pubkey` without learning which
/// group member is sending.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct MembershipCert {
    /// MLS group ID (16 bytes UUID).
    #[prost(bytes = "vec", tag = "1")]
    pub group_id: Vec<u8>,
    /// MLS epoch this cert is valid in.
    #[prost(uint64, tag = "2")]
    pub epoch: u64,
    /// Ed25519 ephemeral sender pubkey (32 bytes). The cert holder signs
    /// outbound sealed envelopes with the matching private key.
    #[prost(bytes = "vec", tag = "3")]
    pub ephemeral_sender_pubkey: Vec<u8>,
    /// Unix epoch seconds when the cert expires.
    #[prost(int64, tag = "4")]
    pub valid_until: i64,
    /// Ed25519 server signature over the canonical encoding of every
    /// other field (64 bytes).
    #[prost(bytes = "vec", tag = "5")]
    pub server_sig: Vec<u8>,
}

/// Sealed-sender envelope (D-05).
///
/// Server sees: group_id, epoch, the cert, and an opaque inner ciphertext.
/// Server validates the cert + the envelope signature, then routes by
/// group_id without learning sender identity. Recipients decrypt the inner
/// ciphertext using their MLS group state.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct SealedEnvelope {
    /// MLS group ID this envelope routes to.
    #[prost(bytes = "vec", tag = "1")]
    pub group_id: Vec<u8>,
    /// MLS epoch. Must match the cert's epoch.
    #[prost(uint64, tag = "2")]
    pub epoch: u64,
    /// Server-issued membership cert authorizing this send.
    #[prost(message, optional, tag = "3")]
    pub membership_cert: Option<MembershipCert>,
    /// Inner MLS application message ciphertext. Opaque to the server.
    #[prost(bytes = "vec", tag = "4")]
    pub inner_ciphertext: Vec<u8>,
    /// Ed25519 signature over `inner_ciphertext`, produced by the private
    /// key matching `membership_cert.ephemeral_sender_pubkey`.
    #[prost(bytes = "vec", tag = "5")]
    pub envelope_sig: Vec<u8>,
}

/// Lattice KeyPackage: an MLS KeyPackage wrapped with the user's hybrid
/// identity claim, so peers can verify both the MLS leaf node and the
/// hybrid identity binding.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct KeyPackage {
    /// User's hybrid identity claim. Must validate before consuming the
    /// MLS KeyPackage.
    #[prost(message, optional, tag = "1")]
    pub identity: Option<IdentityClaim>,
    /// Serialized `mls_rs::MlsMessage` containing the KeyPackage.
    #[prost(bytes = "vec", tag = "2")]
    pub mls_key_package: Vec<u8>,
}

/// MLS Welcome message wrapper.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct Welcome {
    /// Serialized `mls_rs::MlsMessage` containing the Welcome.
    #[prost(bytes = "vec", tag = "1")]
    pub mls_welcome: Vec<u8>,
}

/// MLS Commit message wrapper.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct Commit {
    /// Serialized `mls_rs::MlsMessage` containing the Commit.
    #[prost(bytes = "vec", tag = "1")]
    pub mls_commit: Vec<u8>,
}

/// MLS application message wrapper.
///
/// In sealed-sender flows this lives inside [`SealedEnvelope::inner_ciphertext`].
/// Direct (un-sealed) group sends place this payload at the outer wire
/// level.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct ApplicationMessage {
    /// Serialized `mls_rs::MlsMessage` containing the application data.
    #[prost(bytes = "vec", tag = "1")]
    pub mls_application_message: Vec<u8>,
}

/// Helper: encode a Prost message to bytes.
///
/// Wraps `Message::encode_to_vec` so callers don't need to import the trait.
#[must_use]
pub fn encode<M: Message>(msg: &M) -> Vec<u8> {
    msg.encode_to_vec()
}

/// Helper: decode bytes into a Prost message.
///
/// # Errors
///
/// Returns [`crate::Error::Decode`] if the bytes are not a valid encoding
/// of `M`.
pub fn decode<M: Message + Default>(buf: &[u8]) -> crate::Result<M> {
    M::decode(buf).map_err(|e| crate::Error::Decode(format!("prost decode: {e}")))
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
        let back: lattice_crypto::identity::HybridSignature =
            wire.try_into().expect("try_into");
        assert_eq!(back.ml_dsa_sig, crypto_sig.ml_dsa_sig);
        assert_eq!(back.ed25519_sig, crypto_sig.ed25519_sig);
    }

    #[test]
    fn hybrid_sig_conversion_rejects_short_ed25519() {
        let wire = HybridSignatureWire {
            ml_dsa_sig: vec![0xEE; 3309],
            ed25519_sig: vec![0xFF; 63], // wrong length
        };
        let result: crate::Result<lattice_crypto::identity::HybridSignature> = wire.try_into();
        assert!(matches!(result, Err(crate::Error::Decode(_))));
    }

    #[test]
    fn decoding_garbage_fails() {
        let garbage = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let result: crate::Result<IdentityClaim> = decode(&garbage);
        assert!(result.is_err());
    }
}
