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

// ===== M7 voice/video call signaling =====
//
// These types are the *plaintext payload* the application encodes
// before handing to MLS for encryption. The server only ever sees
// the MLS-encrypted `ApplicationMessage.mls_application_message`
// bytes that wrap them.

/// One ICE candidate line, opaque to Lattice. RFC 8839 SDP format.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallIceCandidateLine {
    /// SDP-format ICE candidate line.
    pub sdp_line: String,
    /// Which m-line this candidate applies to (0 = audio, 1 = video).
    pub sdp_mline_index: u32,
}

/// Caller's invite. Carries the ML-KEM-768 encapsulation key + the
/// caller's local ICE candidates. Signed by caller's Ed25519
/// identity key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallInvite {
    /// Per-call random identifier (16 bytes).
    pub call_id: Vec<u8>,
    /// ML-KEM-768 encapsulation key, 1184 bytes.
    pub pq_encapsulation_key: Vec<u8>,
    /// Local ICE candidates known at invite time. Additional
    /// candidates are trickled via `CallIceCandidate`.
    pub ice_candidates: Vec<CallIceCandidateLine>,
    /// Ed25519 signature over the canonical transcript bytes, 64
    /// bytes. Transcript covers `CALL_INVITE_TRANSCRIPT_PREFIX ||
    /// call_id || pq_encapsulation_key || ice_candidates`.
    pub sig: Vec<u8>,
}

/// Callee's accept. Carries the ML-KEM-768 ciphertext (which the
/// caller decapsulates to recover the shared PQ secret) + the
/// callee's local ICE candidates. Signed by callee's Ed25519
/// identity key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallAccept {
    /// Echoed from the corresponding `CallInvite`.
    pub call_id: Vec<u8>,
    /// ML-KEM-768 ciphertext, 1088 bytes.
    pub pq_ciphertext: Vec<u8>,
    /// Callee's local ICE candidates known at accept time.
    pub ice_candidates: Vec<CallIceCandidateLine>,
    /// Ed25519 signature, 64 bytes.
    pub sig: Vec<u8>,
}

/// A single trickled ICE candidate sent after the invite/accept
/// exchange. Either party may send these during the connection-
/// checks phase. Signed by sender's Ed25519 identity key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallIceCandidate {
    /// Echoed from the active call's `CallInvite`.
    pub call_id: Vec<u8>,
    /// The candidate line being trickled.
    pub candidate: CallIceCandidateLine,
    /// Ed25519 signature, 64 bytes.
    pub sig: Vec<u8>,
}

/// Reason a call ended. Mirrors `lattice_media::call::EndReason`
/// — the wire integer is the discriminant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CallEndReason {
    /// Remote side hung up.
    #[default]
    RemoteHangup,
    /// Local side hung up.
    LocalHangup,
    /// Remote declined the invite.
    Declined,
    /// ICE candidate pair could not connect.
    IceFailed,
    /// DTLS handshake failed.
    DtlsFailed,
    /// PQ KEM encap or decap failed.
    PqKexFailed,
}

/// Sent by either party to end a call.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallEnd {
    /// Echoed from the active call's `CallInvite`.
    pub call_id: Vec<u8>,
    /// Why the call ended.
    pub reason: CallEndReason,
    /// Ed25519 signature, 64 bytes.
    pub sig: Vec<u8>,
}

/// One in-call signaling message. The application encodes a
/// `CallSignal` as the plaintext payload of an MLS application
/// message. Decoders dispatch on the variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallSignal {
    /// Caller's initial invite.
    Invite(CallInvite),
    /// Callee's accept.
    Accept(CallAccept),
    /// Trickled ICE candidate.
    IceCandidate(CallIceCandidate),
    /// Call ended.
    End(CallEnd),
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

// ===== M7 call signaling impls =====

fn build_ice_candidate_line(
    src: &CallIceCandidateLine,
    mut b: lattice_capnp::call_ice_candidate_line::Builder,
) {
    b.set_sdp_line(&src.sdp_line);
    b.set_sdp_mline_index(src.sdp_mline_index);
}

fn read_ice_candidate_line(
    r: lattice_capnp::call_ice_candidate_line::Reader,
) -> crate::Result<CallIceCandidateLine> {
    Ok(CallIceCandidateLine {
        sdp_line: r
            .get_sdp_line()
            .map_err(|e| crate::Error::Decode(format!("sdp_line: {e}")))?
            .to_str()
            .map_err(|e| crate::Error::Decode(format!("sdp_line utf8: {e}")))?
            .to_string(),
        sdp_mline_index: r.get_sdp_mline_index(),
    })
}

#[allow(clippy::cast_possible_truncation)] // candidate counts well under u32::MAX
fn build_ice_candidate_list(
    src: &[CallIceCandidateLine],
    mut builder: capnp::struct_list::Builder<'_, lattice_capnp::call_ice_candidate_line::Owned>,
) {
    for (i, c) in src.iter().enumerate() {
        let slot = builder.reborrow().get(i as u32);
        build_ice_candidate_line(c, slot);
    }
}

fn read_ice_candidate_list(
    list: capnp::struct_list::Reader<'_, lattice_capnp::call_ice_candidate_line::Owned>,
) -> crate::Result<Vec<CallIceCandidateLine>> {
    let mut out = Vec::with_capacity(list.len() as usize);
    for r in list {
        out.push(read_ice_candidate_line(r)?);
    }
    Ok(out)
}

impl WireType for CallIceCandidateLine {
    fn encode_capnp(&self) -> Vec<u8> {
        let mut message = capnp::message::Builder::new_default();
        {
            let root = message.init_root::<lattice_capnp::call_ice_candidate_line::Builder>();
            build_ice_candidate_line(self, root);
        }
        write_message(&message)
    }
    fn decode_capnp(bytes: &[u8]) -> crate::Result<Self> {
        let reader = read_message(bytes)?;
        let root = reader
            .get_root::<lattice_capnp::call_ice_candidate_line::Reader>()
            .map_err(|e| crate::Error::Decode(format!("call_ice_candidate_line root: {e}")))?;
        read_ice_candidate_line(root)
    }
}

impl WireType for CallInvite {
    #[allow(clippy::cast_possible_truncation)]
    fn encode_capnp(&self) -> Vec<u8> {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut root = message.init_root::<lattice_capnp::call_invite::Builder>();
            root.set_call_id(&self.call_id);
            root.set_pq_encapsulation_key(&self.pq_encapsulation_key);
            root.set_sig(&self.sig);
            let candidates = root
                .reborrow()
                .init_ice_candidates(self.ice_candidates.len() as u32);
            build_ice_candidate_list(&self.ice_candidates, candidates);
        }
        write_message(&message)
    }
    fn decode_capnp(bytes: &[u8]) -> crate::Result<Self> {
        let reader = read_message(bytes)?;
        let r = reader
            .get_root::<lattice_capnp::call_invite::Reader>()
            .map_err(|e| crate::Error::Decode(format!("call_invite root: {e}")))?;
        Ok(Self {
            call_id: r
                .get_call_id()
                .map_err(|e| crate::Error::Decode(format!("call_id: {e}")))?
                .to_vec(),
            pq_encapsulation_key: r
                .get_pq_encapsulation_key()
                .map_err(|e| crate::Error::Decode(format!("pq_encapsulation_key: {e}")))?
                .to_vec(),
            ice_candidates: read_ice_candidate_list(
                r.get_ice_candidates()
                    .map_err(|e| crate::Error::Decode(format!("ice_candidates: {e}")))?,
            )?,
            sig: r
                .get_sig()
                .map_err(|e| crate::Error::Decode(format!("sig: {e}")))?
                .to_vec(),
        })
    }
}

impl WireType for CallAccept {
    #[allow(clippy::cast_possible_truncation)]
    fn encode_capnp(&self) -> Vec<u8> {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut root = message.init_root::<lattice_capnp::call_accept::Builder>();
            root.set_call_id(&self.call_id);
            root.set_pq_ciphertext(&self.pq_ciphertext);
            root.set_sig(&self.sig);
            let candidates = root
                .reborrow()
                .init_ice_candidates(self.ice_candidates.len() as u32);
            build_ice_candidate_list(&self.ice_candidates, candidates);
        }
        write_message(&message)
    }
    fn decode_capnp(bytes: &[u8]) -> crate::Result<Self> {
        let reader = read_message(bytes)?;
        let r = reader
            .get_root::<lattice_capnp::call_accept::Reader>()
            .map_err(|e| crate::Error::Decode(format!("call_accept root: {e}")))?;
        Ok(Self {
            call_id: r
                .get_call_id()
                .map_err(|e| crate::Error::Decode(format!("call_id: {e}")))?
                .to_vec(),
            pq_ciphertext: r
                .get_pq_ciphertext()
                .map_err(|e| crate::Error::Decode(format!("pq_ciphertext: {e}")))?
                .to_vec(),
            ice_candidates: read_ice_candidate_list(
                r.get_ice_candidates()
                    .map_err(|e| crate::Error::Decode(format!("ice_candidates: {e}")))?,
            )?,
            sig: r
                .get_sig()
                .map_err(|e| crate::Error::Decode(format!("sig: {e}")))?
                .to_vec(),
        })
    }
}

impl WireType for CallIceCandidate {
    fn encode_capnp(&self) -> Vec<u8> {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut root = message.init_root::<lattice_capnp::call_ice_candidate::Builder>();
            root.set_call_id(&self.call_id);
            root.set_sig(&self.sig);
            build_ice_candidate_line(&self.candidate, root.reborrow().init_candidate());
        }
        write_message(&message)
    }
    fn decode_capnp(bytes: &[u8]) -> crate::Result<Self> {
        let reader = read_message(bytes)?;
        let r = reader
            .get_root::<lattice_capnp::call_ice_candidate::Reader>()
            .map_err(|e| crate::Error::Decode(format!("call_ice_candidate root: {e}")))?;
        Ok(Self {
            call_id: r
                .get_call_id()
                .map_err(|e| crate::Error::Decode(format!("call_id: {e}")))?
                .to_vec(),
            candidate: read_ice_candidate_line(
                r.get_candidate()
                    .map_err(|e| crate::Error::Decode(format!("candidate: {e}")))?,
            )?,
            sig: r
                .get_sig()
                .map_err(|e| crate::Error::Decode(format!("sig: {e}")))?
                .to_vec(),
        })
    }
}

impl From<CallEndReason> for lattice_capnp::CallEndReason {
    fn from(r: CallEndReason) -> Self {
        match r {
            CallEndReason::RemoteHangup => Self::RemoteHangup,
            CallEndReason::LocalHangup => Self::LocalHangup,
            CallEndReason::Declined => Self::Declined,
            CallEndReason::IceFailed => Self::IceFailed,
            CallEndReason::DtlsFailed => Self::DtlsFailed,
            CallEndReason::PqKexFailed => Self::PqKexFailed,
        }
    }
}

impl From<lattice_capnp::CallEndReason> for CallEndReason {
    fn from(r: lattice_capnp::CallEndReason) -> Self {
        match r {
            lattice_capnp::CallEndReason::RemoteHangup => Self::RemoteHangup,
            lattice_capnp::CallEndReason::LocalHangup => Self::LocalHangup,
            lattice_capnp::CallEndReason::Declined => Self::Declined,
            lattice_capnp::CallEndReason::IceFailed => Self::IceFailed,
            lattice_capnp::CallEndReason::DtlsFailed => Self::DtlsFailed,
            lattice_capnp::CallEndReason::PqKexFailed => Self::PqKexFailed,
        }
    }
}

impl WireType for CallEnd {
    fn encode_capnp(&self) -> Vec<u8> {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut root = message.init_root::<lattice_capnp::call_end::Builder>();
            root.set_call_id(&self.call_id);
            root.set_reason(self.reason.into());
            root.set_sig(&self.sig);
        }
        write_message(&message)
    }
    fn decode_capnp(bytes: &[u8]) -> crate::Result<Self> {
        let reader = read_message(bytes)?;
        let r = reader
            .get_root::<lattice_capnp::call_end::Reader>()
            .map_err(|e| crate::Error::Decode(format!("call_end root: {e}")))?;
        Ok(Self {
            call_id: r
                .get_call_id()
                .map_err(|e| crate::Error::Decode(format!("call_id: {e}")))?
                .to_vec(),
            reason: r
                .get_reason()
                .map_err(|e| crate::Error::Decode(format!("reason: {e}")))?
                .into(),
            sig: r
                .get_sig()
                .map_err(|e| crate::Error::Decode(format!("sig: {e}")))?
                .to_vec(),
        })
    }
}

impl WireType for CallSignal {
    fn encode_capnp(&self) -> Vec<u8> {
        let mut message = capnp::message::Builder::new_default();
        {
            let root = message.init_root::<lattice_capnp::call_signal::Builder>();
            let body = root.init_body();
            match self {
                Self::Invite(inv) => {
                    let mut b = body.init_invite();
                    b.set_call_id(&inv.call_id);
                    b.set_pq_encapsulation_key(&inv.pq_encapsulation_key);
                    b.set_sig(&inv.sig);
                    #[allow(clippy::cast_possible_truncation)]
                    let candidates = b.reborrow().init_ice_candidates(inv.ice_candidates.len() as u32);
                    build_ice_candidate_list(&inv.ice_candidates, candidates);
                }
                Self::Accept(acc) => {
                    let mut b = body.init_accept();
                    b.set_call_id(&acc.call_id);
                    b.set_pq_ciphertext(&acc.pq_ciphertext);
                    b.set_sig(&acc.sig);
                    #[allow(clippy::cast_possible_truncation)]
                    let candidates = b.reborrow().init_ice_candidates(acc.ice_candidates.len() as u32);
                    build_ice_candidate_list(&acc.ice_candidates, candidates);
                }
                Self::IceCandidate(ic) => {
                    let mut b = body.init_ice_candidate();
                    b.set_call_id(&ic.call_id);
                    b.set_sig(&ic.sig);
                    build_ice_candidate_line(&ic.candidate, b.reborrow().init_candidate());
                }
                Self::End(e) => {
                    let mut b = body.init_end_call();
                    b.set_call_id(&e.call_id);
                    b.set_reason(e.reason.into());
                    b.set_sig(&e.sig);
                }
            }
        }
        write_message(&message)
    }
    fn decode_capnp(bytes: &[u8]) -> crate::Result<Self> {
        use lattice_capnp::call_signal::body::Which as BodyWhich;

        let reader = read_message(bytes)?;
        let r = reader
            .get_root::<lattice_capnp::call_signal::Reader>()
            .map_err(|e| crate::Error::Decode(format!("call_signal root: {e}")))?;
        let body = r.get_body();
        match body
            .which()
            .map_err(|e| crate::Error::Decode(format!("call_signal body union: {e}")))?
        {
            BodyWhich::Invite(b) => {
                let b = b.map_err(|e| crate::Error::Decode(format!("invite body: {e}")))?;
                Ok(Self::Invite(CallInvite {
                    call_id: b
                        .get_call_id()
                        .map_err(|e| crate::Error::Decode(format!("call_id: {e}")))?
                        .to_vec(),
                    pq_encapsulation_key: b
                        .get_pq_encapsulation_key()
                        .map_err(|e| crate::Error::Decode(format!("pq_encapsulation_key: {e}")))?
                        .to_vec(),
                    ice_candidates: read_ice_candidate_list(
                        b.get_ice_candidates()
                            .map_err(|e| crate::Error::Decode(format!("ice_candidates: {e}")))?,
                    )?,
                    sig: b
                        .get_sig()
                        .map_err(|e| crate::Error::Decode(format!("sig: {e}")))?
                        .to_vec(),
                }))
            }
            BodyWhich::Accept(b) => {
                let b = b.map_err(|e| crate::Error::Decode(format!("accept body: {e}")))?;
                Ok(Self::Accept(CallAccept {
                    call_id: b
                        .get_call_id()
                        .map_err(|e| crate::Error::Decode(format!("call_id: {e}")))?
                        .to_vec(),
                    pq_ciphertext: b
                        .get_pq_ciphertext()
                        .map_err(|e| crate::Error::Decode(format!("pq_ciphertext: {e}")))?
                        .to_vec(),
                    ice_candidates: read_ice_candidate_list(
                        b.get_ice_candidates()
                            .map_err(|e| crate::Error::Decode(format!("ice_candidates: {e}")))?,
                    )?,
                    sig: b
                        .get_sig()
                        .map_err(|e| crate::Error::Decode(format!("sig: {e}")))?
                        .to_vec(),
                }))
            }
            BodyWhich::IceCandidate(b) => {
                let b = b.map_err(|e| crate::Error::Decode(format!("ice_candidate body: {e}")))?;
                Ok(Self::IceCandidate(CallIceCandidate {
                    call_id: b
                        .get_call_id()
                        .map_err(|e| crate::Error::Decode(format!("call_id: {e}")))?
                        .to_vec(),
                    candidate: read_ice_candidate_line(
                        b.get_candidate()
                            .map_err(|e| crate::Error::Decode(format!("candidate: {e}")))?,
                    )?,
                    sig: b
                        .get_sig()
                        .map_err(|e| crate::Error::Decode(format!("sig: {e}")))?
                        .to_vec(),
                }))
            }
            BodyWhich::EndCall(b) => {
                let b = b.map_err(|e| crate::Error::Decode(format!("end_call body: {e}")))?;
                Ok(Self::End(CallEnd {
                    call_id: b
                        .get_call_id()
                        .map_err(|e| crate::Error::Decode(format!("call_id: {e}")))?
                        .to_vec(),
                    reason: b
                        .get_reason()
                        .map_err(|e| crate::Error::Decode(format!("reason: {e}")))?
                        .into(),
                    sig: b
                        .get_sig()
                        .map_err(|e| crate::Error::Decode(format!("sig: {e}")))?
                        .to_vec(),
                }))
            }
        }
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

    // ===== M7 call signaling round-trip tests =====

    fn sample_ice_candidate(index: u32, body: &str) -> CallIceCandidateLine {
        CallIceCandidateLine {
            sdp_line: format!("candidate:foundation 1 udp 12345 192.0.2.1 12345 typ host {body}"),
            sdp_mline_index: index,
        }
    }

    #[test]
    fn call_invite_round_trip() {
        let inv = CallInvite {
            call_id: vec![0xc1; 16],
            pq_encapsulation_key: vec![0xc2; 1184],
            ice_candidates: vec![sample_ice_candidate(0, "a"), sample_ice_candidate(1, "b")],
            sig: vec![0xc3; 64],
        };
        let bytes = encode(&inv);
        let decoded: CallInvite = decode(&bytes).expect("decode");
        assert_eq!(decoded, inv);
    }

    #[test]
    fn call_accept_round_trip() {
        let acc = CallAccept {
            call_id: vec![0xc1; 16],
            pq_ciphertext: vec![0xc4; 1088],
            ice_candidates: vec![sample_ice_candidate(0, "x")],
            sig: vec![0xc5; 64],
        };
        let bytes = encode(&acc);
        let decoded: CallAccept = decode(&bytes).expect("decode");
        assert_eq!(decoded, acc);
    }

    #[test]
    fn call_ice_candidate_round_trip() {
        let ic = CallIceCandidate {
            call_id: vec![0xc1; 16],
            candidate: sample_ice_candidate(1, "trickled"),
            sig: vec![0xc6; 64],
        };
        let bytes = encode(&ic);
        let decoded: CallIceCandidate = decode(&bytes).expect("decode");
        assert_eq!(decoded, ic);
    }

    #[test]
    fn call_end_round_trip() {
        for reason in [
            CallEndReason::RemoteHangup,
            CallEndReason::LocalHangup,
            CallEndReason::Declined,
            CallEndReason::IceFailed,
            CallEndReason::DtlsFailed,
            CallEndReason::PqKexFailed,
        ] {
            let e = CallEnd {
                call_id: vec![0xc1; 16],
                reason,
                sig: vec![0xc7; 64],
            };
            let bytes = encode(&e);
            let decoded: CallEnd = decode(&bytes).expect("decode");
            assert_eq!(decoded, e);
        }
    }

    #[test]
    fn call_signal_dispatches_by_variant() {
        // Each variant round-trips through CallSignal and decodes
        // back into the same variant, not a different one.
        let invite = CallSignal::Invite(CallInvite {
            call_id: vec![1; 16],
            pq_encapsulation_key: vec![2; 1184],
            ice_candidates: vec![],
            sig: vec![3; 64],
        });
        let bytes = encode(&invite);
        let decoded: CallSignal = decode(&bytes).expect("decode invite");
        assert_eq!(decoded, invite);

        let accept = CallSignal::Accept(CallAccept {
            call_id: vec![4; 16],
            pq_ciphertext: vec![5; 1088],
            ice_candidates: vec![sample_ice_candidate(0, "a")],
            sig: vec![6; 64],
        });
        let bytes = encode(&accept);
        let decoded: CallSignal = decode(&bytes).expect("decode accept");
        assert_eq!(decoded, accept);

        let ice = CallSignal::IceCandidate(CallIceCandidate {
            call_id: vec![7; 16],
            candidate: sample_ice_candidate(1, "b"),
            sig: vec![8; 64],
        });
        let bytes = encode(&ice);
        let decoded: CallSignal = decode(&bytes).expect("decode ice");
        assert_eq!(decoded, ice);

        let end = CallSignal::End(CallEnd {
            call_id: vec![9; 16],
            reason: CallEndReason::IceFailed,
            sig: vec![10; 64],
        });
        let bytes = encode(&end);
        let decoded: CallSignal = decode(&bytes).expect("decode end");
        assert_eq!(decoded, end);
    }

    #[test]
    fn call_invite_with_no_ice_candidates_round_trips() {
        // ICE candidates can legitimately be empty at invite time;
        // the caller may not have gathered any yet (mDNS-only setup
        // or pre-gather invite).
        let inv = CallInvite {
            call_id: vec![1; 16],
            pq_encapsulation_key: vec![2; 1184],
            ice_candidates: vec![],
            sig: vec![3; 64],
        };
        let bytes = encode(&inv);
        let decoded: CallInvite = decode(&bytes).expect("decode");
        assert_eq!(decoded, inv);
    }

    #[test]
    fn wire_version_is_v4_at_m7() {
        // Bumped when call signaling landed (M7 Phase C). If this
        // assertion fails, the schema changed without bumping the
        // version — fix one or the other.
        assert_eq!(crate::WIRE_VERSION, 4);
    }
}
