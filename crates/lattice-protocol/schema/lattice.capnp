# Lattice wire schema (Cap'n Proto).
#
# Target of the M5 Cap'n Proto migration (ROADMAP §M5). The current
# in-tree wire types live in `src/wire.rs` as Prost-derived structs;
# this file is the schema-of-record that mls field tags and message
# shapes will be regenerated from once the build step is wired
# (capnp + capnpc-rust).
#
# Field IDs are stable. Adding a field appends to the message;
# renumbering an existing field is a wire-breaking change and
# requires a `WIRE_VERSION` bump (currently v2 after M5 multi-member;
# the Cap'n Proto swap would bump to v3).
#
# Schema review notes:
# * `Data` corresponds to Prost `bytes` — variable-length byte string.
# * `UInt32` / `UInt64` map cleanly from Prost `uint32` / `uint64`.
# * `Int64` maps from Prost `int64` (Unix-epoch seconds).
# * Optional message fields use Cap'n Proto's native Union for the
#   `null` case; the wire is more compact than Prost's "presence
#   bit" + tagged length.
# * The MLS-codec-encoded blobs (KeyPackage, Welcome, Commit,
#   ApplicationMessage payload bytes) stay as opaque `Data` — they
#   carry their own framing via mls-rs.

@0x9e3a4f2b5c1d6a87;  # File ID, unique 64-bit nonce per capnp

# Hybrid identity signature: ML-DSA-65 + Ed25519 concatenated wire
# form. The two sub-signatures are kept separate (not concatenated)
# so a hardware module that only computes one half can still validate
# the other half independently.
struct HybridSignatureWire {
    mlDsaSig    @0 :Data;    # ML-DSA-65 signature, 3309 bytes (FIPS 204)
    ed25519Sig  @1 :Data;    # Ed25519 signature, 64 bytes
}

# Identity claim published by a user, signed by their hybrid key.
#
# The wire bytes that get signed are this struct encoded with
# `signature` set to its null-union case. Verifiers re-encode with the
# signature cleared to obtain the canonical TBS bytes.
struct IdentityClaim {
    userId       @0 :Data;    # User UUID v7 (16 bytes)
    deviceId     @1 :Data;    # Device UUID v7 (16 bytes)
    mlDsaPub     @2 :Data;    # ML-DSA-65 verifying key (1952 bytes)
    ed25519Pub   @3 :Data;    # Ed25519 verifying key (32 bytes)
    issuedAt     @4 :Int64;   # Unix epoch seconds
    validUntil   @5 :Int64;   # Unix epoch seconds
    signature :union {
        none      @6 :Void;
        present   @7 :HybridSignatureWire;
    }
}

# Server-issued attribution cert for sealed sender (D-05). The server
# signs (group_id, epoch, ephemeral_sender_pubkey, valid_until) with
# its identity Ed25519 key.
struct MembershipCert {
    groupId                @0 :Data;     # MLS group id (16 bytes UUID)
    epoch                  @1 :UInt64;   # MLS epoch
    ephemeralSenderPubkey  @2 :Data;     # Ed25519 ephemeral pubkey (32 bytes)
    validUntil             @3 :Int64;    # Unix epoch seconds
    serverSig              @4 :Data;     # Ed25519 server signature (64 bytes)
}

# Sealed-sender envelope (D-05). The router sees: group_id, epoch,
# cert, opaque inner ciphertext. Recipients decrypt the inner
# ciphertext using their MLS group state.
struct SealedEnvelope {
    groupId          @0 :Data;     # MLS group id (16 bytes)
    epoch            @1 :UInt64;
    membershipCert :union {
        none          @2 :Void;
        present       @3 :MembershipCert;
    }
    innerCiphertext  @4 :Data;     # opaque to server
    envelopeSig      @5 :Data;     # Ed25519 sig over innerCiphertext (64 bytes)
}

# Lattice KeyPackage: an MLS KeyPackage wrapped with the user's
# hybrid identity claim so peers can verify both the MLS leaf node
# and the hybrid identity binding.
struct KeyPackage {
    identity :union {
        none          @0 :Void;
        present       @1 :IdentityClaim;
    }
    mlsKeyPackage    @2 :Data;     # mls-rs MlsMessage bytes
}

# MLS Welcome message wrapper. Multi-member Welcomes from
# lattice_crypto::mls::add_members are paired by joiner_idx with
# their corresponding PqWelcomePayload via the M5 wire v2 fields on
# the PQ side; the Welcome itself stays opaque mls-rs bytes.
struct Welcome {
    mlsWelcome       @0 :Data;
}

# MLS Commit message wrapper.
struct Commit {
    mlsCommit        @0 :Data;
}

# MLS application message wrapper. In sealed-sender flows this lives
# inside SealedEnvelope.innerCiphertext.
struct ApplicationMessage {
    mlsApplicationMessage  @0 :Data;
}

# ---- M7 voice/video call signaling ---------------------------------
#
# These types are the *plaintext payload* that gets encrypted by MLS
# before becoming `ApplicationMessage.mlsApplicationMessage`. The
# server never sees them in cleartext. The structures match the
# construction in `scratch/pq-dtls-srtp-construction.md`.
#
# Wire version bumped 3 -> 4 when these structs land. M7 Phase C.

# Single ICE candidate carried over the MLS application channel.
# `sdpLine` is opaque to Lattice — it's the standard ICE SDP
# candidate line format (RFC 8839). `sdpMlineIndex` is 0 for the
# audio m-line and 1 for video.
struct CallIceCandidateLine {
    sdpLine          @0 :Text;
    sdpMlineIndex    @1 :UInt32;
}

# CallInvite — sent by the caller (Alice) to start a 1:1 call.
#
# The caller generates a fresh ML-KEM-768 keypair for this call and
# attaches the encapsulation key here. ICE candidates are also
# bundled so the callee can start connectivity checks immediately.
# Signed by the caller's Ed25519 identity key over the canonical
# transcript bytes (see CALL_INVITE_TRANSCRIPT_PREFIX in
# lattice-media::constants).
struct CallInvite {
    callId               @0 :Data;     # 16 random bytes (CallId)
    pqEncapsulationKey   @1 :Data;     # ML-KEM-768 ek, 1184 B
    iceCandidates        @2 :List(CallIceCandidateLine);
    sig                  @3 :Data;     # Ed25519 sig, 64 B
}

# CallAccept — sent by the callee (Bob) in response to a CallInvite.
#
# Carries the ML-KEM-768 ciphertext that the caller decapsulates to
# recover the shared PQ secret, plus the callee's local ICE
# candidates. Signed by the callee's Ed25519 identity key.
struct CallAccept {
    callId           @0 :Data;     # 16 bytes
    pqCiphertext     @1 :Data;     # ML-KEM-768 ct, 1088 B
    iceCandidates    @2 :List(CallIceCandidateLine);
    sig              @3 :Data;     # Ed25519 sig, 64 B
}

# CallIceCandidate — trickled ICE candidate after the initial
# invite/accept exchange. Both sides may send these throughout the
# connection-checks phase.
struct CallIceCandidate {
    callId          @0 :Data;
    candidate       @1 :CallIceCandidateLine;
    sig             @2 :Data;     # Ed25519 sig, 64 B
}

# Reason a call ended. Mirrors lattice-media::call::EndReason; the
# wire integer maps to the Rust enum variant.
enum CallEndReason {
    remoteHangup    @0;
    localHangup     @1;
    declined        @2;
    iceFailed       @3;
    dtlsFailed      @4;
    pqKexFailed     @5;
}

# CallEnd — sent when one side hangs up or the call fails. Either
# party may send this. Signed by sender's Ed25519 identity key.
struct CallEnd {
    callId          @0 :Data;
    reason          @1 :CallEndReason;
    sig             @2 :Data;     # Ed25519 sig, 64 B
}

# Discriminated union for call signaling — one CallSignal per MLS
# application message during a voice/video call. The application
# layer parses an MLS application message body as a CallSignal when
# the surrounding MLS group has an active call_id; otherwise it
# falls back to plain text framing.
struct CallSignal {
    body :union {
        invite        @0 :CallInvite;
        accept        @1 :CallAccept;
        iceCandidate  @2 :CallIceCandidate;
        endCall       @3 :CallEnd;
    }
}
