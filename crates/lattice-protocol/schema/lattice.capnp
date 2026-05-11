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
