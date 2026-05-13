# Identity and keys

Every Lattice account is a set of cryptographic keys. There is no
username + password. There is no email. There is no recovery flow
that depends on the home server. This page describes what your keys
are, where they live, how to back them up, and what happens if a
device is lost.

If you are looking for "what's protected against what" instead, see
[security-model.md](security-model.md). This page is about the
mechanics; the threat model is its own document.

---

## What a Lattice identity is

A Lattice **identity** is two keypairs plus an extension:

| Component | Algorithm | Purpose | Size (pub / sec) |
|---|---|---|---|
| Signing | ML-DSA-65 (FIPS 204) | PQ signature on identity claims | 1952 / 32 (seed) |
| Signing | Ed25519 | Classical signature on identity claims | 32 / 32 |
| KEM | ML-KEM-768 (FIPS 203) | PQ encapsulation for MLS LeafNode | 1184 / 2400 |

The ML-KEM keypair is carried as a custom MLS LeafNode extension with
ID `0xF002`, distinct from the credential. ML-KEM is not a signature
scheme; it lives next to the leaf init key (X25519 HPKE pubkey from
the base 0x0003 suite) rather than inside the credential.

For ML-DSA-65 we persist only the 32-byte seed (the FIPS 204 `xi`
value). The expanded signing key is deterministically rederived from
the seed via `SigningKey::from_seed`. This keeps the at-rest footprint
small.

### The user_id

Your **user_id** is a 32-byte BLAKE3 hash over the canonical encoding
of the two signing public keys. It is presented as 64 hex characters
in the UI. Example:

```
486fc5d875b69078c68a171b2f08b74c94a317489806adbc54eb5eef8a765cd8
```

The user_id is what you share with someone to start a conversation.
It looks long because it is intended to be unspoofable, not memorable
— in the future an out-of-band exchange flow (QR code, share-link)
will hide the hex string. For now the chat UI shows the hex directly.

The user_id is **server-independent**. Your home server stores your
identity claim and KeyPackage, but your user_id does not encode the
home server's hostname. A different home server can publish a claim
for the same user_id, which is detected as a key-substitution attack
by the key transparency log (see
[security-model.md#key-transparency](security-model.md#key-transparency)).

---

## The hybrid signature

Every identity-level claim — your `IdentityClaim`, your KeyPackage
external signature, federation events — is signed by **both** keys
independently. A signature is a `HybridSignature` wire type with two
fields:

```rust
pub struct HybridSignature {
    pub ml_dsa_sig: Vec<u8>,    // always 3309 bytes per FIPS 204
    pub ed25519_sig: [u8; 64],  // fixed
}
```

Both signatures sign the **same** transcript. Both must verify for
the hybrid signature to be considered valid. There is no "degrade to
classical" path:

- If ML-DSA-65 is cryptanalytically broken in five years, your
  identity is still protected by the Ed25519 co-signature.
- If Ed25519 is broken (a CRQC arriving in your lifetime), your
  identity is still protected by the ML-DSA-65 co-signature.

The framing-layer signatures inside MLS handshake messages are
classical Ed25519 (per the base 0x0003 ciphersuite). Only
identity-level claims are hybrid-signed.

---

## The KeyPackage

A **KeyPackage** is a pre-published, signed bundle that lets someone
invite you to an MLS group without a real-time handshake. Your client
publishes one at registration time and refreshes it after each use
(MLS consumes the leaf init key when the Welcome is processed). The
server stores the most-recent KeyPackage per user; old KPs are not
retained.

A Lattice KeyPackage carries:

- The MLS leaf init key (X25519 HPKE pubkey, base 0x0003 suite).
- Your `LatticeCredential` (ID `0xF001`): user_id + ed25519_pub +
  ml_dsa_pub.
- The `LatticeKemPubkey` LeafNode extension (ID `0xF002`):
  ML-KEM-768 verifying key.
- The MLS leaf signature, classical (Ed25519, per RFC 9420).

Size: roughly 12,057 bytes (verified in browser-to-browser smoke).

Wire-level structure is `mls-rs`'s `KeyPackage`; the extension layout
is Lattice-specific.

---

## Identity persistence — three blob versions

Your private key material has to live somewhere. Lattice supports
three at-rest formats in the browser, with progressively stronger
protection:

| Version | KEK source | Threat model defended |
|---|---|---|
| v1 | None (plaintext) | None. Only useful for dev / quick demos. |
| v2 | Argon2id over a user-chosen passphrase | Cold-storage attacks where the attacker has the browser profile but not the passphrase. |
| v3 | WebAuthn PRF | Cold-storage attacks **plus** scenarios where the attacker has the user's passphrase but not the physical authenticator. |

All three blobs live in `localStorage["lattice/identity/v1"]` (the
key name is fixed regardless of blob version — the blob carries its
own `version` field). The first byte of the JSON disambiguates.

### v1 — plaintext

Generated on first bootstrap when no blob exists. All key material is
base64-encoded JSON. Anyone with read access to the browser profile
recovers the keys. Acceptable for `localhost:5173` development;
never use on a public deployment.

Size: ~7,679 bytes for a fresh identity.

To upgrade to v2 or v3, open the legacy debug grid (the
`<details>` element under the chat shell) and click **Save
encrypted** (v2) or **Save with passkey** (v3).

### v2 — Argon2id + ChaCha20-Poly1305

The public material (user_id, ed25519_pub, ml_dsa_pub, kem_ek) stays
in the clear so the UI can show "encrypted identity for user_id …"
without prompting for the passphrase first. The two secret fields
(the ML-KEM decapsulation key and the signature secret key concat)
are sealed by a ChaCha20-Poly1305 AEAD whose key is derived by
Argon2id from your passphrase.

Argon2id parameters:

```
m_kib   = 64 * 1024   // 64 MiB
t       = 3           // iterations
p       = 1           // parallelism
out_len = 32 bytes
salt    = 16 random bytes (per-identity)
nonce   = 12 random bytes (per-seal)
aad     = b"lattice/persist/v2"
```

Size: ~7,756 bytes for a fresh identity (77-byte overhead over v1).
A 64 MiB Argon2id work on a current laptop is ~250 ms — enough to
make brute force impractical, fast enough to feel snappy at unlock.

To **load** an encrypted identity, the chat shell prompts for the
passphrase. Wrong passwords are caught by Poly1305's tag failure
without leaking timing.

### v3 — WebAuthn PRF + ChaCha20-Poly1305

Same envelope shape as v2 minus the salt — the KEK now comes from the
WebAuthn PRF extension (`hmac-secret`) evaluated against your
hardware authenticator.

On **create**: the client calls `navigator.credentials.create` with a
`prf` request in the extensions. The authenticator records the
credential and returns a credential_id. The client persists the
credential_id alongside the encrypted blob.

On **load**: the client calls `navigator.credentials.get` with the
credential_id, asks for `prf.eval`, and pulls the 32-byte secret out
of `getClientExtensionResults().prf.results.first`. That secret is
the KEK.

Properties:

- The KEK never leaves the authenticator hardware.
- The KEK is hardware-bound — copy the browser profile, open it on
  another machine, the PRF evaluation returns a different secret and
  the unwrap fails.
- The credential_id is not secret. It is fine for it to live in
  plaintext alongside the encrypted blob.

To use v3, your browser + authenticator must both support the PRF
extension:

- **Chrome / Edge 116+** with a security key (YubiKey 5C+ NFC,
  Titan v2+, Solo v2+) or a platform authenticator (Windows Hello
  recent versions, Touch ID on macOS Ventura+).
- **Safari 17+** with a platform authenticator on iOS 17+ or macOS
  Sonoma+.
- **Firefox 122+** on platform authenticators only.

The capabilities panel in the chat shell shows whether PRF is
available. If it is not, the v2 passphrase path is the safe
fallback.

---

## Hardware-backed storage on native

The Tauri desktop shell sidesteps `localStorage` entirely and stores
the identity in an OS-keychain primitive. The trait surface is
`lattice_media::keystore::Keystore` with three implementations
selected at build time:

| Platform | Implementation | Seal primitive | Vault location |
|---|---|---|---|
| Windows | `WindowsKeystore` (Phase G.1) | DPAPI (`CryptProtectData`) | `%LOCALAPPDATA%\Lattice\keystore\<handle>.dpapi` + `<handle>.pub` sidecar |
| Linux | `LinuxKeystore` (Phase G.2) | FreeDesktop Secret Service via `secret-service` over `zbus` | KDE Wallet / GNOME Keyring vault, sidecar on disk |
| macOS | `MacosKeystore` (Phase G.2) | `security-framework` against the login Keychain | login Keychain, sidecar on disk |

For each identity, the keystore writes two files: a sealed blob
containing the 64-byte secret key (32 ML-DSA-65 seed + 32 Ed25519
signing key), and a JSON public sidecar (label, created_at,
public bundle). `list()` and `pubkey()` read only the sidecar; `sign`
is the only operation that touches the seal primitive.

During a sign call, the secret bytes are unsealed into a `Zeroizing`
buffer in process RAM, used to sign, and wiped on drop. True
hardware-resident signing — where the key never leaves the secure
module — is not achievable for Ed25519 or ML-DSA-65 on Windows
(NCrypt does not support those algorithms). A TPM-backed
implementation swaps DPAPI for a TPM-bound wrap key on Windows,
Secure Enclave ECDH wrap on macOS, and optional `tss-esapi` on
Linux. The trait surface does not change.

Auditors should treat "hardware-backed" in Lattice's native-shell
context as "platform-sealed at rest, RAM-only during sign," not as
full enclave-resident signing.

---

## Backup, export, and recovery

There is currently no first-class identity export flow in the chat
UI. The pragmatic recovery story for now is:

### Browser → Browser on the same device

`localStorage` is persistent — closing and reopening the browser does
not delete the blob. Clearing site data deletes it. Use Chrome's
"Export bookmarks" → no, that doesn't include `localStorage`.
DevTools → Application → Storage → Local Storage → copy the
`lattice/identity/v1` value into a text file. The same value pasted
into a new browser profile (paste into DevTools and assign back to
`localStorage`) restores the identity.

### Browser → Tauri or Tauri → Tauri

There is no automatic migration today. The hybrid keystore handoff is
tracked as a Phase G follow-up: keystore handles cannot be reused as
WebAuthn credential IDs, so the UI needs an explicit "which identity
store am I using" toggle. Until that ships, treat the browser and
the desktop shell as separate identities on the same human.

### Device loss

If you lose your device and you have not backed up the identity
blob, the keypair is gone. There is no server-side recovery — the
home server never had your private keys.

What you can do:

- Boot a new identity on a new device. Other users will see a new
  user_id; conversations with them need to be re-established. The
  key transparency log makes a malicious server's attempt to
  "recover" your account as a different user_id detectable.
- If you have any **sibling device** still logged in to your
  account, you can issue an MLS Remove proposal to evict the lost
  device from active groups. The Remove fires a commit, advances
  the group epoch, and the lost device's per-epoch keys stop
  working on next decrypt.

The roadmap entry for a real export / import flow is Phase G
follow-up — passphrase-keyed Argon2id wrap that lives outside the
keystore boundary, re-importable on a new machine where it re-seals
under the new platform credential.

---

## File paths and storage locations

For reference, here is where Lattice puts identity material on each
platform.

| Surface | OS | Path |
|---|---|---|
| Browser blob | All | `localStorage["lattice/identity/v1"]` |
| CLI identity | Linux | `~/.local/share/lattice/identity` |
| CLI identity | macOS | `~/Library/Application Support/chat.lattice.lattice/identity` |
| CLI identity | Windows | `%APPDATA%\lattice\lattice\identity` |
| Tauri keystore — Windows DPAPI seal | Windows | `%LOCALAPPDATA%\Lattice\keystore\<handle>.dpapi` |
| Tauri keystore — Linux Secret Service | Linux | Stored in the user's keyring vault (KDE Wallet / GNOME Keyring); sidecar at `~/.local/share/lattice/keystore/` |
| Tauri keystore — macOS Keychain | macOS | login Keychain; sidecar at `~/Library/Application Support/chat.lattice.lattice/keystore/` |

The CLI identity file is a header (Argon2id params + salt) + body
(ChaCha20-Poly1305 ciphertext over a Prost-encoded `Identity`
struct) + AEAD tag. File permissions `0600` on Unix; refuse to
load files with looser permissions.

---

## What's not yet implemented

Honesty check, because over-claiming the security posture is the
fastest way to lose the user. As of the current handoff:

- **No export / import UI.** Backup is "copy the blob from DevTools."
- **No cross-device sync.** Lattice does not bridge two devices into
  one account automatically. The "device revocation" path works, but
  pairing a new device to an existing identity requires you to
  hand-carry the blob.
- **No multi-device hybrid keystore.** Browser PRF and Tauri
  keystore are not yet unified into one logical identity.
- **No TPM 2.0 / Secure Enclave binding.** Phase G.1 + G.2 use
  DPAPI / Secret Service / Keychain user-level seals. The
  hardware-bound seal (G.3) is the next "more secure" tier.
- **No biometric step at sign.** The OS keychain unlocks once per
  session; signing operations inside the session do not re-prompt.
- **No key transparency proofs in the chat UI.** The KT log code is
  in `crates/lattice-keytransparency/` (shipped) and the server
  publishes roots; the client-side inclusion-proof verification is
  not yet wired into the chat shell.

Each of the above is in the public roadmap kept in the source
repository.
