//! Thin HTTP client for the M3 `lattice-server` REST surface.
//!
//! Mirrors the per-flow shape used by `crates/lattice-cli/src/main.rs`
//! (`register`, `publish_kp`, `fetch_kp`, …) but uses `gloo-net` so the
//! same logic runs in the browser. Server-side CORS is wired in
//! `lattice_server::app()` — see the workspace handoff.
//!
//! The API surface is deliberately tiny right now (just `register`); the
//! rest of the per-action methods land in later M4 γ sub-phases as the
//! browser UI gains more buttons.

use base64::Engine;
use gloo_net::http::Request;
use lattice_crypto::mls::LatticeIdentity;
use lattice_crypto::mls::psk::LatticePskStorage;
use lattice_crypto::mls::welcome_pq::PqWelcomePayload;
use lattice_crypto::mls::LatticeWelcome;
use lattice_protocol::wire::{IdentityClaim, MembershipCert, SealedEnvelope, encode};
use mls_rs_codec::{MlsDecode, MlsEncode};
use prost::Message;
use serde::Deserialize;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Mirror of `lattice_server::routes::identity::RegisterResponse`.
///
/// The server returns `{ "new_registration": bool }` and nothing else;
/// we only decode the bool flag.
#[derive(Debug, Deserialize)]
struct RegisterResponse {
    new_registration: bool,
}

/// `POST /register` against a `lattice-server` URL.
///
/// Encodes a (currently empty) `IdentityClaim` placeholder per
/// `lattice_cli::register_raw` — the server today accepts any
/// well-formed Prost claim and does not yet verify the hybrid signature
/// against the credential. Returns the server's `new_registration` flag
/// (`true` on first registration, `false` if the user_id was already
/// known and the claim was overwritten in place).
///
/// # Errors
///
/// Returns a `String` describing where the call failed — network
/// reachability, non-2xx status, or JSON decode mismatch. Errors are
/// surfaced to the UI as-is.
pub async fn register(server: &str, identity: &LatticeIdentity) -> Result<bool, String> {
    let claim_bytes = encode(&IdentityClaim::default());
    let body = serde_json::json!({
        "user_id_b64": B64.encode(identity.credential.user_id),
        "claim_b64": B64.encode(&claim_bytes),
    });

    let request = Request::post(&format!("{server}/register"))
        .json(&body)
        .map_err(|e| format!("build register request: {e}"))?;

    let response = request
        .send()
        .await
        .map_err(|e| format!("send register: {e}"))?;

    if !response.ok() {
        return Err(format!(
            "register HTTP {} ({})",
            response.status(),
            response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string())
        ));
    }

    let parsed: RegisterResponse = response
        .json()
        .await
        .map_err(|e| format!("decode register response: {e}"))?;
    Ok(parsed.new_registration)
}

/// Mirror of `lattice_server::routes::identity::PublishKeyPackageResponse`.
#[derive(Debug, Deserialize)]
struct PublishKpResponse {
    published_at: i64,
}

/// Mirror of `lattice_server::routes::identity::FetchKeyPackageResponse`.
#[derive(Debug, Deserialize)]
struct FetchKpResponse {
    key_package_b64: String,
    #[allow(dead_code)] // surfaced through publish flow; fetch returns it too
    published_at: i64,
}

/// `POST /key_packages` — generate a KeyPackage for `identity` and
/// publish it to the server.
///
/// Returns the server-reported `published_at` timestamp on success.
/// Generates the KeyPackage in-WASM via
/// `lattice_crypto::mls::generate_key_package`, using the caller's
/// `LatticePskStorage` so the eventual `process_welcome` step can
/// recover the PQ secret.
///
/// # Errors
///
/// Surfaces failure points individually — KP generation, request
/// build, send, non-2xx, JSON decode.
pub async fn publish_key_package(
    server: &str,
    identity: &LatticeIdentity,
    psk_store: &LatticePskStorage,
) -> Result<i64, String> {
    let kp_bytes = lattice_crypto::mls::generate_key_package(identity, psk_store.clone())
        .map_err(|e| format!("generate_key_package: {e}"))?;
    let body = serde_json::json!({
        "user_id_b64": B64.encode(identity.credential.user_id),
        "key_package_b64": B64.encode(&kp_bytes),
    });

    let response = Request::post(&format!("{server}/key_packages"))
        .json(&body)
        .map_err(|e| format!("build publish_kp request: {e}"))?
        .send()
        .await
        .map_err(|e| format!("send publish_kp: {e}"))?;

    if !response.ok() {
        return Err(format!(
            "publish_kp HTTP {} ({})",
            response.status(),
            response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string())
        ));
    }

    let parsed: PublishKpResponse = response
        .json()
        .await
        .map_err(|e| format!("decode publish_kp response: {e}"))?;
    Ok(parsed.published_at)
}

/// `GET /key_packages/:user_id_b64url` — fetch the latest published
/// KeyPackage for a user, returning the raw bytes ready to feed back
/// into `lattice_crypto::mls::add_member`.
///
/// We pass the user_id in URL-safe base64 (no padding) to keep clean
/// path segments. The server tries both encodings on its end.
///
/// # Errors
///
/// 404 when no KP has been published for that user — surfaced as a
/// clear string so the UI can distinguish missing-state from network.
pub async fn fetch_key_package(
    server: &str,
    user_id: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let user_id_b64url = B64URL.encode(user_id);
    let response = Request::get(&format!("{server}/key_packages/{user_id_b64url}"))
        .send()
        .await
        .map_err(|e| format!("send fetch_kp: {e}"))?;

    if !response.ok() {
        return Err(format!(
            "fetch_kp HTTP {} ({})",
            response.status(),
            response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string())
        ));
    }

    let parsed: FetchKpResponse = response
        .json()
        .await
        .map_err(|e| format!("decode fetch_kp response: {e}"))?;
    B64.decode(&parsed.key_package_b64)
        .map_err(|e| format!("decode key_package_b64: {e}"))
}

/// Mirror of `lattice_server::routes::groups::CommitResponse`.
#[derive(Debug, Deserialize)]
struct CommitResponse {
    #[allow(dead_code)]
    epoch: u64,
    welcomes_accepted: usize,
}

/// `POST /group/:gid/commit` — submit an MLS commit + per-joiner
/// Welcome bundle. Returns the number of welcomes the server accepted
/// for fan-out (federation push to remote home servers is a no-op
/// when `remote_routing` is empty, which is the case for our
/// single-server demo).
///
/// `pq_payload` is MLS-codec-encoded inline so the server can store it
/// alongside the MLS Welcome and hand it back on
/// `GET /group/:gid/welcome/:user_id`.
///
/// # Errors
///
/// Surfaces request/response failures with HTTP status and body text.
pub async fn submit_commit(
    server: &str,
    group_id: &[u8; 16],
    epoch: u64,
    commit_bytes: &[u8],
    welcome: &LatticeWelcome,
    joiner_user_id: &[u8; 32],
) -> Result<usize, String> {
    let pq_bytes = welcome
        .pq_payload
        .mls_encode_to_vec()
        .map_err(|e| format!("mls-encode pq_payload: {e}"))?;
    let body = serde_json::json!({
        "epoch": epoch,
        "commit_b64": B64.encode(commit_bytes),
        "welcomes": [{
            "joiner_user_id_b64": B64.encode(joiner_user_id),
            "mls_welcome_b64": B64.encode(&welcome.mls_welcome),
            "pq_payload_b64": B64.encode(&pq_bytes),
        }],
    });
    let response = Request::post(&format!(
        "{server}/group/{}/commit",
        B64URL.encode(group_id)
    ))
    .json(&body)
    .map_err(|e| format!("build commit request: {e}"))?
    .send()
    .await
    .map_err(|e| format!("send commit: {e}"))?;

    if !response.ok() {
        return Err(format!(
            "commit HTTP {} ({})",
            response.status(),
            response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string())
        ));
    }

    let parsed: CommitResponse = response
        .json()
        .await
        .map_err(|e| format!("decode commit response: {e}"))?;
    Ok(parsed.welcomes_accepted)
}

/// Mirror of `lattice_server::routes::groups::WelcomeResponse`.
#[derive(Debug, Deserialize)]
struct WelcomeResponse {
    #[allow(dead_code)]
    epoch: u64,
    mls_welcome_b64: String,
    pq_payload_b64: String,
}

/// `GET /group/:gid/welcome/:user_id_b64url` — fetch a pending welcome
/// for the joiner. Decodes both the MLS Welcome bytes and the
/// MLS-codec `PqWelcomePayload`, then reassembles a [`LatticeWelcome`]
/// ready to feed back into `process_welcome`.
///
/// # Errors
///
/// 404 ("no pending welcome") is reported verbatim by the server and
/// surfaces here as a HTTP-status error.
pub async fn fetch_welcome(
    server: &str,
    group_id: &[u8; 16],
    user_id: &[u8; 32],
) -> Result<LatticeWelcome, String> {
    let response = Request::get(&format!(
        "{server}/group/{}/welcome/{}",
        B64URL.encode(group_id),
        B64URL.encode(user_id)
    ))
    .send()
    .await
    .map_err(|e| format!("send fetch_welcome: {e}"))?;

    if !response.ok() {
        return Err(format!(
            "fetch_welcome HTTP {} ({})",
            response.status(),
            response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string())
        ));
    }

    let parsed: WelcomeResponse = response
        .json()
        .await
        .map_err(|e| format!("decode fetch_welcome response: {e}"))?;
    let mls_welcome = B64
        .decode(&parsed.mls_welcome_b64)
        .map_err(|e| format!("decode mls_welcome_b64: {e}"))?;
    let pq_bytes = B64
        .decode(&parsed.pq_payload_b64)
        .map_err(|e| format!("decode pq_payload_b64: {e}"))?;
    let pq_payload = PqWelcomePayload::mls_decode(&mut pq_bytes.as_slice())
        .map_err(|e| format!("mls-decode pq_payload: {e}"))?;
    Ok(LatticeWelcome {
        mls_welcome,
        pq_payload,
    })
}

/// Mirror of `lattice_server::routes::groups::PublishMessageResponse`.
#[derive(Debug, Deserialize)]
struct PublishMessageResponse {
    seq: u64,
}

/// `POST /group/:gid/messages` — append a sealed envelope (or raw MLS
/// application-message ciphertext) to the group's inbox. The server
/// assigns a monotonic `seq` and returns it.
///
/// # Errors
///
/// Network or non-2xx status.
pub async fn publish_message(
    server: &str,
    group_id: &[u8; 16],
    envelope: &[u8],
) -> Result<u64, String> {
    let body = serde_json::json!({
        "envelope_b64": B64.encode(envelope),
    });
    let response = Request::post(&format!(
        "{server}/group/{}/messages",
        B64URL.encode(group_id)
    ))
    .json(&body)
    .map_err(|e| format!("build publish_message request: {e}"))?
    .send()
    .await
    .map_err(|e| format!("send publish_message: {e}"))?;

    if !response.ok() {
        return Err(format!(
            "publish_message HTTP {} ({})",
            response.status(),
            response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string())
        ));
    }
    let parsed: PublishMessageResponse = response
        .json()
        .await
        .map_err(|e| format!("decode publish_message response: {e}"))?;
    Ok(parsed.seq)
}

/// One message returned by [`fetch_messages`].
pub struct FetchedMessage {
    /// Server-assigned monotonic sequence number. Used by callers
    /// that page through the inbox; the M4 γ.3 demo decrypts the
    /// envelope and discards the seq, so it lives behind `dead_code`
    /// for now.
    #[allow(dead_code)]
    pub seq: u64,
    /// Decoded envelope bytes.
    pub envelope: Vec<u8>,
}

/// `GET /group/:gid/messages?since=N` — drain the group's inbox from
/// `since` upward. Returns the latest-seen seq + the messages in
/// ascending seq order.
///
/// # Errors
///
/// Network or non-2xx status. Decode errors on the inner envelope
/// base64 surface as `decode_envelope_b64`.
pub async fn fetch_messages(
    server: &str,
    group_id: &[u8; 16],
    since: u64,
) -> Result<(u64, Vec<FetchedMessage>), String> {
    #[derive(Deserialize)]
    struct Entry {
        seq: u64,
        envelope_b64: String,
    }
    #[derive(Deserialize)]
    struct Body {
        latest_seq: u64,
        messages: Vec<Entry>,
    }

    let response = Request::get(&format!(
        "{server}/group/{}/messages?since={since}",
        B64URL.encode(group_id)
    ))
    .send()
    .await
    .map_err(|e| format!("send fetch_messages: {e}"))?;

    if !response.ok() {
        return Err(format!(
            "fetch_messages HTTP {} ({})",
            response.status(),
            response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string())
        ));
    }
    let parsed: Body = response
        .json()
        .await
        .map_err(|e| format!("decode fetch_messages response: {e}"))?;
    let messages = parsed
        .messages
        .into_iter()
        .map(|e| {
            let envelope = B64
                .decode(&e.envelope_b64)
                .map_err(|err| format!("decode_envelope_b64 seq={}: {err}", e.seq))?;
            Ok(FetchedMessage {
                seq: e.seq,
                envelope,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((parsed.latest_seq, messages))
}

/// Mirror of `lattice_server::routes::well_known::ServerDescriptor`.
/// We only consume the federation pubkey here — the wire_version /
/// server_version fields are surfaced for logging.
#[derive(Debug, Deserialize)]
pub struct ServerDescriptor {
    /// Wire protocol version supported by the server.
    pub wire_version: u32,
    /// Base64 of the server's Ed25519 federation pubkey. Sealed-sender
    /// verification at the router (and at the recipient, per D-05)
    /// reads this.
    pub federation_pubkey_b64: String,
    /// Server's reported version string.
    pub server_version: String,
}

/// `GET /.well-known/lattice/server` — fetch the server descriptor.
///
/// # Errors
///
/// Network or non-2xx status; JSON parse failure.
pub async fn fetch_descriptor(server: &str) -> Result<ServerDescriptor, String> {
    let response = Request::get(&format!("{server}/.well-known/lattice/server"))
        .send()
        .await
        .map_err(|e| format!("send fetch_descriptor: {e}"))?;
    if !response.ok() {
        return Err(format!(
            "fetch_descriptor HTTP {} ({})",
            response.status(),
            response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string())
        ));
    }
    response
        .json()
        .await
        .map_err(|e| format!("decode descriptor: {e}"))
}

/// Mirror of `lattice_server::routes::groups::IssueCertResponse`.
#[derive(Debug, Deserialize)]
struct IssueCertResponseWire {
    cert_b64: String,
}

/// `POST /group/:gid/issue_cert` — request a sealed-sender membership
/// cert binding `ephemeral_pubkey` to the current epoch for
/// `valid_until` seconds. Decodes the server's Prost-encoded
/// [`MembershipCert`] and returns it ready to feed into
/// `lattice_protocol::sealed_sender::seal`.
///
/// # Errors
///
/// Network, non-2xx, base64, or Prost decode failures.
pub async fn issue_cert(
    server: &str,
    group_id: &[u8; 16],
    epoch: u64,
    ephemeral_pubkey: &[u8; 32],
    valid_until: i64,
) -> Result<MembershipCert, String> {
    let body = serde_json::json!({
        "epoch": epoch,
        "ephemeral_pubkey_b64": B64.encode(ephemeral_pubkey),
        "valid_until": valid_until,
    });
    let response = Request::post(&format!(
        "{server}/group/{}/issue_cert",
        B64URL.encode(group_id)
    ))
    .json(&body)
    .map_err(|e| format!("build issue_cert request: {e}"))?
    .send()
    .await
    .map_err(|e| format!("send issue_cert: {e}"))?;
    if !response.ok() {
        return Err(format!(
            "issue_cert HTTP {} ({})",
            response.status(),
            response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string())
        ));
    }
    let parsed: IssueCertResponseWire = response
        .json()
        .await
        .map_err(|e| format!("decode issue_cert response: {e}"))?;
    let cert_bytes = B64
        .decode(&parsed.cert_b64)
        .map_err(|e| format!("decode cert_b64: {e}"))?;
    MembershipCert::decode(cert_bytes.as_slice())
        .map_err(|e| format!("prost decode MembershipCert: {e}"))
}

/// Helper: Prost-encode a [`SealedEnvelope`] for transport.
#[must_use]
pub fn encode_sealed(envelope: &SealedEnvelope) -> Vec<u8> {
    encode(envelope)
}

/// Helper: Prost-decode a [`SealedEnvelope`] from bytes pulled out of
/// `/group/:gid/messages`.
///
/// # Errors
///
/// Returns the Prost decode error as a string.
pub fn decode_sealed(bytes: &[u8]) -> Result<SealedEnvelope, String> {
    SealedEnvelope::decode(bytes).map_err(|e| format!("prost decode SealedEnvelope: {e}"))
}

/// `GET /group/:gid/messages/ws` — open a live message-subscription
/// WebSocket. The browser receives a JSON `{seq, envelope_b64}`
/// text frame each time a new message lands on the server. D-11
/// fallback tier of γ.4; the WebTransport equivalent ships once the
/// server-side QUIC stack is in place.
///
/// Returns the raw `web_sys::WebSocket` so the caller can hook
/// `set_onmessage` / `set_onclose` and stash it in a Leptos signal
/// to keep it alive. Closing the socket happens automatically when
/// the returned handle is dropped — keep it live for the duration
/// of the subscription.
///
/// # Errors
///
/// Returns the JS-side error description if `WebSocket::new` rejects
/// (bad URL, mixed-content block, etc).
pub fn open_messages_ws(
    server: &str,
    group_id: &[u8; 16],
) -> Result<web_sys::WebSocket, String> {
    // Translate http(s)://… → ws(s)://… for the WS handshake host.
    let base = if let Some(rest) = server.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = server.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        server.to_string()
    };
    let url = format!(
        "{base}/group/{}/messages/ws",
        B64URL.encode(group_id)
    );
    web_sys::WebSocket::new(&url).map_err(|e| format!("WebSocket::new({url}): {e:?}"))
}

/// One pushed message decoded from a WS frame.
pub struct WsPush {
    /// Monotonic seq the server assigned.
    pub seq: u64,
    /// Envelope bytes (raw MLS application ciphertext OR a
    /// Prost-encoded `SealedEnvelope`, depending on the publisher).
    pub envelope: Vec<u8>,
}

/// Parse one `MessageEvent.data` payload off the WS. JSON shape is
/// `{ "seq": <u64>, "envelope_b64": "<base64>" }`.
///
/// # Errors
///
/// JSON parse / base64 decode failures, surfaced as strings.
pub fn parse_ws_push(text: &str) -> Result<WsPush, String> {
    #[derive(serde::Deserialize)]
    struct Frame {
        seq: u64,
        envelope_b64: String,
    }
    let parsed: Frame = serde_json::from_str(text)
        .map_err(|e| format!("ws frame parse: {e}"))?;
    let envelope = B64
        .decode(&parsed.envelope_b64)
        .map_err(|e| format!("ws frame envelope_b64: {e}"))?;
    Ok(WsPush {
        seq: parsed.seq,
        envelope,
    })
}
