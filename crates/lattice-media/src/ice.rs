//! ICE agent wrapper.
//!
//! Wraps `webrtc_ice::agent::Agent` so the rest of `lattice-media`
//! never has to touch upstream's type names directly. Candidates and
//! credentials are exchanged over the MLS application channel via the
//! `CallIceCandidate` / `CallInvite` / `CallAccept` wire types in
//! `lattice-protocol`; the SDP candidate-line strings are opaque
//! payloads on the wire (RFC 8839 format).
//!
//! Phase C.1: real wrapper for same-process loopback + per-server
//! STUN/TURN. Phase C.2 will exercise it in a same-process
//! integration test.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex};
use tracing::instrument;
use webrtc_ice::agent::Agent;
use webrtc_ice::agent::agent_config::AgentConfig;
use webrtc_ice::candidate::Candidate;
use webrtc_ice::candidate::candidate_base::unmarshal_candidate;
use webrtc_ice::network_type::NetworkType;
use webrtc_ice::udp_network::UDPNetwork;
use webrtc_ice::url::Url;
use webrtc_util::Conn;

use crate::error::MediaError;

/// One side of an ICE session — wraps the upstream
/// `webrtc_ice::agent::Agent` with a thin async-friendly surface.
///
/// Typical lifecycle:
///
/// ```text
/// 1. new()                  // construct against optional STUN/TURN urls
/// 2. on_local_candidate(_)  // register handler that forwards to MLS
/// 3. local_credentials()    // hand to peer in CallInvite / CallAccept
/// 4. gather_candidates()    // kicks off the gather loop
/// 5. set_remote_credentials(_) + add_remote_candidate(_) repeatedly
///    as the peer's MLS-routed signaling arrives
/// 6. dial()   // controlling agent (caller) blocks until pair selected
///    accept() // controlled agent (callee) blocks until pair selected
/// 7. close()
/// ```
///
/// Both `dial` and `accept` return `Arc<dyn Conn + Send + Sync>` —
/// pass it to `dtls::DTLSConn::new` as the underlying transport for
/// the post-ICE DTLS handshake.
pub struct IceAgent {
    inner: Arc<Agent>,
    /// Held so that `dial` / `accept` can hand the receiver in to
    /// upstream. Drop the sender (via `close()`) to cancel an
    /// in-flight `dial`/`accept`.
    cancel_tx: Mutex<Option<mpsc::Sender<()>>>,
    cancel_rx: Mutex<Option<mpsc::Receiver<()>>>,
}

/// Short-lived ICE credentials. Both sides exchange these once at
/// invite/accept time over MLS; later trickled candidates are bound to
/// the same ufrag/pwd.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IceCredentials {
    /// ICE user fragment. RFC 8445 §5.3 requires ≥ 24 bits of entropy.
    pub ufrag: String,
    /// ICE password. RFC 8445 §5.3 requires ≥ 128 bits of entropy.
    pub pwd: String,
}

impl IceAgent {
    /// Build a new agent. `stun_turn_urls` are the rendezvous
    /// endpoints per D-19 — typically `stun:relay.<server>:3478`
    /// plus a matching `turn:` URL.
    ///
    /// `is_controlling` matches the DTLS role of the local side: the
    /// caller (DTLS client) is controlling, the callee is controlled.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::IceGathering`] if upstream rejects the
    /// config or fails to open the underlying UDP socket.
    #[instrument(level = "debug", skip(stun_turn_urls))]
    pub async fn new(
        stun_turn_urls: Vec<Url>,
        is_controlling: bool,
    ) -> Result<Self, MediaError> {
        let config = AgentConfig {
            urls: stun_turn_urls,
            udp_network: UDPNetwork::default(),
            network_types: vec![
                NetworkType::Udp4,
                NetworkType::Udp6,
            ],
            is_controlling,
            // Tighter than the upstream default (5 s) — we want the
            // user to see "ICE failed" within a few seconds rather
            // than wait through the 25 s "failed" timeout.
            disconnected_timeout: Some(Duration::from_secs(3)),
            failed_timeout: Some(Duration::from_secs(10)),
            ..AgentConfig::default()
        };

        let agent = Agent::new(config)
            .await
            .map_err(|e| MediaError::IceGathering(format!("agent new: {e}")))?;

        // Channel is sized 1 — close() either sends a unit signal or
        // drops the sender entirely.
        let (cancel_tx, cancel_rx) = mpsc::channel(1);
        Ok(Self {
            inner: Arc::new(agent),
            cancel_tx: Mutex::new(Some(cancel_tx)),
            cancel_rx: Mutex::new(Some(cancel_rx)),
        })
    }

    /// Local ICE user-credentials, ready to attach to a `CallInvite`
    /// or `CallAccept` wire payload.
    pub async fn local_credentials(&self) -> IceCredentials {
        let (ufrag, pwd) = self.inner.get_local_user_credentials().await;
        IceCredentials { ufrag, pwd }
    }

    /// Stash the peer's ICE credentials. Must be called before
    /// `dial`/`accept`.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::IceGathering`] on upstream error.
    #[instrument(level = "debug", skip(self, creds))]
    pub async fn set_remote_credentials(
        &self,
        creds: IceCredentials,
    ) -> Result<(), MediaError> {
        self.inner
            .set_remote_credentials(creds.ufrag, creds.pwd)
            .await
            .map_err(|e| MediaError::IceGathering(format!("set_remote_credentials: {e}")))
    }

    /// Register a callback for each local ICE candidate as it's
    /// gathered. The callback is invoked with `Some(sdp_line)` for
    /// each candidate and `None` once gathering completes — at which
    /// point the caller should send an end-of-candidates signal to
    /// the peer.
    ///
    /// The SDP line is the RFC 8839 candidate format, suitable for
    /// dropping straight into a `CallIceCandidate.candidate.sdp_line`
    /// field.
    pub fn on_local_candidate<F>(&self, f: F)
    where
        F: Fn(Option<String>) + Send + Sync + 'static,
    {
        let f = Arc::new(f);
        self.inner.on_candidate(Box::new(move |maybe_c| {
            let f = Arc::clone(&f);
            Box::pin(async move {
                let line = maybe_c.map(|c| c.marshal());
                f(line);
            })
        }));
    }

    /// Kick off the gather loop. Candidates arrive asynchronously via
    /// the [`Self::on_local_candidate`] callback.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::IceGathering`] on upstream error.
    #[instrument(level = "debug", skip(self))]
    pub fn gather_candidates(&self) -> Result<(), MediaError> {
        self.inner
            .gather_candidates()
            .map_err(|e| MediaError::IceGathering(format!("gather_candidates: {e}")))
    }

    /// Parse a remote SDP candidate line (RFC 8839) and feed it to
    /// the agent.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::IceGathering`] on parse or upstream error.
    #[instrument(level = "debug", skip(self))]
    pub fn add_remote_candidate(&self, sdp_line: &str) -> Result<(), MediaError> {
        let candidate = unmarshal_candidate(sdp_line)
            .map_err(|e| MediaError::IceGathering(format!("unmarshal candidate: {e}")))?;
        let candidate: Arc<dyn Candidate + Send + Sync> = Arc::new(candidate);
        self.inner
            .add_remote_candidate(&candidate)
            .map_err(|e| MediaError::IceGathering(format!("add_remote_candidate: {e}")))
    }

    /// Synchronous local-candidates snapshot — primarily useful for
    /// tests or for emitting an initial batch of candidates that
    /// were already gathered before the peer became reachable.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::IceGathering`] on upstream error.
    pub async fn local_candidates(&self) -> Result<Vec<String>, MediaError> {
        let cs = self
            .inner
            .get_local_candidates()
            .await
            .map_err(|e| MediaError::IceGathering(format!("get_local_candidates: {e}")))?;
        Ok(cs.iter().map(|c| c.marshal()).collect())
    }

    /// Drive the controlling-side connectivity checks. Returns an
    /// `Arc<dyn Conn>` once at least one candidate pair has
    /// connected. Feed this `Conn` to `dtls::DTLSConn::new` next.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::IceGathering`] if no candidate pair
    /// connects within `failed_timeout`, or if the cancel channel
    /// fires.
    #[instrument(level = "debug", skip(self, remote))]
    pub async fn dial(
        &self,
        remote: IceCredentials,
    ) -> Result<Arc<dyn Conn + Send + Sync>, MediaError> {
        let cancel_rx = self
            .cancel_rx
            .lock()
            .await
            .take()
            .ok_or_else(|| MediaError::IceGathering("dial/accept already called".into()))?;
        let conn = self
            .inner
            .dial(cancel_rx, remote.ufrag, remote.pwd)
            .await
            .map_err(|e| MediaError::IceGathering(format!("dial: {e}")))?;
        Ok(conn as Arc<dyn Conn + Send + Sync>)
    }

    /// Drive the controlled-side connectivity checks. Symmetric
    /// counterpart of [`Self::dial`].
    ///
    /// # Errors
    ///
    /// Same shape as [`Self::dial`].
    #[instrument(level = "debug", skip(self, remote))]
    pub async fn accept(
        &self,
        remote: IceCredentials,
    ) -> Result<Arc<dyn Conn + Send + Sync>, MediaError> {
        let cancel_rx = self
            .cancel_rx
            .lock()
            .await
            .take()
            .ok_or_else(|| MediaError::IceGathering("dial/accept already called".into()))?;
        let conn = self
            .inner
            .accept(cancel_rx, remote.ufrag, remote.pwd)
            .await
            .map_err(|e| MediaError::IceGathering(format!("accept: {e}")))?;
        Ok(conn as Arc<dyn Conn + Send + Sync>)
    }

    /// Cancel any in-flight `dial`/`accept` and tear down the
    /// underlying agent.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::IceGathering`] on upstream close error.
    #[instrument(level = "debug", skip(self))]
    pub async fn close(&self) -> Result<(), MediaError> {
        // Send the cancel signal first so a blocked dial/accept
        // returns ErrCanceledByCaller before we tear down the agent.
        if let Some(tx) = self.cancel_tx.lock().await.take() {
            let _ = tx.send(()).await;
        }
        self.inner
            .close()
            .await
            .map_err(|e| MediaError::IceGathering(format!("close: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn new_agent_yields_credentials() {
        let agent = IceAgent::new(vec![], true).await.expect("new");
        let creds = agent.local_credentials().await;
        // Per RFC 8445 §5.3, ufrag is ≥ 24 bits ≈ 4 base64 chars,
        // pwd is ≥ 128 bits ≈ 22 base64 chars. webrtc-ice generates
        // longer in practice, but pin the lower bound here.
        assert!(
            creds.ufrag.len() >= 4,
            "ufrag too short: {:?}",
            creds.ufrag
        );
        assert!(creds.pwd.len() >= 22, "pwd too short: {:?}", creds.pwd);
        agent.close().await.expect("close");
    }

    #[tokio::test]
    async fn dial_then_dial_errors() {
        // Calling dial twice (or dial then accept) on the same
        // IceAgent must fail rather than hand out a second cancel
        // receiver. Validates the dial/accept exclusivity check.
        let agent = IceAgent::new(vec![], true).await.expect("new");
        agent.set_remote_credentials(IceCredentials {
            ufrag: "fakeufrag".into(),
            pwd: "fakepwdthatissufficientlylong".into(),
        })
        .await
        .expect("set remote");

        // Spawn a dial that we'll cancel via close().
        let agent_clone = Arc::new(agent);
        let dial_handle = {
            let a = Arc::clone(&agent_clone);
            tokio::spawn(async move {
                a.dial(IceCredentials {
                    ufrag: "fakeufrag".into(),
                    pwd: "fakepwdthatissufficientlylong".into(),
                })
                .await
            })
        };
        // Give the dial a moment to take the receiver.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let second = agent_clone
            .accept(IceCredentials {
                ufrag: "fakeufrag".into(),
                pwd: "fakepwdthatissufficientlylong".into(),
            })
            .await;
        assert!(matches!(second, Err(MediaError::IceGathering(_))));

        agent_clone.close().await.expect("close");
        let _ = dial_handle.await; // collect the cancelled dial
    }
}
