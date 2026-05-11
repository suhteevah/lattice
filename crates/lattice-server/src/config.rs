//! Typed configuration loaded from env + `lattice.toml`.

use serde::Deserialize;

/// Top-level application configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    /// Listener config.
    pub server: ServerConfig,
    /// Database connection string, e.g. `postgres://user:pw@host/db`.
    pub database_url: String,
    /// Environment label (`development`, `staging`, `production`).
    pub environment: String,
    /// Federation key path (file holding the server's signing key).
    pub federation_key_path: String,
    /// Snapshot path — JSON file holding a serialized in-memory state
    /// dump, restored on startup and saved on graceful shutdown.
    /// Empty string disables snapshotting (process restarts then lose
    /// all state).
    pub snapshot_path: String,
}

/// HTTP/QUIC listener config.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Socket address to bind (e.g. `0.0.0.0:8443`).
    pub bind_addr: String,
}

impl AppConfig {
    /// Load config from `LATTICE_*` env vars + optional `lattice.toml`.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing or types mismatch.
    pub fn load() -> Result<Self, config::ConfigError> {
        config::Config::builder()
            .add_source(config::File::with_name("lattice").required(false))
            .add_source(
                config::Environment::with_prefix("LATTICE")
                    .separator("__")
                    .try_parsing(true),
            )
            .set_default("server.bind_addr", "0.0.0.0:8443")?
            .set_default("environment", "development")?
            .set_default("federation_key_path", "./federation.key")?
            .set_default("snapshot_path", "")?
            .set_default(
                "database_url",
                "postgres://lattice:lattice@localhost:5432/lattice",
            )?
            .build()?
            .try_deserialize()
    }
}
