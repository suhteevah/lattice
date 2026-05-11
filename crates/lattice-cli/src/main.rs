//! `lattice` — admin and developer CLI.
//!
//! Subcommands cover:
//! - `register` — generate a hybrid identity, publish a key bundle
//! - `create-group` — create a new MLS group on the local home server
//! - `invite` — add a peer to a group
//! - `send` — send a message to a group or DM peer
//! - `recv` — fetch and decrypt pending messages
//! - `server` — admin operations against a home server (rotate federation
//!   key, list users, etc.)
//!
//! The CLI is the primary way to exercise the **first vertical slice** —
//! see `docs/HANDOFF.md §6`.

#![forbid(unsafe_code)]

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{prelude::*, EnvFilter};

#[derive(Debug, Parser)]
#[command(name = "lattice", version, about = "Lattice CLI")]
struct Cli {
    /// Home server URL.
    #[arg(long, env = "LATTICE_HOME_SERVER", default_value = "https://localhost:8443")]
    home_server: String,

    /// Local identity file. Defaults to `~/.lattice/identity.json`.
    #[arg(long, env = "LATTICE_IDENTITY")]
    identity: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Generate a hybrid identity and register it with the home server.
    Register {
        /// Display name.
        #[arg(long)]
        name: String,
    },
    /// Create a new MLS group.
    CreateGroup {
        /// Group display name.
        #[arg(long)]
        name: String,
    },
    /// Invite a user to an existing group.
    Invite {
        /// Group ID.
        #[arg(long)]
        group: String,
        /// Peer user ID.
        #[arg(long)]
        user: String,
    },
    /// Send an application message.
    Send {
        /// Target group or user.
        #[arg(long)]
        to: String,
        /// Message text.
        #[arg(long)]
        text: String,
    },
    /// Receive and decrypt pending messages.
    Recv,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("lattice=debug"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().compact())
        .try_init()
        .ok();

    let cli = Cli::parse();

    lattice_core::init().map_err(|e| anyhow::anyhow!("core init: {e}"))?;

    match cli.cmd {
        Cmd::Register { name } => {
            tracing::info!(name, "register — TODO");
        }
        Cmd::CreateGroup { name } => {
            tracing::info!(name, "create-group — TODO");
        }
        Cmd::Invite { group, user } => {
            tracing::info!(group, user, "invite — TODO");
        }
        Cmd::Send { to, text } => {
            tracing::info!(to, text_len = text.len(), "send — TODO");
        }
        Cmd::Recv => {
            tracing::info!("recv — TODO");
        }
    }

    Ok(())
}
