//! `iroh-gateway-edge`: the public side of the tunnel.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};
use iroh::EndpointId;
use iroh_gateway_edge::{Edge, EdgeOptions};
use iroh_gateway_proto::key::load_or_generate;
use iroh_gateway_proto::transport::Relay;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "Public edge of iroh-gateway")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print this edge's EndpointId, creating the key file if it is missing.
    Id {
        #[arg(
            long,
            env = "IROH_GATEWAY_EDGE_KEY_FILE",
            default_value = "/var/lib/iroh-gateway-edge/edge.key"
        )]
        key_file: PathBuf,
    },
    /// Serve the operator and forward visitors to it.
    Run {
        #[arg(
            long,
            env = "IROH_GATEWAY_EDGE_KEY_FILE",
            default_value = "/var/lib/iroh-gateway-edge/edge.key"
        )]
        key_file: PathBuf,
        /// EndpointId of the only operator this edge serves.
        #[arg(long, env = "IROH_GATEWAY_EDGE_OPERATOR")]
        operator: EndpointId,
        /// UDP address for the iroh endpoint.
        #[arg(
            long,
            env = "IROH_GATEWAY_EDGE_IROH_LISTEN",
            default_value = "0.0.0.0:7842"
        )]
        iroh_listen: SocketAddr,
        /// Address the public listeners bind to.
        #[arg(long, env = "IROH_GATEWAY_EDGE_PUBLIC_BIND", default_value = "::")]
        public_bind: IpAddr,
        /// Maximum number of simultaneous visitor connections.
        #[arg(
            long,
            env = "IROH_GATEWAY_EDGE_MAX_CONNECTIONS",
            default_value_t = 10_000,
            value_parser = clap::value_parser!(u32).range(1..=65_536)
        )]
        max_connections: u32,
        /// How long listeners stay open without a tunnel, e.g. "5s".
        #[arg(
            long,
            env = "IROH_GATEWAY_EDGE_TUNNEL_GRACE",
            default_value = "5s",
            value_parser = humantime::parse_duration
        )]
        tunnel_grace: Duration,
        /// "disabled", "n0" or an https relay URL; the operator must use the same.
        #[arg(long, env = "IROH_GATEWAY_EDGE_RELAY", default_value = "disabled")]
        relay: Relay,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    match cli.command {
        Command::Id { key_file } => {
            let key = load_or_generate(&key_file)
                .with_context(|| format!("key file {}", key_file.display()))?;
            println!("{}", key.public());
        }
        Command::Run {
            key_file,
            operator,
            iroh_listen,
            public_bind,
            max_connections,
            tunnel_grace,
            relay,
        } => {
            let secret_key = load_or_generate(&key_file)
                .with_context(|| format!("key file {}", key_file.display()))?;
            let edge = Edge::spawn(EdgeOptions {
                secret_key,
                operator,
                iroh_listen,
                public_bind,
                max_connections: max_connections as usize,
                tunnel_grace,
                relay,
            })
            .await?;
            info!(id = %edge.endpoint_id(), "serving; waiting for SIGINT or SIGTERM");
            shutdown_signal().await?;
            info!("shutting down");
            edge.shutdown().await;
        }
    }
    Ok(())
}

/// Resolves on SIGINT or SIGTERM.
async fn shutdown_signal() -> anyhow::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        r = tokio::signal::ctrl_c() => r?,
        _ = term.recv() => {}
    }
    Ok(())
}
