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
use tracing::{info, warn};
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
        /// Maximum number of simultaneous visitor connections; each may hold about 400 KiB.
        #[arg(
            long,
            env = "IROH_GATEWAY_EDGE_MAX_CONNECTIONS",
            default_value_t = 2048,
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
            // One descriptor per visitor, plus the endpoint, listeners and the rest.
            let limit = raise_open_file_limit()?;
            info!("open file limit is {limit}");
            let needed = u64::from(max_connections) + 64;
            if needed > limit {
                warn!(
                    "--max-connections {max_connections} needs about {needed} open files, \
                     more than the limit of {limit}: visitors past it will fail to be accepted"
                );
            }
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

/// Raises the soft open-file limit as far as the hard limit allows and returns the soft limit
/// then in force. A failure to raise it is logged and the old limit stays.
fn raise_open_file_limit() -> anyhow::Result<u64> {
    use nix::sys::resource::{Resource, getrlimit, setrlimit};
    let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).context("reading the open file limit")?;
    // macOS refuses a soft limit above OPEN_MAX, which an unlimited hard limit would ask for.
    #[cfg(target_os = "macos")]
    let target = hard.min(10_240);
    #[cfg(not(target_os = "macos"))]
    let target = hard;
    if soft < target
        && let Err(e) = setrlimit(Resource::RLIMIT_NOFILE, target, hard)
    {
        warn!("raising the open file limit from {soft} to {target} failed: {e}");
    }
    let (soft, _) = getrlimit(Resource::RLIMIT_NOFILE).context("reading the open file limit")?;
    Ok(soft)
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
