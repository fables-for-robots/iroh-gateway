//! `iroh-gateway-operator`: the private side of the tunnel.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use iroh_gateway_operator::staticcfg;
use iroh_gateway_operator::tunnel::{EdgeLink, LinkOptions, StaticConnector, bind_endpoint};
use iroh_gateway_proto::control::ListenerKey;
use iroh_gateway_proto::key::load_or_generate;
use tokio::sync::watch;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "Private operator of iroh-gateway")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print this operator's EndpointId, creating the key file if it is missing.
    Id {
        #[arg(long, default_value = "operator.key")]
        key_file: PathBuf,
    },
    /// Connect to the edges listed in a configuration file and forward their visitors.
    Static {
        #[arg(long)]
        config: PathBuf,
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
        Command::Static { config } => run_static(config).await?,
    }
    Ok(())
}

async fn run_static(path: PathBuf) -> anyhow::Result<()> {
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let base_dir = path.parent().unwrap_or(Path::new(""));
    let cfg =
        staticcfg::parse(&text, base_dir).with_context(|| format!("in {}", path.display()))?;
    let key = load_or_generate(&cfg.key_file)
        .with_context(|| format!("key file {}", cfg.key_file.display()))?;
    // One descriptor per backend connection, plus the endpoint and the rest.
    let limit = raise_open_file_limit()?;
    info!("open file limit is {limit}");
    let endpoint = bind_endpoint(key.clone(), &cfg.relay).await?;
    info!(id = %key.public(), "operator started");

    let mut links = Vec::new();
    let mut watchers = Vec::new();
    // The senders live until shutdown; the links keep the last desired set anyway.
    let mut desired_senders = Vec::new();
    for edge in cfg.edges {
        let keys: Vec<ListenerKey> = edge
            .listeners
            .iter()
            .map(|l| ListenerKey {
                protocol: l.protocol,
                port: l.port,
            })
            .collect();
        let targets: HashMap<_, _> = edge
            .listeners
            .iter()
            .map(|l| {
                (
                    ListenerKey {
                        protocol: l.protocol,
                        port: l.port,
                    },
                    l.target,
                )
            })
            .collect();
        let opts = LinkOptions::new(edge.endpoint_id, edge.address, cfg.relay.clone())?;
        let (tx, rx) = watch::channel(keys);
        let link = EdgeLink::spawn(
            endpoint.clone(),
            opts,
            rx,
            Arc::new(StaticConnector::new(targets)),
        );
        let mut state = link.state();
        let id = edge.endpoint_id;
        watchers.push(tokio::spawn(async move {
            while state.changed().await.is_ok() {
                let s = state.borrow_and_update().clone();
                let listeners: Vec<String> = s
                    .listeners
                    .iter()
                    .map(|l| match &l.bound {
                        Ok(()) => format!("{:?}/{} bound", l.key.protocol, l.key.port),
                        Err(e) => format!("{:?}/{} error: {e}", l.key.protocol, l.key.port),
                    })
                    .collect();
                info!(
                    edge = %id.fmt_short(),
                    connected = s.connected,
                    version = ?s.edge_version,
                    generation = s.generation,
                    listeners = ?listeners,
                    "edge state"
                );
            }
        }));
        desired_senders.push(tx);
        links.push(link);
    }

    shutdown_signal().await?;
    info!("shutting down");
    for link in links {
        link.shutdown().await;
    }
    for w in watchers {
        w.abort();
    }
    drop(desired_senders);
    endpoint.close().await;
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
