//! `iroh-gateway-operator`: the private side of the tunnel.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use iroh_gateway_operator::staticcfg;
use iroh_gateway_operator::tunnel::{EdgeLink, LinkOptions, StaticConnector, bind_endpoint};
use iroh_gateway_proto::control::ListenerKey;
use iroh_gateway_proto::key::load_or_generate;
use tokio::sync::watch;
use tracing::info;
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
    let cfg = staticcfg::parse(&text).with_context(|| format!("in {}", path.display()))?;
    let key = load_or_generate(&cfg.key_file)
        .with_context(|| format!("key file {}", cfg.key_file.display()))?;
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
