//! `iroh-gateway-operator`: the private side of the tunnel.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use iroh_gateway_operator::cluster::{StatusWriter, Stores, identity};
use iroh_gateway_operator::controller::{ControllerOptions, run_loop};
use iroh_gateway_operator::engine::{Engine, EngineOptions};
use iroh_gateway_operator::haproxy::SupervisorOptions;
use iroh_gateway_operator::haproxy::render::render;
use iroh_gateway_operator::model::{self, Settings, Snapshot};
use iroh_gateway_operator::staticcfg;
use iroh_gateway_operator::tunnel::{EdgeLink, LinkOptions, StaticConnector, bind_endpoint};
use iroh_gateway_proto::control::ListenerKey;
use iroh_gateway_proto::key::load_or_generate;
use iroh_gateway_proto::transport::Relay;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/// The directory inside `--runtime-dir` that `run` gives HAProxy.
const HAPROXY_DIR: &str = "haproxy";

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
    /// Run as the Gateway API controller of the cluster this runs in.
    Run(RunArgs),
}

#[derive(clap::Args)]
struct RunArgs {
    /// The namespace the operator runs in, which holds its identity Secret.
    #[arg(long, env = "POD_NAMESPACE")]
    namespace: String,
    /// Comma-separated namespaces whose Gateways and Edges are served; defaults to --namespace.
    #[arg(long, env = "IROH_GATEWAY_NAMESPACES")]
    gateway_namespaces: Option<String>,
    /// The controllerName of the GatewayClasses this operator owns.
    #[arg(
        long,
        env = "IROH_GATEWAY_CONTROLLER_NAME",
        default_value = "gateway.fables-for-robots.ch/iroh-gateway"
    )]
    controller_name: String,
    /// The Secret in --namespace that holds the operator's key; created if missing.
    #[arg(
        long,
        env = "IROH_GATEWAY_IDENTITY_SECRET",
        default_value = "iroh-gateway-identity"
    )]
    identity_secret: String,
    /// "disabled", "n0" or an https relay URL; the edges must use the same.
    #[arg(long, env = "IROH_GATEWAY_RELAY", default_value = "disabled")]
    relay: Relay,
    /// A directory the operator may write to; it creates a private `haproxy` directory inside
    /// it for HAProxy's configuration and sockets.
    #[arg(
        long,
        env = "IROH_GATEWAY_RUNTIME_DIR",
        default_value = "/run/iroh-gateway"
    )]
    runtime_dir: PathBuf,
    #[arg(long, env = "IROH_GATEWAY_HAPROXY_BIN", default_value = "haproxy")]
    haproxy_bin: PathBuf,
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
        Command::Run(args) => run_controller(args).await?,
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
    // Each ends when its link's task ends, which before shutdown it never does on its own.
    let mut watchers = JoinSet::new();
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
        watchers.spawn(async move {
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
            id
        });
        desired_senders.push(tx);
        links.push(link);
    }

    tokio::select! {
        r = shutdown_signal() => r?,
        Some(ended) = watchers.join_next() => {
            let edge = ended.map_or_else(|e| e.to_string(), |id| id.fmt_short().to_string());
            error!(%edge, "the link to an edge stopped on its own; exiting");
            bail!("the link to edge {edge} stopped on its own");
        }
    }
    info!("shutting down");
    for link in links {
        link.shutdown().await;
    }
    watchers.abort_all();
    drop(desired_senders);
    endpoint.close().await;
    Ok(())
}

/// The namespaces in a comma-separated list; an empty list or entry is an error.
fn parse_namespaces(list: &str) -> anyhow::Result<BTreeSet<String>> {
    let names: Vec<&str> = list.split(',').map(str::trim).collect();
    if names.iter().any(|n| n.is_empty()) {
        bail!("--gateway-namespaces {list:?} names an empty namespace");
    }
    Ok(names.into_iter().map(str::to_owned).collect())
}

async fn run_controller(args: RunArgs) -> anyhow::Result<()> {
    if args.namespace.is_empty() {
        bail!("--namespace is empty");
    }
    let gateway_namespaces = parse_namespaces(
        args.gateway_namespaces
            .as_deref()
            .unwrap_or(&args.namespace),
    )?;
    let settings = Settings {
        controller_name: args.controller_name.clone(),
        gateway_namespaces,
        relay: args.relay.clone(),
    };
    // First, so that a signal at any point from here on stops the operator cleanly.
    let shutdown = shutdown_signals()?;
    let mut shutdown = pin!(shutdown);
    let limit = raise_open_file_limit()?;
    info!("open file limit is {limit}");

    let client = kube::Client::try_default()
        .await
        .context("no Kubernetes configuration: neither in-cluster nor from a kubeconfig")?;
    let key = tokio::select! {
        key = identity::load_or_create(&client, &args.namespace, &args.identity_secret) => key?,
        () = &mut shutdown => {
            info!("stopped during start-up");
            return Ok(());
        }
    };
    let endpoint = bind_endpoint(key.clone(), &args.relay).await?;
    info!(id = %key.public(), namespaces = ?settings.gateway_namespaces, "operator started");

    // The directory given may belong to someone else (an emptyDir's root belongs to root), so
    // HAProxy gets one of its own inside it, which the supervisor creates and makes private.
    let haproxy_dir = args.runtime_dir.join(HAPROXY_DIR);
    let mut supervisor = SupervisorOptions::new(&haproxy_dir);
    supervisor.haproxy_bin = args.haproxy_bin;
    // Nothing is served until the stores have synced and the first pass has run.
    let initial = render(&model::build(&Snapshot::default(), &settings), &haproxy_dir);
    let started = tokio::select! {
        engine = Engine::start(
            endpoint.clone(),
            EngineOptions::new(supervisor, args.relay),
            initial,
        ) => engine,
        () = &mut shutdown => {
            // Dropping the unfinished start kills the HAProxy it may have started.
            info!("stopped during start-up");
            endpoint.close().await;
            return Ok(());
        }
    };
    let mut engine = started?;
    let stores = Stores::start(client.clone());
    let writer = StatusWriter::new(client, args.controller_name);
    let opts = ControllerOptions::new(settings, &haproxy_dir);
    // A signal that came since the engine started ends the loop at once.
    let ended = run_loop(stores, &mut engine, writer, opts, shutdown).await;
    info!("shutting down");
    engine.shutdown().await;
    endpoint.close().await;
    if let Err(e) = &ended {
        error!("{e:#}");
    }
    ended
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

/// Listens for SIGINT and SIGTERM now; the future resolves on the first of them.
fn shutdown_signals() -> anyhow::Result<impl Future<Output = ()> + Send> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut int = signal(SignalKind::interrupt()).context("listening for SIGINT")?;
    let mut term = signal(SignalKind::terminate()).context("listening for SIGTERM")?;
    Ok(async move {
        tokio::select! {
            _ = int.recv() => {}
            _ = term.recv() => {}
        }
    })
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
