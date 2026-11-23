//! In-memory copies of every resource the model reads, kept current by watches.
//!
//! A store that cannot list (for example because the Gateway API CRDs are not installed) logs a
//! warning at most every 30 s and keeps retrying with the watcher's backoff;
//! [`SnapshotSource::synced`] stays pending until every store has listed once, so nothing is
//! applied meanwhile.

use std::fmt::Debug;
use std::future::pending;
use std::time::Duration;

use futures::StreamExt;
use gateway_api::gatewayclasses::v1::GatewayClass;
use gateway_api::gateways::v1::Gateway;
use gateway_api::tcproutes::v1::TcpRoute;
use k8s_openapi::api::core::v1::{Namespace, Service};
use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, Client, Resource};
use serde::de::DeserializeOwned;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::crd::Edge;
use crate::model::Snapshot;

/// The least time between two warnings about the same store's watch failing.
const WARN_EVERY: Duration = Duration::from_secs(30);

/// Where the reconcile loop gets the cluster's state from.
pub trait SnapshotSource: Send {
    /// Resolves once every store has finished its first list.
    fn synced(&mut self) -> impl Future<Output = ()> + Send;
    fn snapshot(&self) -> Snapshot;
    /// Resolves when any store changed since the last call.
    fn changed(&mut self) -> impl Future<Output = ()> + Send;
}

/// Cluster-wide watches of GatewayClasses, Gateways, TCPRoutes, Edges, Services and Namespaces.
/// Dropping it stops the watches.
pub struct Stores {
    gateway_classes: Store<GatewayClass>,
    gateways: Store<Gateway>,
    tcp_routes: Store<TcpRoute>,
    edges: Store<Edge>,
    services: Store<Service>,
    namespaces: Store<Namespace>,
    changes: watch::Receiver<()>,
    _watches: JoinSet<()>,
}

impl Stores {
    /// Starts one watch per resource. Must be called inside a Tokio runtime.
    pub fn start(client: Client) -> Self {
        let (notify, changes) = watch::channel(());
        let mut watches = JoinSet::new();
        Self {
            gateway_classes: watch_all(&client, "GatewayClass", &notify, &mut watches),
            gateways: watch_all(&client, "Gateway", &notify, &mut watches),
            tcp_routes: watch_all(&client, "TCPRoute", &notify, &mut watches),
            edges: watch_all(&client, "Edge", &notify, &mut watches),
            services: watch_all(&client, "Service", &notify, &mut watches),
            namespaces: watch_all(&client, "Namespace", &notify, &mut watches),
            changes,
            _watches: watches,
        }
    }
}

impl SnapshotSource for Stores {
    async fn synced(&mut self) {
        let ready = tokio::try_join!(
            self.gateway_classes.wait_until_ready(),
            self.gateways.wait_until_ready(),
            self.tcp_routes.wait_until_ready(),
            self.edges.wait_until_ready(),
            self.services.wait_until_ready(),
            self.namespaces.wait_until_ready(),
        );
        if ready.is_err() {
            // A watch task ended, which happens only when the stores are being dropped.
            pending::<()>().await;
        }
        // The snapshot taken next holds everything up to now.
        self.changes.mark_unchanged();
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            gateway_classes: cloned(&self.gateway_classes),
            gateways: cloned(&self.gateways),
            tcp_routes: cloned(&self.tcp_routes),
            edges: cloned(&self.edges),
            services: cloned(&self.services),
            namespaces: cloned(&self.namespaces),
        }
    }

    async fn changed(&mut self) {
        if self.changes.changed().await.is_err() {
            pending::<()>().await;
        }
    }
}

fn cloned<K: Resource + Clone>(store: &Store<K>) -> Vec<K>
where
    K::DynamicType: std::hash::Hash + Eq + Clone,
{
    store.state().iter().map(|k| (**k).clone()).collect()
}

/// Spawns a watch of every `K` in the cluster that fills the returned store and sends on
/// `notify` whenever the store's contents changed.
fn watch_all<K>(
    client: &Client,
    kind: &'static str,
    notify: &watch::Sender<()>,
    tasks: &mut JoinSet<()>,
) -> Store<K>
where
    K: Resource<DynamicType = ()> + Clone + DeserializeOwned + Debug + Send + Sync + 'static,
{
    let (reader, writer) = reflector::store();
    let stream = watcher(Api::<K>::all(client.clone()), watcher::Config::default())
        .default_backoff()
        .reflect(writer);
    let notify = notify.clone();
    tasks.spawn(async move {
        let mut stream = std::pin::pin!(stream);
        let mut last_warning: Option<Instant> = None;
        while let Some(event) = stream.next().await {
            match event {
                // The reflector buffers a relist until it is complete; the store is unchanged.
                Ok(watcher::Event::Init | watcher::Event::InitApply(_)) => {}
                Ok(_) => {
                    notify.send_replace(());
                }
                Err(e) => {
                    if last_warning.is_none_or(|at| at.elapsed() >= WARN_EVERY) {
                        warn!(kind, "watch failed, retrying: {e}");
                        last_warning = Some(Instant::now());
                    } else {
                        debug!(kind, "watch failed, retrying: {e}");
                    }
                }
            }
        }
    });
    reader
}
