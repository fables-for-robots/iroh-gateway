//! In-memory copies of every resource the model reads, kept current by watches.
//!
//! A store that cannot list (for example because the Gateway API CRDs are not installed) logs a
//! warning at most every 30 s and keeps retrying with the watcher's backoff;
//! [`SnapshotSource::synced`] stays pending until every store has listed once, so nothing is
//! applied meanwhile, and names the stores it is waiting for every 30 s.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::future::pending;
use std::time::Duration;

use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use gateway_api::gatewayclasses::v1::GatewayClass;
use gateway_api::gateways::v1::Gateway;
use gateway_api::httproutes::v1::HttpRoute;
use gateway_api::tcproutes::v1::TcpRoute;
use k8s_openapi::api::core::v1::{Namespace, Secret, Service};
use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, Client, Resource};
use serde::de::DeserializeOwned;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Instant, interval_at};
use tracing::{debug, warn};

use crate::crd::Edge;
use crate::model::Snapshot;

/// The least time between two warnings about the same store's watch failing, and between two
/// warnings about the stores that have not listed yet.
const WARN_EVERY: Duration = Duration::from_secs(30);

/// The only Secrets the operator requests: those that hold a TLS certificate and key.
const TLS_SECRETS: &str = "type=kubernetes.io/tls";

/// Where the reconcile loop gets the cluster's state from.
pub trait SnapshotSource: Send {
    /// Resolves once every store has finished its first list.
    fn synced(&mut self) -> impl Future<Output = ()> + Send;
    fn snapshot(&self) -> Snapshot;
    /// Resolves when any store changed since the last call.
    fn changed(&mut self) -> impl Future<Output = ()> + Send;
}

/// Cluster-wide watches of GatewayClasses, Gateways, TCPRoutes, HTTPRoutes, Edges, Services and
/// Namespaces, and one watch of the Secrets of type `kubernetes.io/tls` in each gateway
/// namespace. Dropping it stops the watches.
///
/// When the operator may not list Secrets in a gateway namespace (for example because no Role
/// there grants it, as when the namespace does not exist yet), that namespace's Secret store
/// does not list until it may, by design: [`SnapshotSource::synced`] keeps waiting and names it
/// (`Secret in <namespace>`) in its warning every 30 s, and nothing is applied meanwhile.
pub struct Stores {
    gateway_classes: Store<GatewayClass>,
    gateways: Store<Gateway>,
    tcp_routes: Store<TcpRoute>,
    http_routes: Store<HttpRoute>,
    edges: Store<Edge>,
    services: Store<Service>,
    namespaces: Store<Namespace>,
    /// The TLS Secrets of each gateway namespace, by namespace.
    secrets: BTreeMap<String, Store<Secret>>,
    changes: watch::Receiver<()>,
    _watches: JoinSet<()>,
}

impl Stores {
    /// One watch per resource kind, cluster-wide, and one watch of TLS Secrets per gateway
    /// namespace. Must be called inside a Tokio runtime.
    pub fn start(client: Client, gateway_namespaces: &BTreeSet<String>) -> Self {
        let (notify, changes) = watch::channel(());
        let mut watches = JoinSet::new();
        let gateway_classes = watch_all(&client, "GatewayClass", &notify, &mut watches);
        let gateways = watch_all(&client, "Gateway", &notify, &mut watches);
        let tcp_routes = watch_all(&client, "TCPRoute", &notify, &mut watches);
        let http_routes = watch_all(&client, "HTTPRoute", &notify, &mut watches);
        let edges = watch_all(&client, "Edge", &notify, &mut watches);
        let services = watch_all(&client, "Service", &notify, &mut watches);
        let namespaces = watch_all(&client, "Namespace", &notify, &mut watches);
        let secrets = gateway_namespaces
            .iter()
            .map(|ns| {
                let store = spawn_watch(
                    format!("Secret in {ns}"),
                    Api::namespaced(client.clone(), ns),
                    watcher::Config::default().fields(TLS_SECRETS),
                    &notify,
                    &mut watches,
                );
                (ns.clone(), store)
            })
            .collect();
        Self {
            gateway_classes,
            gateways,
            tcp_routes,
            http_routes,
            edges,
            services,
            namespaces,
            secrets,
            changes,
            _watches: watches,
        }
    }
}

impl SnapshotSource for Stores {
    async fn synced(&mut self) {
        let mut waits = vec![
            ready("GatewayClass", &self.gateway_classes),
            ready("Gateway", &self.gateways),
            ready("TCPRoute", &self.tcp_routes),
            ready("HTTPRoute", &self.http_routes),
            ready("Edge", &self.edges),
            ready("Service", &self.services),
            ready("Namespace", &self.namespaces),
        ];
        for (ns, store) in &self.secrets {
            waits.push(ready(format!("Secret in {ns}"), store));
        }
        wait_all(waits, WARN_EVERY, |pending| {
            warn!(
                "still waiting for the first list of: {}",
                pending.join(", ")
            );
        })
        .await;
        // The snapshot taken next holds everything up to now.
        self.changes.mark_unchanged();
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            gateway_classes: cloned(&self.gateway_classes),
            gateways: cloned(&self.gateways),
            tcp_routes: cloned(&self.tcp_routes),
            http_routes: cloned(&self.http_routes),
            edges: cloned(&self.edges),
            services: cloned(&self.services),
            namespaces: cloned(&self.namespaces),
            secrets: self.secrets.values().flat_map(cloned).collect(),
        }
    }

    async fn changed(&mut self) {
        if self.changes.changed().await.is_err() {
            pending::<()>().await;
        }
    }
}

/// `store`'s first list, named `name`.
fn ready<K>(name: impl Into<String>, store: &Store<K>) -> (String, BoxFuture<'_, ()>)
where
    K: Resource<DynamicType = ()> + Clone + Send + Sync + 'static,
{
    let wait = async move {
        if store.wait_until_ready().await.is_err() {
            // A watch task ended, which happens only when the stores are being dropped.
            pending::<()>().await;
        }
    };
    (name.into(), wait.boxed())
}

/// Waits for every named future; while some are pending, calls `report` with their names every
/// `every`.
pub(crate) async fn wait_all(
    waits: Vec<(String, BoxFuture<'_, ()>)>,
    every: Duration,
    mut report: impl FnMut(&[String]),
) {
    let mut names: BTreeMap<usize, String> = BTreeMap::new();
    let mut running = FuturesUnordered::new();
    for (i, (name, wait)) in waits.into_iter().enumerate() {
        names.insert(i, name);
        running.push(wait.map(move |()| i));
    }
    let mut ticks = interval_at(Instant::now() + every, every);
    loop {
        tokio::select! {
            // What finished at the same instant as a tick is not reported.
            biased;
            done = running.next() => match done {
                Some(i) => {
                    names.remove(&i);
                }
                None => return,
            },
            _ = ticks.tick() => {
                let pending: Vec<String> = names.values().cloned().collect();
                report(&pending);
            }
        }
    }
}

fn cloned<K: Resource + Clone>(store: &Store<K>) -> Vec<K>
where
    K::DynamicType: std::hash::Hash + Eq + Clone,
{
    store.state().iter().map(|k| (**k).clone()).collect()
}

/// Spawns a watch of every `K` in the cluster; see [`spawn_watch`].
fn watch_all<K>(
    client: &Client,
    kind: &str,
    notify: &watch::Sender<()>,
    tasks: &mut JoinSet<()>,
) -> Store<K>
where
    K: Resource<DynamicType = ()> + Clone + DeserializeOwned + Debug + Send + Sync + 'static,
{
    let api = Api::all(client.clone());
    spawn_watch(kind, api, watcher::Config::default(), notify, tasks)
}

/// Spawns a watch of what `api` and `config` select that fills the returned store and sends on
/// `notify` whenever the store's contents changed. Only the watch's `name` and its errors are
/// logged, never an object: a Secret's `Debug` prints its data.
fn spawn_watch<K>(
    name: impl Into<String>,
    api: Api<K>,
    config: watcher::Config,
    notify: &watch::Sender<()>,
    tasks: &mut JoinSet<()>,
) -> Store<K>
where
    K: Resource<DynamicType = ()> + Clone + DeserializeOwned + Debug + Send + Sync + 'static,
{
    let name = name.into();
    let (reader, writer) = reflector::store();
    let stream = watcher(api, config).default_backoff().reflect(writer);
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
                        warn!(watch = %name, "watch failed, retrying: {e}");
                        last_warning = Some(Instant::now());
                    } else {
                        debug!(watch = %name, "watch failed, retrying: {e}");
                    }
                }
            }
        }
    });
    reader
}

#[cfg(test)]
mod tests {
    use futures::FutureExt;
    use tokio::time::sleep;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn wait_all_reports_what_is_still_pending() {
        let start = Instant::now();
        let mut reports: Vec<(Duration, Vec<String>)> = Vec::new();
        wait_all(
            vec![
                ("a".to_owned(), async {}.boxed()),
                ("b".to_owned(), sleep(Duration::from_secs(70)).boxed()),
            ],
            Duration::from_secs(30),
            |pending| reports.push((start.elapsed(), pending.to_vec())),
        )
        .await;
        assert_eq!(start.elapsed(), Duration::from_secs(70));
        assert_eq!(
            reports,
            [
                (Duration::from_secs(30), vec!["b".to_owned()]),
                (Duration::from_secs(60), vec!["b".to_owned()]),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn wait_all_reports_nothing_when_all_are_ready() {
        let start = Instant::now();
        let mut reports: Vec<Vec<String>> = Vec::new();
        wait_all(
            vec![
                ("a".to_owned(), async {}.boxed()),
                ("b".to_owned(), async {}.boxed()),
            ],
            Duration::from_secs(30),
            |pending| reports.push(pending.to_vec()),
        )
        .await;
        wait_all(Vec::new(), Duration::from_secs(30), |pending| {
            reports.push(pending.to_vec())
        })
        .await;
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert!(reports.is_empty(), "{reports:?}");
    }
}
