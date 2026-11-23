//! Applies a [`Rendered`] to the running system: HAProxy first, then one link per edge.
//!
//! The rule everything here follows: an edge opens a public port only after HAProxy serves the
//! socket behind it, and an edge that left the plan loses its link whatever HAProxy does.

use std::collections::{BTreeMap, HashMap};
use std::future::poll_fn;
use std::path::PathBuf;
use std::pin::{Pin, pin};
use std::process::ExitStatus;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use iroh::{Endpoint, EndpointId};
use iroh_gateway_proto::control::{ListenerKey, Protocol};
use iroh_gateway_proto::transport::Relay;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until};
use tracing::{error, info, warn};

use crate::haproxy::render::{EdgePlan, PortPlan, Rendered};
use crate::haproxy::{ApplyError, Supervisor, SupervisorOptions};
use crate::model::ObjRef;
use crate::status::Facts;
use crate::tunnel::{
    EdgeLink, EdgeState, HaproxyConnector, LinkHandle, LinkOptions, truncate_status_text,
};

/// Default for [`EngineOptions::retry`].
pub const DEFAULT_RETRY: Duration = Duration::from_secs(5);

pub struct EngineOptions {
    pub supervisor: SupervisorOptions,
    /// The operator's relay mode, which every link dials with.
    pub relay: Relay,
    /// After a reload that failed with its outcome unknown, how long until [`Engine::next_event`]
    /// asks for another pass.
    pub retry: Duration,
}

impl EngineOptions {
    /// Options with [`DEFAULT_RETRY`].
    pub fn new(supervisor: SupervisorOptions, relay: Relay) -> Self {
        Self {
            supervisor,
            relay,
            retry: DEFAULT_RETRY,
        }
    }
}

/// What [`Engine::next_event`] resolves with.
#[derive(Debug)]
pub enum EngineEvent {
    /// A link's state changed, or another pass is due after a failed reload.
    Changed,
    /// HAProxy ended on its own.
    HaproxyExited(ExitStatus),
}

/// HAProxy and the links to the edges, driven by renders.
pub struct Engine {
    endpoint: Endpoint,
    relay: Relay,
    retry: Duration,
    supervisor: Supervisor,
    /// The result of the last HAProxy apply.
    haproxy: Result<(), String>,
    links: BTreeMap<ObjRef, Running>,
    /// Plans no link can be made for, with the state that says why.
    unreachable: BTreeMap<ObjRef, EdgeState>,
    /// When [`Engine::next_event`] asks for another pass after a failed reload.
    retry_at: Option<Instant>,
}

/// One running link and what it was started with.
struct Running {
    endpoint_id: EndpointId,
    address: Option<String>,
    handle: LinkHandle,
    state: watch::Receiver<EdgeState>,
    desired: watch::Sender<Vec<ListenerKey>>,
    connector: Arc<HaproxyConnector>,
    /// The ports in the table `connector` was last given, which are also the ports this link
    /// asks its edge for (once published).
    sockets: HashMap<ListenerKey, PortPlan>,
    /// The ports of this link in the last plan HAProxy loaded.
    loaded: HashMap<ListenerKey, PortPlan>,
}

impl Engine {
    /// Starts HAProxy with `initial.haproxy_cfg`, then applies `initial` as `apply` does.
    pub async fn start(
        endpoint: iroh::Endpoint,
        opts: EngineOptions,
        initial: Rendered,
    ) -> anyhow::Result<Self> {
        let supervisor = Supervisor::start(opts.supervisor, &initial.haproxy_cfg).await?;
        let mut engine = Self {
            endpoint,
            relay: opts.relay,
            retry: opts.retry,
            supervisor,
            haproxy: Ok(()),
            links: BTreeMap::new(),
            unreachable: BTreeMap::new(),
            retry_at: None,
        };
        engine.note_unreachable(&initial.edges);
        engine.program(&initial.edges);
        Ok(engine)
    }

    /// Applies `rendered`: HAProxy's configuration, and the links of the edges in it.
    ///
    /// Links of edges that left the plan, or whose id or address changed, are shut down in any
    /// case. While HAProxy reloads, each remaining link forwards only on the ports whose
    /// [`PortPlan`] (socket and fingerprint) in the new plan is the one HAProxy last loaded.
    /// Only when HAProxy took the configuration are links started and ports added; when it did
    /// not, each link keeps only those unchanged ports.
    ///
    /// Not meant to be cancelled, and the reconcile loop never cancels it. A cancelled call can
    /// leave the links of the edges that left the plan removed while the other links keep their
    /// old socket tables, and HAProxy may already run the new configuration.
    pub async fn apply(&mut self, rendered: Rendered) {
        let gone: Vec<ObjRef> = self
            .links
            .iter()
            .filter(|(key, link)| {
                !rendered.edges.iter().any(|plan| {
                    &plan.key == *key
                        && plan.endpoint_id == link.endpoint_id
                        && plan.address == link.address
                })
            })
            .map(|(key, _)| key.clone())
            .collect();
        let gone: Vec<(ObjRef, Running)> = gone
            .into_iter()
            .filter_map(|key| self.links.remove_entry(&key))
            .collect();
        for (key, _) in &gone {
            info!(edge = %key, "stopping the link");
        }
        // Until HAProxy has the new configuration, a visitor on a port that is moving or going
        // away is refused rather than delivered to what is behind its socket now. The ports
        // asked of the edges stay as they are until the outcome is known.
        for plan in &rendered.edges {
            if let Some(link) = self.links.get_mut(&plan.key) {
                link.keep_unchanged(plan);
            }
        }
        let (applied, ()) = tokio::join!(
            self.supervisor.apply(&rendered.haproxy_cfg),
            stop_links(gone.into_iter().map(|(_, link)| link.handle))
        );
        self.note_unreachable(&rendered.edges);
        match applied {
            Ok(_) => {
                self.haproxy = Ok(());
                self.retry_at = None;
                self.program(&rendered.edges);
            }
            Err(e) => {
                warn!(error = %e, "haproxy did not take the configuration; adding nothing");
                self.retry_at = matches!(e, ApplyError::ReloadFailed(_) | ApplyError::Io(_))
                    .then(|| Instant::now() + self.retry);
                self.haproxy = Err(e.to_string());
                self.cut_down(&rendered.edges);
            }
        }
    }

    pub fn facts(&self) -> Facts {
        let mut edges = self.unreachable.clone();
        edges.extend(
            self.links
                .iter()
                .map(|(key, link)| (key.clone(), observed(&link.state))),
        );
        Facts {
            operator_id: self.endpoint.id(),
            haproxy: self.haproxy.clone(),
            edges,
        }
    }

    /// Resolves with `Changed` when any link's state changed since the last `Changed` was returned
    /// or when a retry is due, and with `HaproxyExited` if HAProxy ends on its own.
    ///
    /// HAProxy's exit is checked first: once it has ended, every later call returns
    /// `HaproxyExited` again at once, with the same status. Cancel-safe: dropping the future loses
    /// neither a change nor the exit.
    pub async fn next_event(&mut self) -> EngineEvent {
        let retry_at = self.retry_at;
        let event = {
            let mut exited = pin!(self.supervisor.exited());
            let mut waits: Vec<Pin<Box<dyn Future<Output = ()> + Send + '_>>> = self
                .links
                .values_mut()
                // A closed channel would resolve at once, every time; its link has ended.
                .filter(|link| link.state.has_changed().is_ok())
                .map(|link| {
                    Box::pin(async {
                        let _ = link.state.changed().await;
                    }) as Pin<Box<dyn Future<Output = ()> + Send + '_>>
                })
                .collect();
            if let Some(at) = retry_at {
                waits.push(Box::pin(sleep_until(at)));
            }
            poll_fn(|cx| {
                if let Poll::Ready(status) = exited.as_mut().poll(cx) {
                    Poll::Ready(EngineEvent::HaproxyExited(status))
                } else if waits.iter_mut().any(|w| w.as_mut().poll(cx).is_ready()) {
                    Poll::Ready(EngineEvent::Changed)
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        if let EngineEvent::Changed = event {
            // The caller reads the facts next, which include every state up to now.
            for link in self.links.values_mut() {
                link.state.mark_unchanged();
            }
            if self.retry_at.is_some_and(|at| at <= Instant::now()) {
                self.retry_at = None;
            }
        }
        event
    }

    /// The HAProxy master's process id.
    pub fn haproxy_pid(&self) -> u32 {
        self.supervisor.pid()
    }

    /// Stops every link, then HAProxy.
    pub async fn shutdown(self) {
        stop_links(self.links.into_values().map(|link| link.handle)).await;
        self.supervisor.shutdown().await;
    }

    /// Records the plans no link can be made for, logging those that are new.
    fn note_unreachable(&mut self, plans: &[EdgePlan]) {
        let mut unreachable = BTreeMap::new();
        for plan in plans {
            if let Err(e) = self.link_options(plan) {
                let why = truncate_status_text(&format!("{e:#}"));
                if self
                    .unreachable
                    .get(&plan.key)
                    .and_then(|s| s.last_error.as_ref())
                    != Some(&why)
                {
                    warn!(edge = %plan.key, "not linking: {why}");
                }
                let state = EdgeState {
                    last_error: Some(why),
                    ..EdgeState::default()
                };
                unreachable.insert(plan.key.clone(), state);
            }
        }
        self.unreachable = unreachable;
    }

    fn link_options(&self, plan: &EdgePlan) -> anyhow::Result<LinkOptions> {
        LinkOptions::new(plan.endpoint_id, plan.address.clone(), self.relay.clone())
    }

    /// After HAProxy took the configuration: socket tables first, then missing links, then the
    /// listeners each link asks its edge for.
    fn program(&mut self, plans: &[EdgePlan]) {
        let mut new = Vec::new();
        for plan in plans {
            match self.links.get_mut(&plan.key) {
                Some(link) => {
                    link.set_sockets(plan.sockets.clone());
                    link.loaded = plan.sockets.clone();
                }
                None => {
                    if let Ok(opts) = self.link_options(plan) {
                        let connector = Arc::new(HaproxyConnector::new());
                        connector.set(paths(&plan.sockets));
                        new.push((plan, opts, connector));
                    }
                }
            }
        }
        for (plan, opts, connector) in new {
            info!(edge = %plan.key, "starting the link");
            let (desired, desired_rx) = watch::channel(Vec::new());
            let handle =
                EdgeLink::spawn(self.endpoint.clone(), opts, desired_rx, connector.clone());
            let link = Running {
                endpoint_id: plan.endpoint_id,
                address: plan.address.clone(),
                state: handle.state(),
                handle,
                desired,
                connector,
                sockets: plan.sockets.clone(),
                loaded: plan.sockets.clone(),
            };
            self.links.insert(plan.key.clone(), link);
        }
        for plan in plans {
            if let Some(link) = self.links.get(&plan.key) {
                link.publish();
            }
        }
    }

    /// After HAProxy refused the configuration: each link keeps only the ports whose
    /// [`PortPlan`] in the new plan is the one HAProxy last loaded; nothing is added.
    fn cut_down(&mut self, plans: &[EdgePlan]) {
        for plan in plans {
            if let Some(link) = self.links.get_mut(&plan.key) {
                link.keep_unchanged(plan);
                link.publish();
            }
        }
    }
}

/// `last_error` of a link whose task has ended although it was not shut down.
const LINK_STOPPED: &str = "the link stopped unexpectedly";

/// A link's state as the facts report it: as last sent, or, once its task has ended and the
/// channel is closed, not connected with [`LINK_STOPPED`].
fn observed(state: &watch::Receiver<EdgeState>) -> EdgeState {
    if state.has_changed().is_err() {
        return EdgeState {
            last_error: Some(LINK_STOPPED.to_owned()),
            ..EdgeState::default()
        };
    }
    state.borrow().clone()
}

/// The socket of each port, as the connector takes them.
fn paths(sockets: &HashMap<ListenerKey, PortPlan>) -> HashMap<ListenerKey, PathBuf> {
    sockets
        .iter()
        .map(|(key, port)| (*key, port.socket.clone()))
        .collect()
}

impl Running {
    fn set_sockets(&mut self, sockets: HashMap<ListenerKey, PortPlan>) {
        self.connector.set(paths(&sockets));
        self.sockets = sockets;
    }

    /// Cuts the table to the ports whose [`PortPlan`] in `plan` is the one HAProxy last loaded.
    fn keep_unchanged(&mut self, plan: &EdgePlan) {
        let kept = self
            .sockets
            .iter()
            .filter(|(key, _)| {
                plan.sockets
                    .get(key)
                    .is_some_and(|port| self.loaded.get(key) == Some(port))
            })
            .map(|(key, port)| (*key, port.clone()))
            .collect();
        self.set_sockets(kept);
    }

    /// Asks the edge for the ports in the socket table, sorted by port.
    fn publish(&self) {
        let mut keys: Vec<ListenerKey> = self.sockets.keys().copied().collect();
        keys.sort_by_key(|k| (k.port, k.protocol == Protocol::Udp));
        self.desired.send_if_modified(|desired| {
            let changed = *desired != keys;
            *desired = keys;
            changed
        });
    }
}

/// Shuts the links down concurrently and waits for all of them.
async fn stop_links(links: impl IntoIterator<Item = LinkHandle>) {
    let mut stopping = JoinSet::new();
    for link in links {
        stopping.spawn(link.shutdown());
    }
    while let Some(done) = stopping.join_next().await {
        if let Err(e) = done {
            error!("a link failed while stopping: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::ListenerState;

    #[test]
    fn a_link_whose_task_ended_is_reported_stopped() {
        let up = EdgeState {
            connected: true,
            generation: 3,
            listeners: vec![ListenerState {
                key: ListenerKey {
                    protocol: Protocol::Tcp,
                    port: 80,
                },
                bound: Ok(()),
            }],
            ..EdgeState::default()
        };
        let (tx, rx) = watch::channel(up.clone());
        assert_eq!(observed(&rx), up);
        drop(tx);
        let stopped = observed(&rx);
        assert!(!stopped.connected);
        assert!(stopped.listeners.is_empty());
        assert_eq!(stopped.last_error.as_deref(), Some(LINK_STOPPED));
    }
}
