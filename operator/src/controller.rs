//! The reconcile loop: snapshot, model, render, apply, status, and again on every change.

use std::path::PathBuf;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::bail;
use tokio::time::{Instant, sleep_until};

use crate::cluster::{SnapshotSource, StatusSink};
use crate::engine::{Engine, EngineEvent};
use crate::haproxy::render::{Rendered, render};
use crate::metrics::Metrics;
use crate::model::{self, Settings};
use crate::status::listing::{Listing, views};
use crate::status::{self, Facts};

/// Default for [`ControllerOptions::debounce`].
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(200);
/// Default for [`ControllerOptions::status_retry_min`].
pub const DEFAULT_STATUS_RETRY_MIN: Duration = Duration::from_secs(5);
/// Default for [`ControllerOptions::status_retry_max`].
pub const DEFAULT_STATUS_RETRY_MAX: Duration = Duration::from_secs(60);
/// Default for [`ControllerOptions::address_grace`].
pub const DEFAULT_ADDRESS_GRACE: Duration = Duration::from_secs(30);

pub struct ControllerOptions {
    pub settings: Settings,
    /// HAProxy's runtime directory, which the render names sockets in.
    pub runtime_dir: PathBuf,
    /// After the first change, how long further changes are absorbed into the same pass.
    pub debounce: Duration,
    /// After a pass whose status write failed, how long until the next pass even if nothing
    /// changed. Doubles after each consecutive failing pass, up to `status_retry_max`.
    pub status_retry_min: Duration,
    pub status_retry_max: Duration,
    /// How long a Gateway keeps listing the addresses of an edge whose link has dropped, so that
    /// a link that reconnects does not change the Gateway's addresses. Zero withdraws at once.
    pub address_grace: Duration,
    /// Where the loop counts and times its passes and counts failed status writes.
    pub metrics: Metrics,
    /// Set once the first pass's apply has returned, whatever HAProxy made of it; never unset.
    pub ready: Arc<AtomicBool>,
}

impl ControllerOptions {
    /// Options with [`DEFAULT_DEBOUNCE`], [`DEFAULT_STATUS_RETRY_MIN`],
    /// [`DEFAULT_STATUS_RETRY_MAX`], [`DEFAULT_ADDRESS_GRACE`], metrics of their own, and not
    /// ready.
    pub fn new(settings: Settings, runtime_dir: impl Into<PathBuf>) -> Self {
        Self {
            settings,
            runtime_dir: runtime_dir.into(),
            debounce: DEFAULT_DEBOUNCE,
            status_retry_min: DEFAULT_STATUS_RETRY_MIN,
            status_retry_max: DEFAULT_STATUS_RETRY_MAX,
            address_grace: DEFAULT_ADDRESS_GRACE,
            metrics: Metrics::new(),
            ready: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// What the loop drives: HAProxy and the edge links. Implemented by [`Engine`].
pub trait Applier: Send {
    fn apply(&mut self, rendered: Rendered) -> impl Future<Output = ()> + Send;
    fn facts(&self) -> Facts;
    /// Resolves when a link changed or a retry is due, or when HAProxy ended on its own.
    fn next_event(&mut self) -> impl Future<Output = EngineEvent> + Send;
}

impl Applier for Engine {
    fn apply(&mut self, rendered: Rendered) -> impl Future<Output = ()> + Send {
        Engine::apply(self, rendered)
    }

    fn facts(&self) -> Facts {
        Engine::facts(self)
    }

    fn next_event(&mut self) -> impl Future<Output = EngineEvent> + Send {
        Engine::next_event(self)
    }
}

/// Lets the caller keep the applier, to shut it down after the loop.
impl<A: Applier> Applier for &mut A {
    fn apply(&mut self, rendered: Rendered) -> impl Future<Output = ()> + Send {
        (**self).apply(rendered)
    }

    fn facts(&self) -> Facts {
        (**self).facts()
    }

    fn next_event(&mut self) -> impl Future<Output = EngineEvent> + Send {
        (**self).next_event()
    }
}

/// Runs until `shutdown` resolves (Ok) or HAProxy dies (Err).
///
/// Nothing is applied before every store has finished its first list. Then one pass runs, and
/// another after each change in the stores or in the applier, once the status retry delay has
/// passed after a pass whose status write failed, or when the address grace of a disconnected
/// edge ends (see [`Listing`]); changes that arrive within `debounce` of the first trigger are
/// taken in the same pass. A pass's apply is never interrupted; its
/// status write is cut short by `shutdown`, which is otherwise noticed between passes.
///
/// Each pass that completes is counted and timed, from taking the snapshot to the end of its
/// status write, in [`ControllerOptions::metrics`]. [`ControllerOptions::ready`] is set once the
/// first pass's apply has returned.
pub async fn run_loop(
    mut source: impl SnapshotSource,
    mut applier: impl Applier,
    mut sink: impl StatusSink,
    opts: ControllerOptions,
    shutdown: impl Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    let mut shutdown = pin!(shutdown);

    // Wait for the first full list. Link changes cannot happen yet; HAProxy may still die.
    loop {
        tokio::select! {
            () = source.synced() => break,
            event = applier.next_event() => check(event)?,
            () = &mut shutdown => return Ok(()),
        }
    }

    // The delay before the next pass while status writes keep failing.
    let mut status_retry: Option<Duration> = None;
    let control = opts.metrics.control();
    let mut listing = Listing::new(opts.address_grace);
    loop {
        let started = Instant::now();
        let snapshot = source.snapshot();
        let model = model::build(&snapshot, &opts.settings);
        applier.apply(render(&model, &opts.runtime_dir)).await;
        opts.ready.store(true, Ordering::Release);
        let facts = applier.facts();
        let listed = listing.update(Instant::now(), &views(&model, &facts, &snapshot));
        let desired = status::compute(&model, &facts, &listed);
        // Each status request has a timeout, but the write is still raced against shutdown: a
        // pass with many slow writes would otherwise hold up SIGTERM.
        let written = tokio::select! {
            written = sink.write(&desired, &snapshot) => written,
            () = &mut shutdown => return Ok(()),
        };
        control.reconciles.inc();
        control
            .reconcile_duration
            .observe(started.elapsed().as_secs_f64());
        if !written {
            control.status_write_failures.inc();
        }
        status_retry = (!written).then(|| match status_retry {
            None => opts.status_retry_min,
            Some(delay) => (delay * 2).min(opts.status_retry_max),
        });
        let retry_at = status_retry.map(|delay| Instant::now() + delay);

        tokio::select! {
            () = source.changed() => {}
            event = applier.next_event() => check(event)?,
            () = sleep_until_some(retry_at) => {}
            // A held edge's grace ends: the next pass withdraws its addresses.
            () = sleep_until_some(listing.next_expiry()) => {}
            () = &mut shutdown => return Ok(()),
        }
        let deadline = Instant::now() + opts.debounce;
        loop {
            tokio::select! {
                () = sleep_until(deadline) => break,
                () = source.changed() => {}
                event = applier.next_event() => check(event)?,
                () = &mut shutdown => return Ok(()),
            }
        }
    }
}

/// Sleeps until `at`, or forever when there is none.
async fn sleep_until_some(at: Option<Instant>) {
    match at {
        Some(at) => sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Ok for a change, an error once HAProxy has exited.
fn check(event: EngineEvent) -> anyhow::Result<()> {
    match event {
        EngineEvent::Changed => Ok(()),
        EngineEvent::HaproxyExited(status) => bail!("haproxy exited on its own ({status})"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::future::pending;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use tokio::sync::{mpsc, oneshot, watch};
    use tokio::task::JoinHandle;
    use tokio::time::sleep;

    use super::*;
    use crate::model::fixtures::{edge, settings};
    use crate::model::{ObjRef, Snapshot};
    use crate::status::DesiredStatus;
    use crate::tunnel::EdgeState;

    fn id(seed: u8) -> iroh::EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn facts(seed: u8) -> Facts {
        Facts {
            operator_id: id(seed),
            haproxy: Ok(()),
            edges: BTreeMap::new(),
        }
    }

    /// Stores that sync when told to and change when told to. Like the real stores, changes
    /// that arrive before the sync are part of the first snapshot.
    struct FakeSource {
        synced: watch::Receiver<bool>,
        changes: mpsc::UnboundedReceiver<()>,
        snapshot: Snapshot,
    }

    impl SnapshotSource for FakeSource {
        async fn synced(&mut self) {
            if self.synced.wait_for(|s| *s).await.is_err() {
                pending::<()>().await;
            }
            while self.changes.try_recv().is_ok() {}
        }

        fn snapshot(&self) -> Snapshot {
            self.snapshot.clone()
        }

        async fn changed(&mut self) {
            if self.changes.recv().await.is_none() {
                pending::<()>().await;
            }
        }
    }

    struct FakeApplier {
        applies: Arc<Mutex<usize>>,
        facts: Arc<Mutex<Facts>>,
        events: mpsc::UnboundedReceiver<EngineEvent>,
    }

    impl Applier for FakeApplier {
        async fn apply(&mut self, _rendered: Rendered) {
            *self.applies.lock().unwrap() += 1;
        }

        fn facts(&self) -> Facts {
            self.facts.lock().unwrap().clone()
        }

        async fn next_event(&mut self) -> EngineEvent {
            match self.events.recv().await {
                Some(event) => event,
                None => pending().await,
            }
        }
    }

    /// Records each write and when it happened; answers from `results`, true once it is empty.
    /// While `hang` is set, a write is recorded and then never returns.
    struct FakeSink {
        writes: Arc<Mutex<Vec<DesiredStatus>>>,
        times: Arc<Mutex<Vec<Instant>>>,
        results: Arc<Mutex<VecDeque<bool>>>,
        hang: Arc<AtomicBool>,
    }

    impl StatusSink for FakeSink {
        async fn write(&mut self, desired: &DesiredStatus, _snapshot: &Snapshot) -> bool {
            self.writes.lock().unwrap().push(desired.clone());
            self.times.lock().unwrap().push(Instant::now());
            if self.hang.load(Ordering::SeqCst) {
                pending::<()>().await;
            }
            self.results.lock().unwrap().pop_front().unwrap_or(true)
        }
    }

    /// A running loop over fakes, and the handles that drive and observe it.
    struct Rig {
        sync: watch::Sender<bool>,
        changes: mpsc::UnboundedSender<()>,
        events: mpsc::UnboundedSender<EngineEvent>,
        facts: Arc<Mutex<Facts>>,
        applies: Arc<Mutex<usize>>,
        writes: Arc<Mutex<Vec<DesiredStatus>>>,
        times: Arc<Mutex<Vec<Instant>>>,
        results: Arc<Mutex<VecDeque<bool>>>,
        hang: Arc<AtomicBool>,
        /// The loop's [`ControllerOptions::metrics`] and [`ControllerOptions::ready`].
        metrics: Metrics,
        ready: Arc<AtomicBool>,
        shutdown: Option<oneshot::Sender<()>>,
        task: JoinHandle<anyhow::Result<()>>,
    }

    impl Rig {
        /// One edge in namespace `gw`, so the desired status carries the operator's id.
        fn start() -> Self {
            Self::start_with(&[], |_| {})
        }

        /// [`Rig::start`] with the sink answering `results` first, and changed options.
        fn start_with(results: &[bool], customize: impl FnOnce(&mut ControllerOptions)) -> Self {
            let snapshot = Snapshot {
                edges: vec![edge("gw", "e1", 7)],
                ..Snapshot::default()
            };
            Self::start_from(snapshot, results, customize)
        }

        /// A loop over `snapshot`, which never changes.
        fn start_from(
            snapshot: Snapshot,
            results: &[bool],
            customize: impl FnOnce(&mut ControllerOptions),
        ) -> Self {
            let (sync, synced) = watch::channel(false);
            let (changes, changes_rx) = mpsc::unbounded_channel();
            let (events, events_rx) = mpsc::unbounded_channel();
            let (shutdown, shutdown_rx) = oneshot::channel::<()>();
            let facts = Arc::new(Mutex::new(facts(1)));
            let applies = Arc::new(Mutex::new(0));
            let writes = Arc::new(Mutex::new(Vec::new()));
            let times = Arc::new(Mutex::new(Vec::new()));
            let results = Arc::new(Mutex::new(results.iter().copied().collect()));
            let hang = Arc::new(AtomicBool::new(false));
            let source = FakeSource {
                synced,
                changes: changes_rx,
                snapshot,
            };
            let applier = FakeApplier {
                applies: applies.clone(),
                facts: facts.clone(),
                events: events_rx,
            };
            let sink = FakeSink {
                writes: writes.clone(),
                times: times.clone(),
                results: results.clone(),
                hang: hang.clone(),
            };
            let mut opts = ControllerOptions::new(settings(&["gw"]), "/run/igw");
            customize(&mut opts);
            let (metrics, ready) = (opts.metrics.clone(), opts.ready.clone());
            let task = tokio::spawn(run_loop(source, applier, sink, opts, async {
                let _ = shutdown_rx.await;
            }));
            Self {
                sync,
                changes,
                events,
                facts,
                applies,
                writes,
                times,
                results,
                hang,
                metrics,
                ready,
                shutdown: Some(shutdown),
                task,
            }
        }

        /// Whether the loop's metrics have the line `iroh_gateway_operator_<series> <value>`.
        fn shows(&self, series: &str, value: u64) -> bool {
            let line = format!("iroh_gateway_operator_{series} {value}");
            self.metrics.render().lines().any(|l| l == line)
        }

        fn ready(&self) -> bool {
            self.ready.load(Ordering::SeqCst)
        }

        fn applies(&self) -> usize {
            *self.applies.lock().unwrap()
        }

        fn writes(&self) -> usize {
            self.writes.lock().unwrap().len()
        }

        /// The addresses of the only Gateway in write number `n`, counted from 0.
        fn addresses(&self, n: usize) -> Vec<String> {
            self.writes.lock().unwrap()[n].gateways[0]
                .addresses
                .iter()
                .map(|a| a.value.clone())
                .collect()
        }

        /// Sets whether the link of edge `gw/e1` is connected, and tells the loop.
        fn set_connected(&self, connected: bool) {
            self.facts.lock().unwrap().edges.insert(
                ObjRef::new("gw", "e1"),
                EdgeState {
                    connected,
                    ..Default::default()
                },
            );
            self.events.send(EngineEvent::Changed).unwrap();
        }

        /// The time between consecutive writes, in milliseconds.
        fn gaps_ms(&self) -> Vec<u128> {
            let times = self.times.lock().unwrap();
            times
                .windows(2)
                .map(|w| (w[1] - w[0]).as_millis())
                .collect()
        }

        /// Syncs the stores and waits until the first pass has written.
        async fn synced(&self) {
            self.sync.send_replace(true);
            sleep(Duration::from_millis(10)).await;
            assert_eq!((self.applies(), self.writes()), (1, 1));
        }

        async fn stop(mut self) -> anyhow::Result<()> {
            let _ = self.shutdown.take().unwrap().send(());
            tokio::time::timeout(Duration::from_secs(1), self.task)
                .await
                .expect("the loop did not end")
                .unwrap()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_applied_before_stores_sync() {
        let rig = Rig::start();
        for _ in 0..6 {
            rig.changes.send(()).unwrap();
            sleep(Duration::from_millis(50)).await;
        }
        assert_eq!((rig.applies(), rig.writes()), (0, 0));
        rig.sync.send_replace(true);
        sleep(Duration::from_secs(1)).await;
        assert_eq!((rig.applies(), rig.writes()), (1, 1));
        rig.stop().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_of_changes_is_one_pass() {
        let rig = Rig::start();
        rig.synced().await;
        for _ in 0..20 {
            rig.changes.send(()).unwrap();
            sleep(Duration::from_micros(2500)).await;
        }
        sleep(Duration::from_secs(1)).await;
        assert_eq!((rig.applies(), rig.writes()), (2, 2));
        rig.stop().await.unwrap();
    }

    /// Gateway `gw/public` with one listener, served by the accepted edge `gw/e1` at
    /// 203.0.113.7, whose link starts connected.
    fn rig_with_a_gateway(customize: impl FnOnce(&mut ControllerOptions)) -> Rig {
        use crate::model::fixtures::{GatewayExt, class, gateway};
        let snapshot = Snapshot {
            gateway_classes: vec![class("ours")],
            gateways: vec![gateway("gw", "public").listener("web", 80, "HTTP")],
            edges: vec![edge("gw", "e1", 7)],
            ..Snapshot::default()
        };
        let rig = Rig::start_from(snapshot, &[], customize);
        rig.facts.lock().unwrap().edges.insert(
            ObjRef::new("gw", "e1"),
            EdgeState {
                connected: true,
                ..Default::default()
            },
        );
        rig
    }

    #[tokio::test(start_paused = true)]
    async fn a_grace_that_ends_triggers_a_pass() {
        let rig = rig_with_a_gateway(|_| {});
        rig.synced().await;
        assert_eq!(rig.addresses(0), ["203.0.113.7"]);

        // The link drops: the next pass still lists the address.
        rig.set_connected(false);
        sleep(Duration::from_secs(1)).await;
        assert_eq!(rig.writes(), 2);
        assert_eq!(rig.addresses(1), ["203.0.113.7"]);

        // Nothing else happens. When the grace ends, one more pass withdraws it.
        sleep(DEFAULT_ADDRESS_GRACE - Duration::from_secs(2)).await;
        assert_eq!(rig.writes(), 2);
        sleep(Duration::from_secs(3)).await;
        assert_eq!(rig.writes(), 3);
        assert!(rig.addresses(2).is_empty(), "{:?}", rig.addresses(2));
        let since_the_drop = rig.gaps_ms()[1];
        let grace = DEFAULT_ADDRESS_GRACE.as_millis();
        assert!(
            (grace..grace + 500).contains(&since_the_drop),
            "{since_the_drop} ms"
        );

        // And no pass after that.
        sleep(DEFAULT_ADDRESS_GRACE * 10).await;
        assert_eq!(rig.writes(), 3);
        rig.stop().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_reconnect_within_the_grace_cancels_the_withdrawal() {
        let rig = rig_with_a_gateway(|o| o.address_grace = Duration::from_secs(10));
        rig.synced().await;
        rig.set_connected(false);
        sleep(Duration::from_secs(5)).await;
        rig.set_connected(true);
        sleep(Duration::from_secs(60)).await;
        // The drop, the reconnect, and nothing when the cancelled grace would have ended.
        assert_eq!(rig.writes(), 3);
        for n in 0..3 {
            assert_eq!(rig.addresses(n), ["203.0.113.7"], "write {n}");
        }
        rig.stop().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn no_pass_is_scheduled_without_a_held_edge() {
        let rig = rig_with_a_gateway(|_| {});
        rig.synced().await;
        sleep(DEFAULT_ADDRESS_GRACE * 20).await;
        assert_eq!((rig.applies(), rig.writes()), (1, 1));
        rig.stop().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn an_edge_that_never_connected_is_not_listed() {
        let rig = rig_with_a_gateway(|_| {});
        rig.facts.lock().unwrap().edges.clear();
        rig.synced().await;
        assert!(rig.addresses(0).is_empty(), "{:?}", rig.addresses(0));
        rig.set_connected(true);
        sleep(Duration::from_secs(1)).await;
        assert_eq!(rig.addresses(1), ["203.0.113.7"]);
        rig.stop().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn link_state_change_triggers_a_status_write() {
        let rig = Rig::start();
        rig.synced().await;
        assert_eq!(
            rig.writes.lock().unwrap()[0].edges[0].gateway_endpoint_id,
            id(1).to_string()
        );
        *rig.facts.lock().unwrap() = facts(2);
        rig.events.send(EngineEvent::Changed).unwrap();
        sleep(Duration::from_secs(1)).await;
        assert_eq!(rig.writes(), 2);
        assert_eq!(
            rig.writes.lock().unwrap()[1].edges[0].gateway_endpoint_id,
            id(2).to_string()
        );
        rig.stop().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn run_ends_with_an_error_when_haproxy_dies() {
        let rig = Rig::start();
        rig.synced().await;
        rig.events
            .send(EngineEvent::HaproxyExited(ExitStatus::from_raw(256)))
            .unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(1), rig.task)
            .await
            .expect("the loop did not end")
            .unwrap();
        let error = ended.expect_err("the loop ended without an error");
        assert!(error.to_string().contains("exit status: 1"), "{error}");
        assert_eq!(*rig.applies.lock().unwrap(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn haproxy_dying_before_the_sync_is_an_error_too() {
        let rig = Rig::start();
        rig.events
            .send(EngineEvent::HaproxyExited(ExitStatus::from_raw(256)))
            .unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(1), rig.task)
            .await
            .expect("the loop did not end")
            .unwrap();
        assert!(ended.is_err());
        assert_eq!(*rig.applies.lock().unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_ends_the_loop_cleanly() {
        let rig = Rig::start();
        rig.synced().await;
        rig.stop().await.unwrap();

        let rig = Rig::start();
        rig.stop().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_ends_the_loop_during_a_write_that_never_returns() {
        let rig = Rig::start();
        rig.synced().await;
        rig.hang.store(true, Ordering::SeqCst);
        rig.changes.send(()).unwrap();
        sleep(Duration::from_secs(1)).await;
        // The second pass is stuck in its write.
        assert_eq!((rig.applies(), rig.writes()), (2, 2));
        // `stop` fails unless the loop ends within 1 s of the shutdown.
        rig.stop().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn failed_status_write_is_retried_without_any_change() {
        let rig = Rig::start_with(&[false], |_| {});
        rig.synced().await;
        // Nothing changes; only the failed write calls for another pass.
        sleep(DEFAULT_STATUS_RETRY_MIN - Duration::from_millis(100)).await;
        assert_eq!(rig.writes(), 1);
        sleep(Duration::from_secs(1)).await;
        assert_eq!((rig.applies(), rig.writes()), (2, 2));
        // That write succeeded: no more passes.
        sleep(DEFAULT_STATUS_RETRY_MAX * 3).await;
        assert_eq!((rig.applies(), rig.writes()), (2, 2));
        rig.stop().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_pass_is_counted_and_timed() {
        let rig = Rig::start();
        assert!(rig.shows("reconciles_total", 0), "{}", rig.metrics.render());
        rig.synced().await;
        assert!(rig.shows("reconciles_total", 1), "{}", rig.metrics.render());
        assert!(
            rig.shows("reconcile_duration_seconds_count", 1),
            "{}",
            rig.metrics.render()
        );
        assert!(rig.shows("status_write_failures_total", 0));
        rig.stop().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_status_write_is_counted() {
        let rig = Rig::start_with(&[false], |_| {});
        rig.synced().await;
        assert!(
            rig.shows("status_write_failures_total", 1),
            "{}",
            rig.metrics.render()
        );
        rig.stop().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn ready_after_the_first_pass_even_when_haproxy_refuses() {
        let rig = Rig::start();
        rig.facts.lock().unwrap().haproxy = Err("haproxy refused the configuration".into());
        rig.changes.send(()).unwrap();
        sleep(Duration::from_secs(1)).await;
        assert!(!rig.ready(), "ready before the stores synced");
        rig.synced().await;
        assert!(rig.ready());
        rig.stop().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn status_retry_backs_off_and_resets() {
        let rig = Rig::start_with(&[false, false, false], |opts| {
            opts.debounce = Duration::ZERO;
            opts.status_retry_min = Duration::from_millis(20);
            opts.status_retry_max = Duration::from_millis(50);
        });
        rig.synced().await;
        sleep(Duration::from_secs(1)).await;
        // Three failing passes, then the fourth succeeds.
        assert_eq!(rig.gaps_ms(), [20, 40, 50]);

        // A later failure starts again at the minimum.
        rig.results.lock().unwrap().push_back(false);
        rig.changes.send(()).unwrap();
        sleep(Duration::from_secs(1)).await;
        assert_eq!(rig.writes(), 6);
        assert_eq!(rig.gaps_ms()[4], 20);
        rig.stop().await.unwrap();
    }
}
