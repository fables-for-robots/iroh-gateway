//! The reconcile loop: snapshot, model, render, apply, status, and again on every change.

use std::path::PathBuf;
use std::pin::pin;
use std::time::Duration;

use anyhow::bail;
use tokio::time::{Instant, sleep_until};

use crate::cluster::{SnapshotSource, StatusSink};
use crate::engine::{Engine, EngineEvent};
use crate::haproxy::render::{Rendered, render};
use crate::model::{self, Settings};
use crate::status::{self, Facts};

/// Default for [`ControllerOptions::debounce`].
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(200);

pub struct ControllerOptions {
    pub settings: Settings,
    /// HAProxy's runtime directory, which the render names sockets in.
    pub runtime_dir: PathBuf,
    /// After the first change, how long further changes are absorbed into the same pass.
    pub debounce: Duration,
}

impl ControllerOptions {
    /// Options with [`DEFAULT_DEBOUNCE`].
    pub fn new(settings: Settings, runtime_dir: impl Into<PathBuf>) -> Self {
        Self {
            settings,
            runtime_dir: runtime_dir.into(),
            debounce: DEFAULT_DEBOUNCE,
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
/// another after each change in the stores or in the applier; changes that arrive within
/// `debounce` of the first one are taken in the same pass. A pass is never interrupted:
/// `shutdown` is noticed between passes.
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

    loop {
        let snapshot = source.snapshot();
        let model = model::build(&snapshot, &opts.settings);
        applier.apply(render(&model, &opts.runtime_dir)).await;
        let desired = status::compute(&model, &applier.facts());
        sink.write(&desired, &snapshot).await;

        tokio::select! {
            () = source.changed() => {}
            event = applier.next_event() => check(event)?,
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

/// Ok for a change, an error once HAProxy has exited.
fn check(event: EngineEvent) -> anyhow::Result<()> {
    match event {
        EngineEvent::Changed => Ok(()),
        EngineEvent::HaproxyExited(status) => bail!("haproxy exited on its own ({status})"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::future::pending;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::sync::{Arc, Mutex};

    use tokio::sync::{mpsc, oneshot, watch};
    use tokio::task::JoinHandle;
    use tokio::time::sleep;

    use super::*;
    use crate::model::Snapshot;
    use crate::model::fixtures::{edge, settings};
    use crate::status::DesiredStatus;

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

    struct FakeSink {
        writes: Arc<Mutex<Vec<DesiredStatus>>>,
    }

    impl StatusSink for FakeSink {
        async fn write(&mut self, desired: &DesiredStatus, _snapshot: &Snapshot) {
            self.writes.lock().unwrap().push(desired.clone());
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
        shutdown: Option<oneshot::Sender<()>>,
        task: JoinHandle<anyhow::Result<()>>,
    }

    impl Rig {
        /// One edge in namespace `gw`, so the desired status carries the operator's id.
        fn start() -> Self {
            let (sync, synced) = watch::channel(false);
            let (changes, changes_rx) = mpsc::unbounded_channel();
            let (events, events_rx) = mpsc::unbounded_channel();
            let (shutdown, shutdown_rx) = oneshot::channel::<()>();
            let facts = Arc::new(Mutex::new(facts(1)));
            let applies = Arc::new(Mutex::new(0));
            let writes = Arc::new(Mutex::new(Vec::new()));
            let source = FakeSource {
                synced,
                changes: changes_rx,
                snapshot: Snapshot {
                    edges: vec![edge("gw", "e1", 7)],
                    ..Snapshot::default()
                },
            };
            let applier = FakeApplier {
                applies: applies.clone(),
                facts: facts.clone(),
                events: events_rx,
            };
            let sink = FakeSink {
                writes: writes.clone(),
            };
            let opts = ControllerOptions::new(settings(&["gw"]), "/run/igw");
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
                shutdown: Some(shutdown),
                task,
            }
        }

        fn applies(&self) -> usize {
            *self.applies.lock().unwrap()
        }

        fn writes(&self) -> usize {
            self.writes.lock().unwrap().len()
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
}
