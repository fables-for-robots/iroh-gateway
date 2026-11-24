//! Runs HAProxy in master-worker mode and applies new configurations to it: each one is
//! validated with `haproxy -c` first, loaded through the master socket's `reload`, and taken
//! back on disk when the reload fails; after a reload HAProxy refused, the previous
//! configuration is reloaded once.
//!
//! The files a configuration names besides itself (certificates with their keys) live in
//! `<runtime_dir>/certs`. A file is kept as long as a configuration HAProxy runs, or may run,
//! lists it, and removed once none does.

use std::collections::BTreeSet;
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context, bail};
use nix::sys::signal::{Signal, kill, killpg};
use nix::unistd::Pid;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::{Instant, sleep, timeout};
use tracing::{info, warn};

use super::SecretFile;

/// Default for [`SupervisorOptions::reload_timeout`].
pub const DEFAULT_RELOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest runtime_dir this module accepts, so that `<runtime_dir>/s/<20 chars>` fits a Unix
/// socket path with room for the `.<pid>.tmp` HAProxy appends while it binds one (macOS allows
/// 104 bytes with the terminating NUL; HAProxy refuses paths longer than about 93 there).
pub const MAX_RUNTIME_DIR_LEN: usize = 60;

/// How long [`Supervisor::shutdown`] waits after SIGTERM before it kills HAProxy.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
/// Pause between attempts to reach the master socket while HAProxy starts.
const START_POLL: Duration = Duration::from_millis(20);
/// Bound for one readiness probe, so a stuck connection does not use up the whole start budget.
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

const CFG: &str = "haproxy.cfg";
const CFG_NEW: &str = "haproxy.cfg.new";
const MASTER_SOCK: &str = "master.sock";
const STATS_SOCK: &str = "stats.sock";
const SOCKET_DIR: &str = "s";
/// The directory under the runtime directory that holds the files, mode 0700.
pub const CERT_DIR: &str = "certs";

pub struct SupervisorOptions {
    /// The HAProxy executable; a bare name is looked up on PATH.
    pub haproxy_bin: PathBuf,
    /// Holds haproxy.cfg, master.sock, stats.sock, s/ and certs/.
    pub runtime_dir: PathBuf,
    /// Bound for HAProxy to answer on its master socket at start, and for a reload's reply.
    pub reload_timeout: Duration,
    /// Whether HAProxy's stdout and stderr go to ours (true) or nowhere (false).
    pub inherit_output: bool,
}

impl SupervisorOptions {
    /// Options for `runtime_dir` with `haproxy` from PATH, [`DEFAULT_RELOAD_TIMEOUT`] and
    /// inherited output.
    pub fn new(runtime_dir: impl Into<PathBuf>) -> Self {
        Self {
            haproxy_bin: "haproxy".into(),
            runtime_dir: runtime_dir.into(),
            reload_timeout: DEFAULT_RELOAD_TIMEOUT,
            inherit_output: true,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Applied {
    /// The text equals the running configuration; nothing was done.
    Unchanged,
    /// HAProxy reloaded with the new text.
    Reloaded,
}

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// `haproxy -c` refused it. Carries the ALERT lines.
    #[error("haproxy refused the configuration:\n{0}")]
    Invalid(String),
    /// The master answered something other than Success=1. Carries its reply.
    #[error("haproxy reload failed:\n{0}")]
    ReloadFailed(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// A running HAProxy master and its workers. Dropping it kills them.
pub struct Supervisor {
    opts: SupervisorOptions,
    child: Child,
    pid: u32,
    /// Set once the master has been reaped.
    status: Option<ExitStatus>,
    /// The configuration the running workers were loaded with; `None` while that is not known,
    /// after a reload whose outcome was lost (timed out, broken off, or cancelled).
    current: Option<String>,
    /// The last configuration HAProxy confirmed loading; written back to `haproxy.cfg` when a
    /// reload fails.
    loaded: String,
    /// The names in `certs/` that a configuration HAProxy runs or may run lists: those of
    /// `loaded`, and those of every configuration since whose reload outcome is unknown. Nothing
    /// else in `certs/` is needed.
    in_use: BTreeSet<String>,
}

/// Why [`Supervisor::reload`] got no reply.
enum ReloadError {
    /// Connecting to the master socket failed: nothing was sent.
    Connect(io::Error),
    /// Failed after connecting: the request may have reached the master.
    Exchange(io::Error),
}

impl Supervisor {
    /// Validates `cfg`, writes it, starts `haproxy -W -S unix@<runtime_dir>/master.sock -f <runtime_dir>/haproxy.cfg`
    /// and returns once the master socket answers and a worker is serving.
    pub async fn start(mut opts: SupervisorOptions, cfg: &str) -> anyhow::Result<Self> {
        opts.runtime_dir = std::path::absolute(&opts.runtime_dir).with_context(|| {
            format!("resolving runtime directory {}", opts.runtime_dir.display())
        })?;
        let dir = &opts.runtime_dir;
        let len = dir.as_os_str().len();
        if len > MAX_RUNTIME_DIR_LEN {
            bail!(
                "runtime directory {} is {len} bytes long, more than the limit of \
                 {MAX_RUNTIME_DIR_LEN} bytes that keeps its socket paths within the OS limit",
                dir.display()
            );
        }
        for d in [dir.clone(), dir.join(SOCKET_DIR), dir.join(CERT_DIR)] {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&d)
                .with_context(|| format!("creating {}", d.display()))?;
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("setting permissions on {}", d.display()))?;
        }
        // Files an earlier run left: no configuration of this run names them.
        let certs = dir.join(CERT_DIR);
        remove_entries(&certs, |_| false)
            .with_context(|| format!("emptying {}", certs.display()))?;

        validate(&opts, cfg).await.map_err(|e| match e {
            ApplyError::Invalid(alerts) => anyhow::anyhow!("invalid configuration:\n{alerts}"),
            other => anyhow::Error::new(other),
        })?;
        let cfg_path = dir.join(CFG);
        if let Err(e) = tokio::fs::rename(dir.join(CFG_NEW), &cfg_path).await {
            let _ = tokio::fs::remove_file(dir.join(CFG_NEW)).await;
            return Err(e).with_context(|| format!("writing {}", cfg_path.display()));
        }

        // A socket left by an earlier run would answer nothing, or answer for someone else.
        let master = dir.join(MASTER_SOCK);
        match std::fs::remove_file(&master) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => {
                return Err(e).with_context(|| format!("removing stale {}", master.display()));
            }
            _ => {}
        }
        let output = || {
            if opts.inherit_output {
                Stdio::inherit()
            } else {
                Stdio::null()
            }
        };
        let child = Command::new(&opts.haproxy_bin)
            .arg("-W")
            .arg("-S")
            .arg(format!("unix@{}", master.display()))
            .arg("-f")
            .arg(&cfg_path)
            .stdin(Stdio::null())
            .stdout(output())
            .stderr(output())
            // Its own group, so that its workers can be killed with it, and so that a terminal's
            // Ctrl-C reaches only us; we stop it.
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("starting {}", opts.haproxy_bin.display()))?;
        let pid = child
            .id()
            .context("haproxy exited before its pid was read")?;
        let mut sup = Supervisor {
            opts,
            child,
            pid,
            status: None,
            current: Some(cfg.to_owned()),
            loaded: cfg.to_owned(),
            in_use: BTreeSet::new(),
        };
        if let Err(e) = sup.wait_ready().await {
            sup.stop().await;
            return Err(e);
        }
        info!(pid, "haproxy started");
        Ok(sup)
    }

    /// The HAProxy master's process id.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Makes `cfg` the running configuration, with `files` written to `<runtime_dir>/certs`
    /// before it is validated. Not re-entrant: one call at a time.
    ///
    /// The caller names files after their content, so that equal `cfg` means equal files: a
    /// file that exists already is not written again, and `cfg` equal to the running text
    /// touches no file. A name that is empty, starts with `.` or has a character outside
    /// `[A-Za-z0-9_.-]` fails the call with [`ApplyError::Io`] of kind `InvalidInput` before
    /// anything is written.
    ///
    /// When the master answers `Success=0`, the previous configuration is written back and
    /// reloaded once before the error is returned: after a failed reload HAProxy's master
    /// re-executes without its listening sockets on the next failure, so two failures in a row
    /// would leave every socket refusing connections; a successful reload in between prevents
    /// that. If that second reload does not answer `Success=1` either, the running
    /// configuration is unknown and the error names both failures.
    ///
    /// Once the outcome is known, every file in `certs/` that no configuration HAProxy runs or
    /// may run lists is removed: after a success all but `files`; after a refused validation or
    /// a reload that certainly failed (and, after `Success=0`, a successful reload of the
    /// previous configuration), all but those of the loaded configuration (and of any
    /// configuration since whose reload outcome is still unknown); after a reload whose outcome
    /// is unknown, nothing.
    ///
    /// Cancelling it, a timeout, or a broken connection during either reload leaves the running
    /// configuration unknown; the next call then reloads whatever text it is given. A cancelled
    /// call removes no file a configuration HAProxy may run lists; files it wrote for `cfg`
    /// stay until a later call removes them. A call cancelled while it reloads the previous
    /// configuration leaves `haproxy.cfg` holding that configuration, and the master may not
    /// have had the successful reload yet: if the next call's configuration fails to load as
    /// well, that is two failures in a row. [`crate::engine::Engine`] never cancels it.
    pub async fn apply(&mut self, cfg: &str, files: &[SecretFile]) -> Result<Applied, ApplyError> {
        check_names(files)?;
        if self.current.as_deref() == Some(cfg) {
            return Ok(Applied::Unchanged);
        }
        // Without an await, so that a cancelled call leaves no write half done in the
        // background, where it could outlive `shutdown` or `Drop`.
        if let Err(e) = self.write_files(files) {
            self.remove_unlisted();
            return Err(e.into());
        }
        if let Err(e) = validate(&self.opts, cfg).await {
            self.remove_unlisted();
            return Err(e);
        }
        // Unknown from here until the master's reply says otherwise, so that a cancelled call
        // leaves it unknown; for the same reason `files` count as in use from here on.
        let previous = self.current.take();
        let previous_in_use = self.in_use.clone();
        self.in_use.extend(files.iter().map(|f| f.name.clone()));
        let dir = &self.opts.runtime_dir;
        if let Err(e) = tokio::fs::rename(dir.join(CFG_NEW), dir.join(CFG)).await {
            let _ = tokio::fs::remove_file(dir.join(CFG_NEW)).await;
            self.current = previous;
            self.in_use = previous_in_use;
            self.remove_unlisted();
            return Err(e.into());
        }
        // Whether the master certainly did not load `cfg`: then `previous` still runs. Whether
        // it said so with `Success=0`: then it has had a failed reload.
        let (failure, not_loaded, refused) =
            match timeout(self.opts.reload_timeout, self.reload()).await {
                Ok(Ok(reply)) if reply.starts_with("Success=1") => {
                    self.current = Some(cfg.to_owned());
                    self.loaded = cfg.to_owned();
                    self.in_use = files.iter().map(|f| f.name.clone()).collect();
                    self.remove_unlisted();
                    info!("haproxy reloaded");
                    return Ok(Applied::Reloaded);
                }
                Ok(Ok(reply)) => {
                    // A complete reply; anything but `Success=0` is not one we understand.
                    let definite = reply.starts_with("Success=0");
                    (ApplyError::ReloadFailed(reply), definite, definite)
                }
                // Nothing was sent: the master saw no reload at all.
                Ok(Err(ReloadError::Connect(e))) => (ApplyError::Io(e), true, false),
                Ok(Err(ReloadError::Exchange(e))) => (ApplyError::Io(e), false, false),
                Err(_) => (ApplyError::ReloadFailed(self.timed_out()), false, false),
            };
        if not_loaded {
            self.current = previous;
        }
        warn!(error = %failure, "haproxy reload failed; restoring the previous configuration");
        // Written beside it and renamed over it, never rewritten in place: a reload whose
        // outcome was lost may still be reading the file.
        let path = dir.join(CFG);
        let staged = dir.join(CFG_NEW);
        let restored = match tokio::fs::write(&staged, &self.loaded).await {
            Ok(()) => tokio::fs::rename(&staged, &path).await,
            Err(e) => Err(e),
        };
        if let Err(e) = restored {
            let _ = tokio::fs::remove_file(&staged).await;
            // `files` stay in use: `haproxy.cfg` may still name them.
            return Err(ApplyError::Io(io::Error::new(
                e.kind(),
                format!(
                    "restoring {} after a failed reload ({failure}): {e}",
                    path.display()
                ),
            )));
        }
        if refused {
            // After a failed reload the master re-executes without its listening sockets on
            // the next failure (it passes them on with `-x` only after a success), so that every
            // socket would stop answering. A successful reload of the restored configuration
            // re-arms it.
            //
            // Unknown until the reply, so that a cancelled call leaves it unknown; `files` stay
            // in use until then. Whatever the master does, `haproxy.cfg` is `loaded` now.
            self.current = None;
            match timeout(self.opts.reload_timeout, self.reload()).await {
                Ok(Ok(reply)) if reply.starts_with("Success=1") => {
                    self.current = Some(self.loaded.clone());
                    info!("haproxy reloaded the previous configuration");
                }
                second => {
                    let second = match second {
                        Ok(Ok(reply)) => reply,
                        Ok(Err(ReloadError::Connect(e) | ReloadError::Exchange(e))) => {
                            e.to_string()
                        }
                        Err(_) => self.timed_out(),
                    };
                    warn!(error = %second, "reloading the previous configuration failed");
                    // `refused` is set only for a `Success=0` reply.
                    let first = match failure {
                        ApplyError::ReloadFailed(reply) => reply,
                        other => other.to_string(),
                    };
                    return Err(ApplyError::ReloadFailed(format!(
                        "{first}\nand reloading the previous configuration afterwards failed:\n{second}"
                    )));
                }
            }
        }
        if not_loaded {
            self.in_use = previous_in_use;
            self.remove_unlisted();
        }
        Err(failure)
    }

    fn timed_out(&self) -> String {
        format!(
            "timed out: no complete reply to reload within {:?}",
            self.opts.reload_timeout
        )
    }

    /// Resolves when the HAProxy master process ends on its own.
    pub async fn exited(&mut self) -> ExitStatus {
        if let Some(status) = self.status {
            return status;
        }
        let status = match self.child.wait().await {
            Ok(status) => status,
            Err(e) => {
                // waitpid failed: the process is not ours to wait for any more. Report it as
                // a failure, exit code 255, so callers do not mistake it for a clean exit.
                warn!(error = %e, "waiting for haproxy failed");
                std::os::unix::process::ExitStatusExt::from_raw(255 << 8)
            }
        };
        self.status = Some(status);
        status
    }

    /// SIGTERM to the master, wait up to 5 s, then kill. Removes the sockets it created and the
    /// files in `certs/`.
    pub async fn shutdown(mut self) {
        self.stop().await;
        info!("haproxy stopped");
    }

    /// Stops HAProxy if it still runs, reaps the master, and removes the sockets and the files.
    async fn stop(&mut self) {
        if self.status.is_none() && matches!(self.child.try_wait(), Ok(None)) {
            // To the master alone: it stops its workers itself.
            let _ = kill(Pid::from_raw(self.pid as i32), Signal::SIGTERM);
            if timeout(SHUTDOWN_GRACE, self.exited()).await.is_err() {
                warn!("haproxy did not stop within {SHUTDOWN_GRACE:?}; killing it");
                self.kill_group();
            }
        }
        self.exited().await;
        self.remove_sockets();
        self.remove_files(|_| false);
    }

    /// Waits until the master answers and passes a request on to a worker, which a worker
    /// does only once it has bound its listeners.
    async fn wait_ready(&mut self) -> anyhow::Result<()> {
        let budget = self.opts.reload_timeout;
        let deadline = Instant::now() + budget;
        let master = self.opts.runtime_dir.join(MASTER_SOCK);
        loop {
            if let Some(status) = self.child.try_wait().context("waiting for haproxy")? {
                self.status = Some(status);
                bail!("haproxy exited during start: {status}");
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if let Ok(Ok(reply)) = timeout(left.min(PROBE_TIMEOUT), probe(&master)).await
                && reply.starts_with("Name:")
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "haproxy did not answer on {} within {budget:?}",
                    master.display()
                );
            }
            sleep(START_POLL).await;
        }
    }

    /// Sends `reload` to the master and reads its reply to the end.
    async fn reload(&self) -> Result<String, ReloadError> {
        let mut s = UnixStream::connect(self.opts.runtime_dir.join(MASTER_SOCK))
            .await
            .map_err(ReloadError::Connect)?;
        let mut reply = Vec::new();
        async {
            s.write_all(b"reload\n").await?;
            s.read_to_end(&mut reply).await
        }
        .await
        .map_err(ReloadError::Exchange)?;
        Ok(String::from_utf8_lossy(&reply).into_owned())
    }

    /// The master's process group; it leads its own.
    fn pgid(&self) -> Pid {
        Pid::from_raw(self.pid as i32)
    }

    /// SIGKILL to the master and its workers. Only while the master is unreaped, so that the
    /// group id cannot belong to anyone else.
    fn kill_group(&mut self) {
        if self.status.is_none() && matches!(self.child.try_wait(), Ok(None)) {
            let _ = killpg(self.pgid(), Signal::SIGKILL);
        }
    }

    /// Writes each of `files` that `certs/` lacks: created with mode 0600 under a temporary
    /// name, then renamed to its own.
    fn write_files(&self, files: &[SecretFile]) -> io::Result<()> {
        let dir = self.opts.runtime_dir.join(CERT_DIR);
        for file in files {
            let path = dir.join(&file.name);
            match std::fs::symlink_metadata(&path) {
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            // A dot name, which no file of a configuration has.
            let staged = dir.join(format!(".{}.tmp", file.name));
            let written = remove_if_exists(&staged)
                .and_then(|()| write_new(&staged, &file.contents))
                .and_then(|()| std::fs::rename(&staged, &path));
            if let Err(e) = written {
                let _ = std::fs::remove_file(&staged);
                return Err(io::Error::new(
                    e.kind(),
                    format!("writing {}: {e}", path.display()),
                ));
            }
        }
        Ok(())
    }

    /// Removes what `certs/` holds besides the files in use.
    fn remove_unlisted(&self) {
        self.remove_files(|name| self.in_use.contains(name));
    }

    /// Removes each entry of `certs/` whose name `keep` refuses.
    fn remove_files(&self, keep: impl Fn(&str) -> bool) {
        let dir = self.opts.runtime_dir.join(CERT_DIR);
        // A missing directory holds no file.
        if let Err(e) = remove_entries(&dir, keep)
            && e.kind() != io::ErrorKind::NotFound
        {
            warn!(dir = %dir.display(), error = %e, "removing certificate files failed");
        }
    }

    fn remove_sockets(&self) {
        let dir = &self.opts.runtime_dir;
        let mut paths = vec![dir.join(MASTER_SOCK), dir.join(STATS_SOCK)];
        if let Ok(entries) = std::fs::read_dir(dir.join(SOCKET_DIR)) {
            paths.extend(
                entries
                    .flatten()
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_socket()))
                    .map(|e| e.path()),
            );
        }
        for path in paths {
            match std::fs::remove_file(&path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => {
                    warn!(path = %path.display(), error = %e, "removing haproxy socket failed");
                }
                _ => {}
            }
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        // The workers leave when their master dies; killing the group also covers the time
        // until they notice. `kill_on_drop` then kills and reaps the master.
        self.kill_group();
        self.remove_files(|_| false);
    }
}

/// Refuses a name that is empty, starts with `.` or has a character outside `[A-Za-z0-9_.-]`:
/// one that could leave `certs/`, clash with a temporary file, or mean something else where a
/// configuration names it.
fn check_names(files: &[SecretFile]) -> io::Result<()> {
    let bad = |name: &str| {
        name.is_empty()
            || name.starts_with('.')
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    };
    match files.iter().find(|f| bad(&f.name)) {
        Some(f) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid certificate file name {:?}", f.name),
        )),
        None => Ok(()),
    }
}

/// Creates `path` with mode 0600, failing if it exists, and writes `contents` to it.
fn write_new(path: &Path, contents: &str) -> io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(contents.as_bytes())
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Removes each entry of `dir` whose name `keep` refuses, directories with their contents.
/// Tries them all; returns the first error.
fn remove_entries(dir: &Path, keep: impl Fn(&str) -> bool) -> io::Result<()> {
    let mut first = None;
    for entry in std::fs::read_dir(dir)? {
        let removed = entry.and_then(|entry| {
            if entry.file_name().to_str().is_some_and(&keep) {
                return Ok(());
            }
            let path = entry.path();
            let result = if entry.file_type()?.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            match result {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(io::Error::new(
                    e.kind(),
                    format!("removing {}: {e}", path.display()),
                )),
                _ => Ok(()),
            }
        });
        if let Err(e) = removed {
            first.get_or_insert(e);
        }
    }
    first.map_or(Ok(()), Err)
}

/// Writes `cfg` to `haproxy.cfg.new` and runs `haproxy -c` on it. On success the file stays
/// for the caller to rename; on any failure it is removed.
async fn validate(opts: &SupervisorOptions, cfg: &str) -> Result<(), ApplyError> {
    let path = opts.runtime_dir.join(CFG_NEW);
    let result = check(opts, &path, cfg).await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&path).await;
    }
    result
}

async fn check(opts: &SupervisorOptions, path: &Path, cfg: &str) -> Result<(), ApplyError> {
    tokio::fs::write(path, cfg).await?;
    let out = Command::new(&opts.haproxy_bin)
        .arg("-c")
        .arg("-f")
        .arg(path)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("running {} -c: {e}", opts.haproxy_bin.display()),
            )
        })?;
    if out.status.success() {
        return Ok(());
    }
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let alerts: Vec<&str> = text.lines().filter(|l| l.contains("[ALERT]")).collect();
    Err(ApplyError::Invalid(if !alerts.is_empty() {
        alerts.join("\n")
    } else if !text.trim().is_empty() {
        text.trim().to_owned()
    } else {
        format!("haproxy -c failed with {}", out.status)
    }))
}

/// Asks the current worker, through the master, for `show info`.
async fn probe(master: &Path) -> io::Result<String> {
    let mut s = UnixStream::connect(master).await?;
    s.write_all(b"@1 show info\n").await?;
    // The master passes the request on and closes only after the client has finished.
    s.shutdown().await?;
    let mut reply = Vec::new();
    s.read_to_end(&mut reply).await?;
    Ok(String::from_utf8_lossy(&reply).into_owned())
}
