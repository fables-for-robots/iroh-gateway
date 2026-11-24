//! A throwaway Kubernetes API server: `etcd` and `kube-apiserver` from `KUBEBUILDER_ASSETS`
//! (see `scripts/envtest-assets`), on free loopback ports, with the `Edge` CRD and the upstream
//! Gateway API CRDs installed, so that the API server validates what the operator writes as a
//! real cluster would. Both processes are killed when the [`Envtest`] is dropped, including when
//! a test panics.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use gateway_api::gatewayclasses::v1::GatewayClass;
use gateway_api::gateways::v1::Gateway;
use gateway_api::httproutes::v1::HttpRoute;
use gateway_api::tcproutes::v1::TcpRoute;
use iroh_gateway_operator::crd::Edge;
use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{ListParams, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Api, Client, Config, CustomResourceExt, Resource};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tempfile::TempDir;
use tokio::time::sleep;

use super::free_tcp_port;

/// How long the API server gets to become ready, and each CRD to become established.
const START_TIMEOUT: Duration = Duration::from_secs(60);
const TOKEN: &str = "envtest-token";
/// How often a start that lost one of its ports to another test is tried.
const START_ATTEMPTS: u32 = 5;
/// The upstream manifest `scripts/envtest-assets` downloads beside the binaries.
const GATEWAY_API_MANIFEST: &str = "gateway-api-v1.7.0-standard-install.yaml";
/// The CRDs of that manifest the operator uses.
const GATEWAY_API_CRDS: [&str; 4] = [
    "gatewayclasses.gateway.networking.k8s.io",
    "gateways.gateway.networking.k8s.io",
    "httproutes.gateway.networking.k8s.io",
    "tcproutes.gateway.networking.k8s.io",
];

/// A process that ended during start, with its log, and whether it found its port taken.
struct Exited {
    message: String,
    port_taken: bool,
}

pub struct Envtest {
    pub client: Client,
    etcd: Child,
    apiserver: Child,
    dir: TempDir,
}

/// The directory named by `KUBEBUILDER_ASSETS`, with `etcd` and `kube-apiserver` in it.
fn assets() -> PathBuf {
    let Some(dir) = std::env::var_os("KUBEBUILDER_ASSETS") else {
        panic!(
            "KUBEBUILDER_ASSETS is not set. Run the cluster tests with\n  \
             KUBEBUILDER_ASSETS=$(scripts/envtest-assets) cargo test -p iroh-gateway-operator \
             --test cluster -- --ignored"
        );
    };
    let dir = PathBuf::from(dir);
    for bin in ["etcd", "kube-apiserver"] {
        assert!(
            dir.join(bin).is_file(),
            "KUBEBUILDER_ASSETS is {}, which has no {bin}; run scripts/envtest-assets",
            dir.display()
        );
    }
    dir
}

/// The Gateway API CRDs the operator uses, from the upstream manifest in `assets` or one of the
/// directories above it.
fn gateway_api_crds(assets: &Path) -> Vec<CustomResourceDefinition> {
    let Some(path) = assets
        .ancestors()
        .map(|d| d.join(GATEWAY_API_MANIFEST))
        .find(|p| p.is_file())
    else {
        panic!(
            "no {GATEWAY_API_MANIFEST} in {} or above it; run scripts/envtest-assets",
            assets.display()
        );
    };
    let text = std::fs::read_to_string(&path).unwrap();
    let mut crds = Vec::new();
    for document in serde_yaml::Deserializer::from_str(&text) {
        let value = serde_json::Value::deserialize(document)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let name = value["metadata"]["name"].as_str().unwrap_or_default();
        if value["kind"] == "CustomResourceDefinition" && GATEWAY_API_CRDS.contains(&name) {
            crds.push(serde_json::from_value(value).unwrap());
        }
    }
    assert_eq!(
        crds.len(),
        GATEWAY_API_CRDS.len(),
        "{} lacks some of {GATEWAY_API_CRDS:?}",
        path.display()
    );
    crds
}

/// A log file in `dir` for a child's stdout and stderr.
fn log_file(dir: &Path, name: &str) -> (Stdio, Stdio) {
    let file = File::create(dir.join(name)).unwrap();
    (file.try_clone().unwrap().into(), file.into())
}

/// The last lines of a log in `dir`, for a failure message.
fn tail(dir: &Path, name: &str) -> String {
    let text = std::fs::read_to_string(dir.join(name)).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(30)..].join("\n")
}

impl Envtest {
    /// Starts the API server, waits until it serves, and installs the `Edge` CRD and the
    /// upstream Gateway API CRDs.
    ///
    /// The ports are picked free but released before the processes bind them, so another test
    /// can take one in between; a start that fails that way is tried again on new ports.
    pub async fn start() -> Self {
        // As the operator's main does, before any client is built.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let assets = assets();
        let mut attempt = 1;
        loop {
            match Self::try_start(&assets).await {
                Ok(mut env) => {
                    env.install_crds(gateway_api_crds(&assets)).await;
                    return env;
                }
                Err(Exited {
                    message,
                    port_taken,
                }) => {
                    if !port_taken || attempt == START_ATTEMPTS {
                        panic!("{message}");
                    }
                    attempt += 1;
                }
            }
        }
    }

    /// Starts the processes on new ports and waits until the API server serves.
    async fn try_start(assets: &Path) -> Result<Self, Exited> {
        let dir = tempfile::Builder::new()
            .prefix("envtest")
            .tempdir()
            .unwrap();
        let path = dir.path();

        let (client_port, peer_port, secure_port) =
            (free_tcp_port(), free_tcp_port(), free_tcp_port());
        let etcd_url = format!("http://127.0.0.1:{client_port}");
        let etcd_log = log_file(path, "etcd.log");
        let etcd = Command::new(assets.join("etcd"))
            .arg(format!("--data-dir={}", path.join("etcd").display()))
            .arg(format!("--listen-client-urls={etcd_url}"))
            .arg(format!("--advertise-client-urls={etcd_url}"))
            .arg(format!("--listen-peer-urls=http://127.0.0.1:{peer_port}"))
            .arg("--unsafe-no-fsync")
            .stdin(Stdio::null())
            .stdout(etcd_log.0)
            .stderr(etcd_log.1)
            .spawn()
            .expect("starting etcd");

        let key = rcgen::KeyPair::generate().unwrap();
        std::fs::write(path.join("sa.key"), key.serialize_pem()).unwrap();
        std::fs::write(path.join("sa.pub"), key.public_key_pem()).unwrap();
        std::fs::write(path.join("tokens.csv"), format!("{TOKEN},admin,admin\n")).unwrap();
        let kube_apiserver_log = log_file(path, "kube-apiserver.log");
        let apiserver = Command::new(assets.join("kube-apiserver"))
            .arg(format!("--etcd-servers={etcd_url}"))
            .arg(format!("--secure-port={secure_port}"))
            .arg("--bind-address=127.0.0.1")
            .arg("--advertise-address=127.0.0.1")
            // Loopback cannot be advertised in the `kubernetes` Service's endpoints.
            .arg("--endpoint-reconciler-type=none")
            .arg(format!("--cert-dir={}", path.join("certs").display()))
            .arg("--service-cluster-ip-range=10.0.0.0/24")
            .arg("--authorization-mode=AlwaysAllow")
            .arg(format!(
                "--token-auth-file={}",
                path.join("tokens.csv").display()
            ))
            .arg("--service-account-issuer=https://localhost")
            .arg(format!(
                "--service-account-key-file={}",
                path.join("sa.pub").display()
            ))
            .arg(format!(
                "--service-account-signing-key-file={}",
                path.join("sa.key").display()
            ))
            .arg("--disable-admission-plugins=ServiceAccount")
            .stdin(Stdio::null())
            .stdout(kube_apiserver_log.0)
            .stderr(kube_apiserver_log.1)
            .spawn()
            .expect("starting kube-apiserver");

        let kubeconfig = format!(
            "apiVersion: v1\n\
             kind: Config\n\
             clusters:\n\
             - name: envtest\n  \
               cluster:\n    \
                 server: https://127.0.0.1:{secure_port}\n    \
                 insecure-skip-tls-verify: true\n\
             users:\n\
             - name: admin\n  \
               user:\n    \
                 token: {TOKEN}\n\
             contexts:\n\
             - name: envtest\n  \
               context:\n    \
                 cluster: envtest\n    \
                 user: admin\n\
             current-context: envtest\n"
        );
        // Kept beside the logs, for `kubectl --kubeconfig` while debugging a test.
        std::fs::write(path.join("kubeconfig"), &kubeconfig).unwrap();
        let config = Config::from_custom_kubeconfig(
            Kubeconfig::from_yaml(&kubeconfig).unwrap(),
            &KubeConfigOptions::default(),
        )
        .await
        .unwrap();
        let client = Client::try_from(config).unwrap();

        let mut env = Self {
            client,
            etcd,
            apiserver,
            dir,
        };
        // On an error `env` is dropped, which stops whichever process is still running.
        env.wait_ready().await?;
        Ok(env)
    }

    /// Why a process ended, if one has.
    fn exited(&mut self) -> Option<Exited> {
        for (name, child, log) in [
            ("etcd", &mut self.etcd, "etcd.log"),
            ("kube-apiserver", &mut self.apiserver, "kube-apiserver.log"),
        ] {
            if let Some(status) = child.try_wait().unwrap() {
                let text = std::fs::read_to_string(self.dir.path().join(log)).unwrap_or_default();
                return Some(Exited {
                    message: format!("{name} exited ({status}):\n{}", tail(self.dir.path(), log)),
                    port_taken: text.contains("address already in use"),
                });
            }
        }
        None
    }

    /// Panics with the logs if either process has ended.
    fn check_alive(&mut self) {
        if let Some(exited) = self.exited() {
            panic!("{}", exited.message);
        }
    }

    /// Waits until the API server serves the `default` namespace, which it creates once ready.
    async fn wait_ready(&mut self) -> Result<(), Exited> {
        let namespaces: Api<Namespace> = Api::all(self.client.clone());
        let start = Instant::now();
        loop {
            if let Some(exited) = self.exited() {
                return Err(exited);
            }
            match namespaces.get("default").await {
                Ok(_) => return Ok(()),
                Err(e) if start.elapsed() > START_TIMEOUT => panic!(
                    "the API server did not become ready: {e}\n{}",
                    tail(self.dir.path(), "kube-apiserver.log")
                ),
                Err(_) => sleep(Duration::from_millis(100)).await,
            }
        }
    }

    async fn install_crds(&mut self, gateway_api: Vec<CustomResourceDefinition>) {
        let crds: Api<CustomResourceDefinition> = Api::all(self.client.clone());
        for crd in std::iter::once(Edge::crd()).chain(gateway_api) {
            let name = crd.metadata.name.clone().unwrap();
            if let Err(e) = crds.create(&PostParams::default(), &crd).await {
                panic!("the API server refused CRD {name}: {e}");
            }
        }
        self.served::<Edge>().await;
        self.served::<GatewayClass>().await;
        self.served::<Gateway>().await;
        self.served::<HttpRoute>().await;
        self.served::<TcpRoute>().await;
    }

    /// Waits until `K` can be listed, which it can once its CRD is established.
    async fn served<K>(&mut self)
    where
        K: Resource<DynamicType = ()> + Clone + DeserializeOwned + std::fmt::Debug,
    {
        let api: Api<K> = Api::all(self.client.clone());
        let start = Instant::now();
        loop {
            self.check_alive();
            match api.list(&ListParams::default()).await {
                Ok(_) => return,
                Err(e) if start.elapsed() > START_TIMEOUT => {
                    panic!("{} is not served: {e}", K::kind(&()))
                }
                Err(_) => sleep(Duration::from_millis(100)).await,
            }
        }
    }

    /// A kubeconfig file for this API server.
    pub fn kubeconfig(&self) -> PathBuf {
        self.dir.path().join("kubeconfig")
    }

    /// Creates namespace `name`.
    pub async fn namespace(&self, name: &str) {
        let ns = Namespace {
            metadata: kube::api::ObjectMeta {
                name: Some(name.into()),
                ..Default::default()
            },
            ..Default::default()
        };
        Api::<Namespace>::all(self.client.clone())
            .create(&PostParams::default(), &ns)
            .await
            .unwrap();
    }
}

impl Drop for Envtest {
    fn drop(&mut self) {
        let _ = self.apiserver.kill();
        let _ = self.apiserver.wait();
        let _ = self.etcd.kill();
        let _ = self.etcd.wait();
    }
}
