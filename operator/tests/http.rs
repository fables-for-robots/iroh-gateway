//! HTTP and HTTPS ports: models built by hand, rendered into a temporary directory and served by
//! a real `haproxy` on PATH, with small HTTP servers on loopback as backends.
#![cfg(unix)]

#[allow(dead_code)]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::short_dir;
use iroh_gateway_operator::haproxy::render::{Rendered, port_id, render};
use iroh_gateway_operator::haproxy::{
    Applied, CERT_DIR, MAX_RUNTIME_DIR_LEN, Supervisor, SupervisorOptions,
};
use iroh_gateway_operator::model::{
    Backend, Certificate, GatewayModel, HeaderMods, HostMatch, HttpAction, HttpBackend, HttpPort,
    HttpRule, ListenerModel, Model, ObjRef, PathMatch, Redirect,
};
use iroh_gateway_operator::tunnel::proxyv2;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair,
};
use rustls::pki_types::{CertificateDer, ServerName};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::time::{sleep, timeout};
use tokio_rustls::client::TlsStream;

/// Upper bound for any single step that should complete promptly on loopback.
const STEP: Duration = Duration::from_secs(10);
/// The visitor every PROXY header names.
const VISITOR: &str = "198.51.100.9:50000";
const LOCAL: &str = "203.0.113.7:80";

// ---- backends ----

/// An HTTP/1.1 server on loopback. It answers each request with 200, `X-Tag: <tag>`,
/// `X-Backend: internal`, and a body of `<tag>\n` followed by the request head exactly as it
/// arrived. A request to upgrade to WebSocket gets 101, and then everything is echoed.
async fn backend(tag: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(serve(stream, tag));
        }
    });
    addr
}

async fn serve(mut stream: TcpStream, tag: &'static str) {
    let mut buf = Vec::new();
    loop {
        let end = loop {
            if let Some(i) = find(&buf, b"\r\n\r\n") {
                break i + 4;
            }
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        let head: Vec<u8> = buf.drain(..end).collect();
        let upgrade = values(&head, "upgrade")
            .iter()
            .any(|v| v.eq_ignore_ascii_case(b"websocket"));
        if upgrade {
            // The accept value of RFC 6455's example key, which the tests send.
            let reply = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                         Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
            if stream.write_all(reply.as_bytes()).await.is_err()
                || stream.write_all(&buf).await.is_err()
            {
                return;
            }
            let (mut rd, mut wr) = stream.split();
            let _ = tokio::io::copy(&mut rd, &mut wr).await;
            return;
        }
        let mut body = format!("{tag}\n").into_bytes();
        body.extend_from_slice(&head);
        let reply = format!(
            "HTTP/1.1 200 OK\r\nX-Tag: {tag}\r\nX-Backend: internal\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        if stream.write_all(reply.as_bytes()).await.is_err()
            || stream.write_all(&body).await.is_err()
        {
            return;
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The values of header `name` (any case) in an HTTP message head, in order, without the
/// whitespace around them.
fn values(head: &[u8], name: &str) -> Vec<Vec<u8>> {
    head.split(|&b| b == b'\n')
        .skip(1)
        .filter_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let colon = line.iter().position(|&b| b == b':')?;
            let (n, v) = (&line[..colon], &line[colon + 1..]);
            n.eq_ignore_ascii_case(name.as_bytes())
                .then(|| v.trim_ascii().to_vec())
        })
        .collect()
}

// ---- requests ----

struct Response {
    status: u16,
    head: Vec<u8>,
    body: Vec<u8>,
}

impl Response {
    fn parse(raw: &[u8]) -> Self {
        let end = find(raw, b"\r\n\r\n")
            .unwrap_or_else(|| panic!("no response head in {:?}", String::from_utf8_lossy(raw)));
        let head = raw[..end + 2].to_vec();
        let status = std::str::from_utf8(&head[9..12])
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("bad status line in {:?}", String::from_utf8_lossy(raw)));
        Self {
            status,
            head,
            body: raw[end + 4..].to_vec(),
        }
    }

    /// The values of response header `name`, as text.
    fn header(&self, name: &str) -> Vec<String> {
        values(&self.head, name)
            .into_iter()
            .map(|v| String::from_utf8(v).unwrap())
            .collect()
    }

    /// The tag of the backend that answered; panics unless one did.
    fn tag(&self) -> &str {
        assert_eq!(self.status, 200, "{}", self.describe());
        let line = self.body.split(|&b| b == b'\n').next().unwrap();
        std::str::from_utf8(line).unwrap()
    }

    /// The values of request header `name` as the backend received them.
    fn seen(&self, name: &str) -> Vec<Vec<u8>> {
        self.tag();
        let at = self.body.iter().position(|&b| b == b'\n').unwrap();
        values(&self.body[at + 1..], name)
    }

    fn describe(&self) -> String {
        format!(
            "{}{}",
            String::from_utf8_lossy(&self.head),
            String::from_utf8_lossy(&self.body)
        )
    }
}

fn request(host: &str, path: &str) -> Vec<u8> {
    request_with("GET", host, path, &[])
}

fn request_with(method: &str, host: &str, path: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut r = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (n, v) in headers {
        r.push_str(&format!("{n}: {v}\r\n"));
    }
    r.push_str("\r\n");
    r.into_bytes()
}

/// Connects to the socket of port `id` and writes the PROXY v2 header for [`VISITOR`].
async fn connect(dir: &Path, id: &str) -> UnixStream {
    let path = dir.join("s").join(format!("{id}.sock"));
    // Right after a reload a connection can be refused once: try again a little later.
    let mut attempts = 0;
    let mut s = loop {
        match timeout(STEP, UnixStream::connect(&path)).await.unwrap() {
            Ok(s) => break s,
            Err(_) if attempts < 50 => {
                attempts += 1;
                sleep(Duration::from_millis(20)).await;
            }
            Err(e) => panic!("connecting to {}: {e}", path.display()),
        }
    };
    let header = proxyv2::header(VISITOR.parse().unwrap(), LOCAL.parse().unwrap());
    s.write_all(&header).await.unwrap();
    s
}

/// Writes `request` and reads the response up to the end of the connection.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, request: &[u8]) -> Response {
    s.write_all(request).await.unwrap();
    let mut raw = Vec::new();
    timeout(STEP, async {
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => raw.extend_from_slice(&buf[..n]),
                // A TLS peer that closes without close_notify.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("reading the response: {e}"),
            }
        }
    })
    .await
    .expect("no complete response in time");
    Response::parse(&raw)
}

/// One request to port `id`, on a connection of its own.
async fn get(dir: &Path, id: &str, request: &[u8]) -> Response {
    let mut s = connect(dir, id).await;
    exchange(&mut s, request).await
}

// ---- models ----

fn gateway_key() -> ObjRef {
    ObjRef::new("gw", "public")
}

/// The id of port `port` of gw/public.
fn id(port: u16) -> String {
    port_id(&gateway_key(), port)
}

fn exact(h: &str) -> HostMatch {
    HostMatch::Exact(h.into())
}

fn prefix(p: &str) -> PathMatch {
    PathMatch::Prefix(p.into())
}

fn exact_path(p: &str) -> PathMatch {
    PathMatch::Exact(p.into())
}

fn rule(host: HostMatch, path: PathMatch, backend: usize) -> HttpRule {
    HttpRule {
        host,
        path,
        method: None,
        headers: Vec::new(),
        backend,
    }
}

/// A rule for every request.
fn any(backend: usize) -> HttpRule {
    rule(HostMatch::Any, prefix("/"), backend)
}

fn server(addr: SocketAddr, weight: u32) -> Backend {
    Backend {
        service: ObjRef::new("gw", "web"),
        ip: addr.ip(),
        port: addr.port(),
        weight,
    }
}

fn action(action: HttpAction) -> HttpBackend {
    HttpBackend {
        route: ObjRef::new("gw", "r"),
        rule: 0,
        request_headers: HeaderMods::default(),
        response_headers: HeaderMods::default(),
        action,
    }
}

/// Forwards to `addr`.
fn to(addr: SocketAddr) -> HttpBackend {
    action(HttpAction::Forward(vec![server(addr, 1)]))
}

fn http_port(port: u16, rules: Vec<HttpRule>, backends: Vec<HttpBackend>) -> HttpPort {
    HttpPort {
        port,
        tls: None,
        rules,
        backends,
    }
}

fn https_port(
    port: u16,
    certificates: Vec<Certificate>,
    rules: Vec<HttpRule>,
    backends: Vec<HttpBackend>,
) -> HttpPort {
    HttpPort {
        tls: Some(certificates),
        ..http_port(port, rules, backends)
    }
}

/// gw/public with `ports` and `listeners`.
fn gateway(ports: Vec<HttpPort>, listeners: Vec<ListenerModel>) -> GatewayModel {
    GatewayModel {
        key: gateway_key(),
        generation: 1,
        accepted: Ok(()),
        listeners,
        edges: Vec::new(),
        http_ports: ports,
    }
}

fn model(ports: Vec<HttpPort>) -> Model {
    Model {
        classes: Vec::new(),
        gateways: vec![gateway(ports, Vec::new())],
        edges: Vec::new(),
        routes: Vec::new(),
    }
}

fn empty_model() -> Model {
    Model {
        classes: Vec::new(),
        gateways: Vec::new(),
        edges: Vec::new(),
        routes: Vec::new(),
    }
}

// ---- HAProxy ----

fn opts(runtime: &Path) -> SupervisorOptions {
    SupervisorOptions {
        haproxy_bin: "haproxy".into(),
        runtime_dir: runtime.to_path_buf(),
        reload_timeout: Duration::from_secs(30),
        inherit_output: false,
    }
}

/// HAProxy serving a model, in a directory of its own.
struct Served {
    dir: TempDir,
    sup: Supervisor,
    rendered: Rendered,
}

impl Served {
    /// Starts HAProxy with the empty model, then applies `m` with its files.
    async fn start(m: &Model) -> Self {
        let dir = short_dir();
        let empty = render(&empty_model(), dir.path());
        let sup = Supervisor::start(opts(dir.path()), &empty.haproxy_cfg)
            .await
            .unwrap();
        let mut served = Self {
            dir,
            sup,
            rendered: empty,
        };
        served.apply(m).await;
        served
    }

    async fn apply(&mut self, m: &Model) {
        let rendered = render(m, self.dir.path());
        let applied = self
            .sup
            .apply(&rendered.haproxy_cfg, &rendered.files)
            .await
            .unwrap_or_else(|e| panic!("{e}\n{}", rendered.haproxy_cfg));
        assert_eq!(applied, Applied::Reloaded);
        self.rendered = rendered;
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    async fn get(&self, port: u16, request: &[u8]) -> Response {
        get(self.path(), &id(port), request).await
    }

    async fn shutdown(self) {
        self.sup.shutdown().await;
    }
}

// ---- TLS ----

/// A certificate authority for the tests.
struct Ca(CertifiedIssuer<'static, KeyPair>);

impl Ca {
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "iroh-gateway test CA");
        Self(CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap())
    }

    fn root(&self) -> CertificateDer<'static> {
        self.0.der().clone()
    }

    /// A certificate for `host` signed by this CA, as Secret gw/<secret> would give it, and the
    /// leaf in DER.
    fn issue(&self, secret: &str, host: &str) -> (Certificate, CertificateDer<'static>) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![host.to_owned()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = params.signed_by(&key, &*self.0).unwrap();
        let pem = format!("{}{}", leaf.pem(), key.serialize_pem());
        let file_name = format!(
            "gw.{secret}.{}.pem",
            &hex::encode(Sha256::digest(pem.as_bytes()))[..16]
        );
        let certificate = Certificate {
            secret: ObjRef::new("gw", secret),
            file_name,
            pem,
        };
        (certificate, leaf.der().clone())
    }
}

/// Connects to port `id` and shakes hands with SNI `sni`, trusting only `root` and offering
/// `alpn`.
async fn tls(
    dir: &Path,
    id: &str,
    sni: &str,
    root: &CertificateDer<'static>,
    alpn: &[&[u8]],
) -> std::io::Result<TlsStream<UnixStream>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = connect(dir, id).await;
    let name = ServerName::try_from(sni.to_owned()).unwrap();
    timeout(STEP, connector.connect(name, stream))
        .await
        .expect("handshake timed out")
}

/// The leaf certificate the server presented.
fn presented(s: &TlsStream<UnixStream>) -> CertificateDer<'static> {
    s.get_ref().1.peer_certificates().expect("a certificate")[0].clone()
}

/// The names in `<dir>/certs`, sorted.
fn cert_files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir.join(CERT_DIR))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

// ---- tests ----

#[tokio::test]
async fn rendered_http_configuration_is_valid() {
    let (a, b) = (backend("A").await, backend("B").await);
    let ca = Ca::new();
    let (one, _) = ca.issue("one", "a.example.com");
    let (two, _) = ca.issue("two", "b.example.com");
    let header_rule = |headers: usize, backend: usize| {
        let mut r = rule(exact("a.example.com"), exact_path("/h"), backend);
        r.method = Some("GET".into());
        r.headers = (0..headers)
            .map(|i| (format!("x-h{i:02}"), format!("v{i}")))
            .collect();
        r
    };
    let mut filtered = to(a);
    filtered.request_headers = HeaderMods {
        set: vec![("x-a".into(), "1".into())],
        add: vec![("x-b".into(), "2".into())],
        remove: vec!["x-c".into()],
    };
    filtered.response_headers = HeaderMods {
        set: vec![("x-d".into(), "4".into())],
        add: vec![("x-e".into(), "5".into())],
        remove: vec!["x-backend".into()],
    };
    let rules = vec![
        // Six and sixteen header matches (sixteen is the most a route may have), with host,
        // path and method.
        header_rule(6, 0),
        header_rule(16, 0),
        rule(exact("a.example.com"), exact_path("/x"), 0),
        rule(HostMatch::Wildcard(".example.com".into()), prefix("/r"), 2),
        rule(HostMatch::Any, prefix("/fail"), 3),
        any(1),
    ];
    let backends = vec![
        filtered,
        action(HttpAction::Forward(vec![server(a, 3), server(b, 1)])),
        action(HttpAction::Redirect(Redirect {
            scheme: Some("https".into()),
            hostname: Some("c.example.com".into()),
            port: Some(8443),
            status: 308,
        })),
        action(HttpAction::Fail),
        // A route rule whose matches were all dropped as repeats.
        to(b),
    ];
    let tcp = ListenerModel {
        name: "pg".into(),
        port: 5432,
        protocol: "TCP".into(),
        hostname: HostMatch::Any,
        accepted: Ok(()),
        conflicted: None,
        resolved_refs: Ok(()),
        supported_kinds: vec!["TCPRoute".into()],
        allowed_namespaces: Default::default(),
        attached_routes: 1,
        backends: vec![server(a, 1)],
        certificates: Vec::new(),
    };
    let m = Model {
        classes: Vec::new(),
        gateways: vec![gateway(
            vec![
                http_port(80, rules.clone(), backends.clone()),
                https_port(443, vec![one, two], rules, backends),
            ],
            vec![tcp],
        )],
        edges: Vec::new(),
        routes: Vec::new(),
    };
    // The longest runtime directory the supervisor accepts.
    let dir = short_dir();
    let mut runtime = dir.path().as_os_str().to_owned();
    runtime.push("/");
    while runtime.len() < MAX_RUNTIME_DIR_LEN {
        runtime.push("r");
    }
    let runtime = std::path::PathBuf::from(runtime);
    let empty = render(&empty_model(), &runtime);
    let mut sup = Supervisor::start(opts(&runtime), &empty.haproxy_cfg)
        .await
        .unwrap();
    let rendered = render(&m, &runtime);
    assert!(
        rendered
            .haproxy_cfg
            .contains("    acl r1_h15 req.fhdr(x-h15) -m str -- 'v15'\n")
    );
    // Two certificates and their list.
    assert_eq!(rendered.files.len(), 3, "{:?}", rendered.files);
    let applied = sup.apply(&rendered.haproxy_cfg, &rendered.files).await;
    assert!(
        matches!(applied, Ok(Applied::Reloaded)),
        "{applied:?}\n{}",
        rendered.haproxy_cfg
    );
    for port in [80, 443, 5432] {
        let socket = runtime.join("s").join(format!("{}.sock", id(port)));
        assert!(socket.exists(), "{}", socket.display());
    }
    assert_eq!(
        cert_files(&runtime),
        rendered
            .files
            .iter()
            .map(|f| f.name.clone())
            .collect::<Vec<_>>()
    );
    // It serves, too.
    let r = get(&runtime, &id(80), &request("a.example.com", "/x")).await;
    assert_eq!(r.tag(), "A");
    sup.shutdown().await;
}

#[tokio::test]
async fn routes_by_host_and_path() {
    let (a, b, c) = (backend("A").await, backend("B").await, backend("C").await);
    let m = model(vec![http_port(
        80,
        vec![
            rule(exact("a.example.com"), prefix("/"), 0),
            rule(exact("b.example.com"), prefix("/"), 1),
            rule(HostMatch::Any, prefix("/c"), 2),
        ],
        vec![to(a), to(b), to(c)],
    )]);
    let s = Served::start(&m).await;
    for (host, path, want) in [
        ("a.example.com", "/", "A"),
        ("a.example.com", "/x/y", "A"),
        ("a.example.com", "/c", "A"),
        ("b.example.com", "/", "B"),
        ("b.example.com", "/c", "B"),
        ("other.example.com", "/c", "C"),
        ("other.example.com", "/c/d", "C"),
    ] {
        let r = s.get(80, &request(host, path)).await;
        assert_eq!(r.tag(), want, "{host}{path}");
    }
    assert_eq!(
        s.get(80, &request("other.example.com", "/")).await.status,
        404
    );
    s.shutdown().await;
}

#[tokio::test]
async fn prefix_matches_whole_path_elements() {
    let a = backend("A").await;
    let m = model(vec![http_port(
        80,
        vec![rule(HostMatch::Any, prefix("/foo"), 0)],
        vec![to(a)],
    )]);
    let s = Served::start(&m).await;
    for path in [
        "/foo",
        "/foo/",
        "/foo/bar",
        "/foo?x=1",
        "/foo/bar?x=/foobar",
    ] {
        assert_eq!(s.get(80, &request("a", path)).await.tag(), "A", "{path}");
    }
    for path in ["/foobar", "/fo", "/", "/bar/foo", "/foobar/foo"] {
        assert_eq!(s.get(80, &request("a", path)).await.status, 404, "{path}");
    }
    s.shutdown().await;
}

#[tokio::test]
async fn exact_path_beats_prefix_and_longer_prefix_wins() {
    let (e, l, short, root) = (
        backend("E").await,
        backend("L").await,
        backend("S").await,
        backend("R").await,
    );
    // In the order the model gives them.
    let m = model(vec![http_port(
        80,
        vec![
            rule(HostMatch::Any, exact_path("/a/b"), 0),
            rule(HostMatch::Any, prefix("/a/b"), 1),
            rule(HostMatch::Any, prefix("/a"), 2),
            rule(HostMatch::Any, prefix("/"), 3),
        ],
        vec![to(e), to(l), to(short), to(root)],
    )]);
    let s = Served::start(&m).await;
    for (path, want) in [
        ("/a/b", "E"),
        ("/a/b?q", "E"),
        ("/a/b/", "L"),
        ("/a/b/c", "L"),
        ("/a/bc", "S"),
        ("/a", "S"),
        ("/a/x", "S"),
        ("/ab", "R"),
        ("/", "R"),
    ] {
        assert_eq!(s.get(80, &request("a", path)).await.tag(), want, "{path}");
    }
    s.shutdown().await;
}

#[tokio::test]
async fn host_header_with_port_and_upper_case_still_matches() {
    let a = backend("A").await;
    let m = model(vec![http_port(
        80,
        vec![rule(exact("example.com"), prefix("/"), 0)],
        vec![to(a)],
    )]);
    let s = Served::start(&m).await;
    for host in ["EXAMPLE.com:8080", "example.com", "Example.Com:80"] {
        assert_eq!(s.get(80, &request(host, "/")).await.tag(), "A", "{host}");
    }
    for host in ["example.org", "a.example.com", "example.com.evil"] {
        assert_eq!(s.get(80, &request(host, "/")).await.status, 404, "{host}");
    }
    s.shutdown().await;
}

#[tokio::test]
async fn wildcard_host_matches_subdomains_only() {
    let a = backend("A").await;
    let m = model(vec![http_port(
        80,
        vec![rule(
            HostMatch::Wildcard(".example.com".into()),
            prefix("/"),
            0,
        )],
        vec![to(a)],
    )]);
    let s = Served::start(&m).await;
    for host in ["a.example.com", "b.a.example.com", "A.Example.COM:8080"] {
        assert_eq!(s.get(80, &request(host, "/")).await.tag(), "A", "{host}");
    }
    for host in ["example.com", "badexample.com", "a.example.org"] {
        assert_eq!(s.get(80, &request(host, "/")).await.status, 404, "{host}");
    }
    s.shutdown().await;
}

#[tokio::test]
async fn method_and_header_matches_select_the_backend() {
    let (p, h, many, d) = (
        backend("P").await,
        backend("H").await,
        backend("M").await,
        backend("D").await,
    );
    let mut post = any(0);
    post.method = Some("POST".into());
    let mut header = any(1);
    header.headers = vec![("x-env".into(), "prod".into())];
    // Sixteen header matches, the most a route may have.
    let sixteen: Vec<(String, String)> = (0..16)
        .map(|i| (format!("x-h{i:02}"), format!("v{i}")))
        .collect();
    let mut all = rule(HostMatch::Any, prefix("/many"), 2);
    all.method = Some("GET".into());
    all.headers = sixteen.clone();
    let m = model(vec![http_port(
        80,
        vec![all, post, header, any(3)],
        vec![to(p), to(h), to(many), to(d)],
    )]);
    let s = Served::start(&m).await;
    let send = |method: &'static str, path: &'static str, headers: Vec<(String, String)>| {
        let headers: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        request_with(method, "a", path, &headers)
    };
    let one = |n: &str, v: &str| vec![(n.to_owned(), v.to_owned())];
    for (req, want) in [
        (send("POST", "/", vec![]), "P"),
        (send("POST", "/", one("x-env", "prod")), "P"),
        (send("GET", "/", one("x-env", "prod")), "H"),
        (send("GET", "/", one("X-Env", "prod")), "H"),
        (send("GET", "/", one("x-env", "PROD")), "D"),
        (send("GET", "/", one("x-env", "prod2")), "D"),
        (send("GET", "/", vec![]), "D"),
        (send("PUT", "/", vec![]), "D"),
        (send("GET", "/many", sixteen.clone()), "M"),
        (send("GET", "/many", sixteen[1..].to_vec()), "D"),
        (send("POST", "/many", sixteen.clone()), "P"),
    ] {
        let r = s.get(80, &req).await;
        assert_eq!(r.tag(), want, "{}", String::from_utf8_lossy(&req));
    }
    // One wrong value among the sixteen.
    let mut wrong = sixteen.clone();
    wrong[15].1 = "nope".into();
    assert_eq!(s.get(80, &send("GET", "/many", wrong)).await.tag(), "D");
    s.shutdown().await;
}

#[tokio::test]
async fn unknown_host_gets_404() {
    let a = backend("A").await;
    let m = model(vec![http_port(
        80,
        vec![rule(exact("a.example.com"), prefix("/"), 0)],
        vec![to(a)],
    )]);
    let s = Served::start(&m).await;
    let r = s.get(80, &request("b.example.com", "/")).await;
    assert_eq!(r.status, 404, "{}", r.describe());
    assert!(r.header("x-tag").is_empty());
    assert!(!r.body.starts_with(b"A\n"));
    s.shutdown().await;
}

#[tokio::test]
async fn rule_without_usable_backend_gets_500() {
    let a = backend("A").await;
    let m = model(vec![http_port(
        80,
        vec![rule(HostMatch::Any, prefix("/broken"), 0), any(1)],
        vec![action(HttpAction::Fail), to(a)],
    )]);
    let s = Served::start(&m).await;
    let r = s.get(80, &request("a", "/broken/x")).await;
    assert_eq!(r.status, 500, "{}", r.describe());
    assert!(r.header("x-tag").is_empty());
    assert_eq!(s.get(80, &request("a", "/fine")).await.tag(), "A");
    s.shutdown().await;
}

#[tokio::test]
async fn redirect_to_https_keeps_host_path_and_query() {
    let m = model(vec![http_port(
        80,
        vec![any(0)],
        vec![action(HttpAction::Redirect(Redirect {
            scheme: Some("https".into()),
            hostname: None,
            port: None,
            status: 301,
        }))],
    )]);
    let s = Served::start(&m).await;
    for host in ["example.com", "example.com:80"] {
        let r = s.get(80, &request(host, "/a?b=c")).await;
        assert_eq!(r.status, 301, "{}", r.describe());
        assert_eq!(r.header("location"), ["https://example.com/a?b=c"]);
    }
    let r = s.get(80, &request("example.com", "/")).await;
    assert_eq!(r.header("location"), ["https://example.com/"]);
    s.shutdown().await;
}

#[tokio::test]
async fn request_and_response_header_filters_apply() {
    let a = backend("A").await;
    let mut filtered = to(a);
    filtered.request_headers = HeaderMods {
        set: vec![("x-set".into(), "new".into())],
        add: vec![("x-add".into(), "two".into())],
        remove: vec!["x-remove".into()],
    };
    filtered.response_headers = HeaderMods {
        set: vec![("x-tag".into(), "replaced".into())],
        add: vec![("x-resp-add".into(), "added".into())],
        remove: vec!["x-backend".into()],
    };
    let m = model(vec![http_port(80, vec![any(0)], vec![filtered])]);
    let s = Served::start(&m).await;
    let req = request_with(
        "GET",
        "a",
        "/",
        &[
            ("X-Set", "old"),
            ("X-Add", "one"),
            ("X-Remove", "gone"),
            ("X-Keep", "kept"),
        ],
    );
    let r = s.get(80, &req).await;
    assert_eq!(r.status, 200, "{}", r.describe());
    assert_eq!(r.seen("x-set"), [b"new".to_vec()]);
    assert_eq!(r.seen("x-add"), [b"one".to_vec(), b"two".to_vec()]);
    assert!(r.seen("x-remove").is_empty());
    assert_eq!(r.seen("x-keep"), [b"kept".to_vec()]);
    // The body still starts with the backend's own tag.
    assert!(r.body.starts_with(b"A\n"));
    assert_eq!(r.header("x-tag"), ["replaced"]);
    assert_eq!(r.header("x-resp-add"), ["added"]);
    assert!(r.header("x-backend").is_empty());
    s.shutdown().await;
}

#[tokio::test]
async fn response_header_filters_apply_to_redirects_and_errors() {
    let a = backend("A").await;
    let response_headers = HeaderMods {
        set: vec![("strict-transport-security".into(), "max-age=60".into())],
        add: vec![("x-added".into(), "yes".into())],
        remove: vec!["x-backend".into()],
    };
    let with_headers = |mut b: HttpBackend| {
        b.response_headers = response_headers.clone();
        b
    };
    let m = model(vec![http_port(
        80,
        vec![
            rule(HostMatch::Any, prefix("/redirect"), 0),
            rule(HostMatch::Any, prefix("/fail"), 1),
            any(2),
        ],
        vec![
            with_headers(action(HttpAction::Redirect(Redirect {
                scheme: Some("https".into()),
                hostname: None,
                port: None,
                status: 301,
            }))),
            with_headers(action(HttpAction::Fail)),
            with_headers(to(a)),
        ],
    )]);
    let s = Served::start(&m).await;
    for (path, status) in [("/redirect", 301), ("/fail", 500), ("/", 200)] {
        let r = s.get(80, &request("example.com", path)).await;
        assert_eq!(r.status, status, "{}", r.describe());
        assert_eq!(
            r.header("strict-transport-security"),
            ["max-age=60"],
            "{path}: {}",
            r.describe()
        );
        assert_eq!(r.header("x-added"), ["yes"], "{path}");
        assert!(r.header("x-backend").is_empty(), "{path}");
    }
    s.shutdown().await;
}

#[tokio::test]
async fn x_forwarded_headers_are_set_and_cannot_be_forged() {
    let a = backend("A").await;
    let s = Served::start(&model(vec![http_port(80, vec![any(0)], vec![to(a)])])).await;
    let req = request_with(
        "GET",
        "app.example.com",
        "/",
        &[
            ("X-Forwarded-For", "1.2.3.4"),
            ("X-Forwarded-Proto", "https"),
            ("X-Forwarded-Host", "evil.example.com"),
            ("X-Forwarded-Port", "8443"),
            ("Forwarded", "for=1.2.3.4;host=evil.example.com;proto=https"),
            ("X-Real-IP", "1.2.3.4"),
        ],
    );
    let r = s.get(80, &req).await;
    assert_eq!(r.seen("x-forwarded-for"), [b"198.51.100.9".to_vec()]);
    assert_eq!(r.seen("x-forwarded-proto"), [b"http".to_vec()]);
    // The request's own host, and the port the visitor connected to (the PROXY header's).
    assert_eq!(r.seen("x-forwarded-host"), [b"app.example.com".to_vec()]);
    assert_eq!(r.seen("x-forwarded-port"), [b"80".to_vec()]);
    assert!(r.seen("forwarded").is_empty(), "{}", r.describe());
    assert!(r.seen("x-real-ip").is_empty(), "{}", r.describe());
    s.shutdown().await;
}

#[tokio::test]
async fn weighted_backends_share_the_traffic() {
    let (a, b) = (backend("A").await, backend("B").await);
    let m = model(vec![
        http_port(
            80,
            vec![any(0)],
            vec![action(HttpAction::Forward(vec![
                server(a, 1),
                server(b, 0),
            ]))],
        ),
        http_port(
            81,
            vec![any(0)],
            vec![action(HttpAction::Forward(vec![
                server(a, 1),
                server(b, 1),
            ]))],
        ),
    ]);
    let s = Served::start(&m).await;
    for _ in 0..10 {
        assert_eq!(s.get(80, &request("a", "/")).await.tag(), "A");
    }
    // With equal weights both get requests.
    let mut seen = BTreeSet::new();
    for _ in 0..10 {
        seen.insert(s.get(81, &request("a", "/")).await.tag().to_owned());
    }
    assert_eq!(seen, BTreeSet::from(["A".to_owned(), "B".to_owned()]));
    s.shutdown().await;
}

#[tokio::test]
async fn websocket_upgrade_passes_bytes_both_ways() {
    let a = backend("A").await;
    let s = Served::start(&model(vec![http_port(80, vec![any(0)], vec![to(a)])])).await;
    let mut conn = connect(s.path(), &id(80)).await;
    conn.write_all(
        b"GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .await
    .unwrap();
    let mut head = Vec::new();
    timeout(STEP, async {
        while find(&head, b"\r\n\r\n").is_none() {
            let mut b = [0u8; 1];
            conn.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
        }
    })
    .await
    .expect("no upgrade response");
    let r = Response::parse(&head);
    assert_eq!(r.status, 101, "{}", r.describe());
    for msg in [&b"ping"[..], b"\x00\x01\xff binary", b"pong"] {
        conn.write_all(msg).await.unwrap();
        let mut back = vec![0u8; msg.len()];
        timeout(STEP, conn.read_exact(&mut back))
            .await
            .expect("no echo in time")
            .unwrap();
        assert_eq!(back, msg);
    }
    drop(conn);
    s.shutdown().await;
}

#[tokio::test]
async fn hostile_strings_cannot_inject_configuration() {
    let (d, literal, sendable, matched) = (
        backend("D").await,
        backend("L").await,
        backend("S").await,
        backend("M").await,
    );
    // (header, value, the value as it must stand in the configuration).
    let set: [(&str, &str, &str); 10] = [
        ("x-h1", "%[src]", "'%%[src]'"),
        ("x-h2", "%[env(HOME)]", "'%%[env(HOME)]'"),
        ("x-h3", "${HOME}", "'${HOME}'"),
        ("x-h4", "\"$HOME\"", "'\"$HOME\"'"),
        ("x-h5", "ends in a backslash \\", "'ends in a backslash \\'"),
        ("x-h6", "gr\u{fc}\u{df}e", "'gr\u{fc}\u{df}e'"),
        ("x-h7", "it's # not a comment", "'it'\\''s # not a comment'"),
        ("x-h8", "100% \\' %%", "'100%% \\'\\'' %%%%'"),
        (
            "x-h9",
            "' } use_backend be_x if TRUE #",
            "''\\'' } use_backend be_x if TRUE #'",
        ),
        // Repeated spaces inside one quoted word stay as they are.
        ("x-h10", "a  b   c", "'a  b   c'"),
    ];
    let mut with_headers = to(d);
    with_headers.request_headers.set = set
        .iter()
        .map(|(n, v, _)| ((*n).to_owned(), (*v).to_owned()))
        .collect();
    let literal_path = "/a b'c\"d#e";
    let sendable_path = "/x'y\"z$HOME%41\\w";
    let match_value = "'; } default_backend be_none #\\";
    let mut header_rule = any(3);
    header_rule.headers = vec![("x-match".into(), match_value.into())];
    // Values that are HAProxy syntax on their own, as whole words: each header match has a
    // backend of its own, and each set value must arrive as it is.
    let words: [(&str, &'static str); 9] = [
        ("}", "W0"),
        ("{", "W1"),
        ("||", "W2"),
        ("!", "W3"),
        ("if", "W4"),
        ("unless", "W5"),
        ("--", "W6"),
        ("-m", "W7"),
        ("-i", "W8"),
    ];
    let set_words = [
        ("x-w1", "}"),
        ("x-w2", "if"),
        ("x-w3", "unless"),
        ("x-w4", "--"),
    ];
    with_headers.request_headers.set.extend(
        set_words
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned())),
    );
    let mut rules = vec![
        rule(HostMatch::Any, exact_path(literal_path), 1),
        rule(HostMatch::Any, exact_path(sendable_path), 2),
        header_rule,
    ];
    let mut backends = vec![with_headers, to(literal), to(sendable), to(matched)];
    for (k, (word, tag)) in words.iter().enumerate() {
        let mut r = any(4 + k);
        r.headers = vec![("x-word".into(), (*word).into())];
        rules.push(r);
        backends.push(to(backend(tag).await));
    }
    rules.push(any(0));
    let m = model(vec![http_port(80, rules, backends)]);
    let s = Served::start(&m).await;

    // The configuration has each value only as its quoted word.
    let quoted: Vec<&str> = set
        .iter()
        .map(|(_, _, q)| *q)
        .chain([
            "'/a b'\\''c\"d#e'",
            "'/x'\\''y\"z$HOME%41\\w'",
            "''\\''; } default_backend be_none #\\'",
        ])
        .collect();
    let cfg = &s.rendered.haproxy_cfg;
    let mut stripped = cfg.clone();
    for q in &quoted {
        assert!(cfg.contains(q), "{q} not in\n{cfg}");
        stripped = stripped.replace(q, "<quoted>");
    }
    for value in set
        .iter()
        .map(|(_, v, _)| *v)
        .chain([literal_path, sendable_path, match_value])
    {
        // `%[src]` is in the template's own X-Forwarded-For line, and only there.
        let allowed = usize::from(value == "%[src]");
        assert_eq!(
            stripped.matches(value).count(),
            allowed,
            "{value}\n{stripped}"
        );
    }
    for fragment in [
        "env(HOME)",
        "$HOME",
        "gr\u{fc}\u{df}e",
        "be_x",
        "be_none",
        "b'c",
        "#e",
    ] {
        assert!(!stripped.contains(fragment), "{fragment}\n{stripped}");
    }

    // The backend receives each value byte for byte.
    let r = s.get(80, &request("a", "/")).await;
    assert_eq!(r.tag(), "D");
    for (name, value, _) in set {
        assert_eq!(r.seen(name), [value.as_bytes().to_vec()], "{name}");
    }
    // A path matches only its literal self: neither decoded nor encoded forms.
    assert_eq!(s.get(80, &request("a", sendable_path)).await.tag(), "S");
    for path in [
        "/x'y\"z$HOMEA\\w",
        "/x%27y%22z$HOME%41%5Cw",
        "/x'y\"z$HOME%41\\",
        "/x'y\"z",
        "/a",
        "/a%20b'c%22d%23e",
        "/a%20b%27c%22d%23e",
    ] {
        assert_eq!(s.get(80, &request("a", path)).await.tag(), "D", "{path}");
    }
    // The literal path itself cannot be sent: HAProxy refuses a request line with a space or
    // a '#' in its target before any rule runs, so it never reaches the backend. (The model
    // refuses a route with such a path; this hand-built model tests the quoting alone.)
    let r = s.get(80, &request("a", literal_path)).await;
    assert_eq!(r.status, 400, "{}", r.describe());
    // A header value matches only its literal self.
    let with = |v: &str| request_with("GET", "a", "/", &[("X-Match", v)]);
    assert_eq!(s.get(80, &with(match_value)).await.tag(), "M");
    assert_eq!(s.get(80, &with("';")).await.tag(), "D");
    assert_eq!(
        s.get(80, &with("'; } default_backend be_none #"))
            .await
            .tag(),
        "D"
    );
    // Each syntax word stands as a quoted pattern of its own ACL, and selects its backend only
    // for exactly that value.
    for (k, (word, tag)) in words.iter().enumerate() {
        let acl = format!(
            "    acl r{}_h0 req.fhdr(x-word) -m str -- '{word}'\n",
            3 + k
        );
        assert!(cfg.contains(&acl), "{acl}\n{cfg}");
        let with = |v: &str| request_with("GET", "a", "/", &[("X-Word", v)]);
        assert_eq!(s.get(80, &with(word)).await.tag(), *tag, "{word}");
        for other in [format!("{word}x"), format!("x{word}"), word.to_uppercase()] {
            if other != *word {
                assert_eq!(s.get(80, &with(&other)).await.tag(), "D", "{other}");
            }
        }
    }
    let r = s.get(80, &request("a", "/")).await;
    for (name, value) in set_words {
        let line = format!("    http-request set-header '{name}' '{value}'\n");
        assert!(cfg.contains(&line), "{line}\n{cfg}");
        assert_eq!(r.seen(name), [value.as_bytes().to_vec()], "{name}");
    }
    s.shutdown().await;
}

/// gw/public with one HTTPS port 443 for `certificates`, every request to `addr`.
fn https_model(certificates: Vec<Certificate>, addr: SocketAddr) -> Model {
    model(vec![https_port(
        443,
        certificates,
        vec![any(0)],
        vec![to(addr)],
    )])
}

#[tokio::test]
async fn https_terminates_tls_with_the_certificate() {
    let a = backend("A").await;
    let ca = Ca::new();
    let (cert, leaf) = ca.issue("site", "app.example.com");
    let s = Served::start(&https_model(vec![cert], a)).await;
    let mut conn = tls(
        s.path(),
        &id(443),
        "app.example.com",
        &ca.root(),
        &[b"http/1.1"],
    )
    .await
    .expect("handshake");
    assert_eq!(presented(&conn), leaf);
    assert_eq!(conn.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    let r = exchange(&mut conn, &request("app.example.com", "/")).await;
    assert_eq!(r.tag(), "A");
    assert_eq!(r.seen("x-forwarded-proto"), [b"https".to_vec()]);
    assert_eq!(r.seen("x-forwarded-for"), [b"198.51.100.9".to_vec()]);
    drop(conn);
    s.shutdown().await;
}

#[tokio::test]
async fn https_negotiates_h2_when_offered() {
    let a = backend("A").await;
    let ca = Ca::new();
    let (cert, _) = ca.issue("site", "app.example.com");
    let s = Served::start(&https_model(vec![cert], a)).await;
    let conn = tls(
        s.path(),
        &id(443),
        "app.example.com",
        &ca.root(),
        &[b"h2", b"http/1.1"],
    )
    .await
    .expect("handshake");
    assert_eq!(conn.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    drop(conn);
    s.shutdown().await;
}

#[tokio::test]
async fn two_certificates_on_one_port_are_chosen_by_sni() {
    let a = backend("A").await;
    let ca = Ca::new();
    let (one, one_leaf) = ca.issue("one", "a.example.com");
    let (two, two_leaf) = ca.issue("two", "b.example.com");
    let s = Served::start(&https_model(vec![one, two], a)).await;
    for (sni, leaf) in [("a.example.com", &one_leaf), ("b.example.com", &two_leaf)] {
        let mut conn = tls(s.path(), &id(443), sni, &ca.root(), &[b"http/1.1"])
            .await
            .expect("handshake");
        assert_eq!(&presented(&conn), leaf, "{sni}");
        assert_eq!(exchange(&mut conn, &request(sni, "/")).await.tag(), "A");
    }
    s.shutdown().await;
}

#[tokio::test]
async fn unknown_sni_fails_the_handshake() {
    let a = backend("A").await;
    let ca = Ca::new();
    let (cert, _) = ca.issue("site", "app.example.com");
    let s = Served::start(&https_model(vec![cert], a)).await;
    let refused = tls(
        s.path(),
        &id(443),
        "other.example.com",
        &ca.root(),
        &[b"http/1.1"],
    )
    .await;
    assert!(refused.is_err(), "handshake succeeded for an unknown name");
    // The known name still works.
    let known = tls(
        s.path(),
        &id(443),
        "app.example.com",
        &ca.root(),
        &[b"http/1.1"],
    )
    .await;
    assert!(known.is_ok(), "{:?}", known.err());
    drop(known);
    s.shutdown().await;
}

#[tokio::test]
async fn rotated_certificate_is_served_after_apply() {
    let a = backend("A").await;
    let ca = Ca::new();
    let (old, old_leaf) = ca.issue("site", "app.example.com");
    let (new, new_leaf) = ca.issue("site", "app.example.com");
    assert_ne!(old.file_name, new.file_name);
    let mut s = Served::start(&https_model(vec![old.clone()], a)).await;
    let leaf_now = |s: &Served| {
        let (dir, port) = (s.path().to_path_buf(), id(443));
        let root = ca.root();
        async move {
            let conn = tls(&dir, &port, "app.example.com", &root, &[b"http/1.1"])
                .await
                .expect("handshake");
            presented(&conn)
        }
    };
    assert_eq!(leaf_now(&s).await, old_leaf);
    assert!(cert_files(s.path()).contains(&old.file_name));

    s.apply(&https_model(vec![new.clone()], a)).await;
    assert_eq!(leaf_now(&s).await, new_leaf);
    let files = cert_files(s.path());
    assert!(!files.contains(&old.file_name), "{files:?}");
    assert!(files.contains(&new.file_name), "{files:?}");
    let want: Vec<String> = s.rendered.files.iter().map(|f| f.name.clone()).collect();
    assert_eq!(files, want);
    s.shutdown().await;
}

#[tokio::test]
async fn a_listener_without_certificates_does_not_break_its_port() {
    use gateway_api::gatewayclasses::v1::GatewayClass;
    use gateway_api::gateways::v1::Gateway;
    use gateway_api::httproutes::v1::HttpRoute;
    use iroh_gateway_operator::model::{Settings, Snapshot, build};
    use iroh_gateway_proto::transport::Relay;
    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::{Namespace, Secret, Service};
    use serde_json::{from_value, json};

    let a = backend("A").await;
    let ca = Ca::new();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["a.example.com".to_owned()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = params.signed_by(&key, &*ca.0).unwrap();

    let controller = "example.com/iroh-gateway";
    let class: GatewayClass = from_value(json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GatewayClass",
        "metadata": {"name": "ours"},
        "spec": {"controllerName": controller},
    }))
    .unwrap();
    let gateway: Gateway = from_value(json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": {"namespace": "gw", "name": "public"},
        "spec": {
            "gatewayClassName": "ours",
            "listeners": [
                {"name": "good", "port": 443, "protocol": "HTTPS", "hostname": "a.example.com",
                 "tls": {"certificateRefs": [{"name": "site"}]}},
                {"name": "bare", "port": 443, "protocol": "HTTPS", "hostname": "b.example.com",
                 "tls": {"certificateRefs": [{"name": "missing"}]}},
            ],
        },
    }))
    .unwrap();
    let route: HttpRoute = from_value(json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": {"namespace": "gw", "name": "r"},
        "spec": {
            "parentRefs": [{"name": "public"}],
            "rules": [{"backendRefs": [{"name": "web", "port": a.port()}]}],
        },
    }))
    .unwrap();
    let service: Service = from_value(json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"namespace": "gw", "name": "web"},
        "spec": {"type": "ClusterIP", "clusterIP": "127.0.0.1", "ports": [{"port": a.port()}]},
    }))
    .unwrap();
    let namespace: Namespace =
        from_value(json!({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "gw"}}))
            .unwrap();
    let mut secret: Secret = from_value(json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"namespace": "gw", "name": "site"},
        "type": "kubernetes.io/tls",
    }))
    .unwrap();
    secret.data = Some(BTreeMap::from([
        ("tls.crt".to_owned(), ByteString(leaf.pem().into_bytes())),
        (
            "tls.key".to_owned(),
            ByteString(key.serialize_pem().into_bytes()),
        ),
    ]));
    let snapshot = Snapshot {
        gateway_classes: vec![class],
        gateways: vec![gateway],
        http_routes: vec![route],
        services: vec![service],
        namespaces: vec![namespace],
        secrets: vec![secret],
        ..Default::default()
    };
    let settings = Settings {
        controller_name: controller.into(),
        gateway_namespaces: BTreeSet::from(["gw".to_owned()]),
        relay: Relay::Disabled,
    };
    let m = build(&snapshot, &settings);
    let g = &m.gateways[0];
    assert_eq!(g.accepted, Ok(()));
    let bare = g.listeners.iter().find(|l| l.name == "bare").unwrap();
    assert!(!bare.serving(), "{bare:?}");
    assert!(bare.resolved_refs.is_err(), "{bare:?}");
    assert_eq!(g.http_ports.len(), 1, "{:?}", g.http_ports);
    assert_eq!(g.http_ports[0].tls.as_ref().map(Vec::len), Some(1));

    let s = Served::start(&m).await;
    let mut conn = tls(
        s.path(),
        &id(443),
        "a.example.com",
        &ca.root(),
        &[b"http/1.1"],
    )
    .await
    .expect("handshake");
    assert_eq!(presented(&conn), leaf.der().clone());
    assert_eq!(
        exchange(&mut conn, &request("a.example.com", "/"))
            .await
            .tag(),
        "A"
    );
    drop(conn);
    // The other listener's host has no certificate on the port.
    let refused = tls(
        s.path(),
        &id(443),
        "b.example.com",
        &ca.root(),
        &[b"http/1.1"],
    )
    .await;
    assert!(refused.is_err());
    s.shutdown().await;
}

// ---- every key form, from a Secret through the model ----

/// Runs `openssl` from PATH with `args` in `dir`.
fn openssl(dir: &Path, args: &[&str]) {
    let out = std::process::Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| {
            panic!("this test needs `openssl` on PATH (the dev shell provides it): {e}")
        });
    assert!(
        out.status.success(),
        "openssl {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// One DER element at the start of `der`: its tag, its content, and what follows it.
fn tlv(der: &[u8]) -> (u8, &[u8], &[u8]) {
    let (len, at) = match der[1] {
        n if n < 0x80 => (usize::from(n), 2),
        0x81 => (usize::from(der[2]), 3),
        0x82 => (usize::from(der[2]) << 8 | usize::from(der[3]), 4),
        n => panic!("length form {n:#x}"),
    };
    (der[0], &der[at..at + len], &der[at + len..])
}

/// `content` as a DER element with `tag`.
fn wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(content);
    out
}

/// A SEC1 `ECPrivateKey` split around its optional `[0]` parameters: what comes before them,
/// the parameters element if present, and what comes after.
fn sec1_parts(sec1: &[u8]) -> (&[u8], Option<&[u8]>, &[u8]) {
    let (tag, content, rest) = tlv(sec1);
    assert_eq!((tag, rest.len()), (0x30, 0), "a SEC1 key");
    let (_, _, after_version) = tlv(content);
    let (_, _, after_key) = tlv(after_version);
    let head = &content[..content.len() - after_key.len()];
    if after_key[0] == 0xa0 {
        let (_, _, tail) = tlv(after_key);
        let params = &after_key[..after_key.len() - tail.len()];
        (head, Some(params), tail)
    } else {
        (head, None, after_key)
    }
}

/// A PEM block of `der` under `label`.
fn pem_block(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|l| std::str::from_utf8(l).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// The DER of the one PEM block in `pem` labelled `label`.
fn pem_der(pem: &str, label: &str) -> Vec<u8> {
    use base64::Engine;
    let begin = format!("-----BEGIN {label}-----\n");
    let start = pem
        .find(&begin)
        .unwrap_or_else(|| panic!("no {label} block"))
        + begin.len();
    let end = pem[start..].find("-----END").unwrap() + start;
    let b64: String = pem[start..end].split_whitespace().collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap()
}

/// A snapshot of gw/public with one HTTPS listener `tls` on port 443 for `app.example.com`, its
/// certificate in Secret gw/site-tls (`crt`, `key`), and a route of every request to `backend`.
fn https_snapshot(
    crt: &str,
    key: &str,
    backend: SocketAddr,
) -> (
    iroh_gateway_operator::model::Snapshot,
    iroh_gateway_operator::model::Settings,
) {
    use iroh_gateway_operator::model::{Settings, Snapshot};
    use iroh_gateway_proto::transport::Relay;
    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::Secret;
    use serde_json::{from_value, json};

    let controller = "example.com/iroh-gateway";
    let mut secret: Secret = from_value(json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"namespace": "gw", "name": "site-tls"},
        "type": "kubernetes.io/tls",
    }))
    .unwrap();
    secret.data = Some(BTreeMap::from([
        ("tls.crt".to_owned(), ByteString(crt.as_bytes().to_vec())),
        ("tls.key".to_owned(), ByteString(key.as_bytes().to_vec())),
    ]));
    let snapshot = Snapshot {
        gateway_classes: vec![
            from_value(json!({
                "apiVersion": "gateway.networking.k8s.io/v1",
                "kind": "GatewayClass",
                "metadata": {"name": "ours"},
                "spec": {"controllerName": controller},
            }))
            .unwrap(),
        ],
        gateways: vec![
            from_value(json!({
                "apiVersion": "gateway.networking.k8s.io/v1",
                "kind": "Gateway",
                "metadata": {"namespace": "gw", "name": "public"},
                "spec": {
                    "gatewayClassName": "ours",
                    "listeners": [
                        {"name": "tls", "port": 443, "protocol": "HTTPS",
                         "hostname": "app.example.com",
                         "tls": {"mode": "Terminate", "certificateRefs": [{"name": "site-tls"}]}},
                    ],
                },
            }))
            .unwrap(),
        ],
        http_routes: vec![
            from_value(json!({
                "apiVersion": "gateway.networking.k8s.io/v1",
                "kind": "HTTPRoute",
                "metadata": {"namespace": "gw", "name": "r"},
                "spec": {
                    "parentRefs": [{"name": "public"}],
                    "rules": [{"backendRefs": [{"name": "web", "port": backend.port()}]}],
                },
            }))
            .unwrap(),
        ],
        services: vec![
            from_value(json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {"namespace": "gw", "name": "web"},
                "spec": {"type": "ClusterIP", "clusterIP": backend.ip().to_string(),
                         "ports": [{"port": backend.port()}]},
            }))
            .unwrap(),
        ],
        secrets: vec![secret],
        ..Default::default()
    };
    let settings = Settings {
        controller_name: controller.into(),
        gateway_namespaces: BTreeSet::from(["gw".to_owned()]),
        relay: Relay::Disabled,
    };
    (snapshot, settings)
}

#[tokio::test]
async fn every_key_form_the_model_accepts_loads_in_haproxy() {
    use iroh_gateway_operator::model::build;

    let a = backend("A").await;
    let ca = Ca::new();
    let keys = TempDir::new().unwrap();
    let dir = keys.path();
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap();
    let leaf_of = |key: &KeyPair| {
        let mut params = CertificateParams::new(vec!["app.example.com".to_owned()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.signed_by(key, &*ca.0).unwrap()
    };

    // (form, tls.crt, tls.key)
    let mut forms: Vec<(&str, rcgen::Certificate, String)> = Vec::new();
    for (curve, alg) in [
        ("P-256", &rcgen::PKCS_ECDSA_P256_SHA256),
        ("P-384", &rcgen::PKCS_ECDSA_P384_SHA384),
    ] {
        let key = KeyPair::generate_for(alg).unwrap();
        let pkcs8 = key.serialize_pem();
        let file = format!("{curve}.pem");
        std::fs::write(dir.join(&file), &pkcs8).unwrap();
        // OpenSSL writes SEC1 with the named curve as parameters.
        let sec1_file = format!("{curve}.sec1.pem");
        openssl(dir, &["ec", "-in", &file, "-out", &sec1_file]);
        let with_params = read(&sec1_file);
        let der = pem_der(&with_params, "EC PRIVATE KEY");
        let (head, params, tail) = sec1_parts(&der);
        assert!(params.is_some(), "{curve}: openssl wrote no parameters");
        let without_params = pem_block("EC PRIVATE KEY", &wrap(0x30, &[head, tail].concat()));
        let (pkcs8_form, with_form, without_form) = match curve {
            "P-256" => (
                "ECDSA P-256 PKCS#8",
                "ECDSA P-256 SEC1 with parameters",
                "ECDSA P-256 SEC1 without parameters",
            ),
            _ => (
                "ECDSA P-384 PKCS#8",
                "ECDSA P-384 SEC1 with parameters",
                "ECDSA P-384 SEC1 without parameters",
            ),
        };
        forms.push((pkcs8_form, leaf_of(&key), pkcs8));
        forms.push((with_form, leaf_of(&key), with_params));
        if curve == "P-256" {
            forms.push((without_form, leaf_of(&key), without_params));
        }
    }
    let ed25519 = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    forms.push(("Ed25519 PKCS#8", leaf_of(&ed25519), ed25519.serialize_pem()));
    // cert-manager's default: RSA-2048 in PKCS#1.
    openssl(
        dir,
        &["genrsa", "-traditional", "-out", "rsa.pkcs1.pem", "2048"],
    );
    openssl(
        dir,
        &[
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            "rsa.pkcs1.pem",
            "-out",
            "rsa.pkcs8.pem",
        ],
    );
    let (rsa1, rsa8) = (read("rsa.pkcs1.pem"), read("rsa.pkcs8.pem"));
    assert!(
        rsa1.starts_with("-----BEGIN RSA PRIVATE KEY-----"),
        "PKCS#1"
    );
    assert!(rsa8.starts_with("-----BEGIN PRIVATE KEY-----"), "PKCS#8");
    let rsa = KeyPair::from_pem_and_sign_algo(&rsa8, &rcgen::PKCS_RSA_SHA256).unwrap();
    forms.push(("RSA-2048 PKCS#1", leaf_of(&rsa), rsa1));
    forms.push(("RSA-2048 PKCS#8", leaf_of(&rsa), rsa8));
    assert_eq!(forms.len(), 8);

    let runtime = short_dir();
    let empty = render(&empty_model(), runtime.path());
    let mut sup = Supervisor::start(opts(runtime.path()), &empty.haproxy_cfg)
        .await
        .unwrap();
    for (form, leaf, key) in &forms {
        let (snapshot, settings) = https_snapshot(&leaf.pem(), key, a);
        let m = build(&snapshot, &settings);
        let listener = &m.gateways[0].listeners[0];
        assert_eq!(listener.resolved_refs, Ok(()), "{form}");
        assert_eq!(listener.certificates.len(), 1, "{form}");
        assert!(listener.serving(), "{form}");
        // Renders, validates and loads, or the apply panics naming HAProxy's complaint.
        let rendered = render(&m, runtime.path());
        let applied = sup
            .apply(&rendered.haproxy_cfg, &rendered.files)
            .await
            .unwrap_or_else(|e| panic!("{form} does not load: {e}"));
        assert_eq!(applied, Applied::Reloaded, "{form}");

        let mut conn = tls(
            runtime.path(),
            &id(443),
            "app.example.com",
            &ca.root(),
            &[b"http/1.1"],
        )
        .await
        .unwrap_or_else(|e| panic!("{form}: handshake: {e}"));
        assert_eq!(&presented(&conn), leaf.der(), "{form}");
        assert_eq!(
            exchange(&mut conn, &request("app.example.com", "/"))
                .await
                .tag(),
            "A",
            "{form}"
        );
    }
    sup.shutdown().await;
}
