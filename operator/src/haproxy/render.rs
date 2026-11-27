//! Render a [`Model`] into the HAProxy configuration, the files it names, and one [`EdgePlan`]
//! per accepted edge.
//!
//! Everything here is pure and its output is byte-for-byte stable for equal models: the engine
//! reloads HAProxy only when the text changes.
//!
//! Strings from cluster resources (host names, paths, header names and values) reach the
//! configuration only through [`quote`] and [`quote_format`], or, where a word cannot be quoted
//! (a header name inside a sample fetch's parentheses), with every character outside
//! `[A-Za-z0-9_-]` replaced. They never stand inside an anonymous `{ … }` ACL: every condition
//! of a rule is a named ACL.

use std::collections::{BTreeMap, HashMap};
use std::fmt::{Display, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use iroh_gateway_proto::control::{ListenerKey, Protocol};
use sha2::{Digest, Sha256};

use crate::haproxy::{CERT_DIR, METRICS_SOCKET, SecretFile};
use crate::model::{
    Backend, GatewayModel, HeaderMods, HostMatch, HttpAction, HttpPort, HttpRule, Model, ObjRef,
    PathMatch, Redirect,
};
use crate::tunnel::UdpTarget;

/// What the model asks of HAProxy and of the edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub haproxy_cfg: String,
    /// The files `haproxy_cfg` names under `<runtime_dir>/certs`, each named after its content,
    /// so that equal configurations mean equal files. Sorted by name, without repeats.
    pub files: Vec<SecretFile>,
    /// One per accepted edge of an accepted Gateway, sorted by key.
    pub edges: Vec<EdgePlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgePlan {
    pub key: ObjRef,
    pub endpoint_id: iroh::EndpointId,
    pub address: Option<String>,
    pub gateway: ObjRef,
    /// The Gateway's serving ports and what HAProxy serves behind each: its TCP ports and its
    /// HTTP and HTTPS ports, all under `Protocol::Tcp`, which is what the edge opens.
    pub sockets: HashMap<ListenerKey, PortPlan>,
    /// The targets of each serving UDP listener of the Gateway, by port.
    pub udp: BTreeMap<u16, Vec<UdpTarget>>,
}

/// One port of an [`EdgePlan`]: HAProxy's socket for it, and a fingerprint of what is behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortPlan {
    pub socket: PathBuf,
    /// The first 16 hex characters of SHA-256 over the exact text of the port's `frontend` and
    /// `backend` sections: equal fingerprints, equal traffic behind the socket. An HTTPS port's
    /// `bind` line names its certificate list after the list's content, which names each
    /// certificate after its own, so a new certificate is a new fingerprint.
    pub fingerprint: String,
    /// An HTTP or HTTPS port, which serves many routes and hosts; `false` for a TCP port. While
    /// a change is applied, and after HAProxy refused one, a port that is shared in the loaded
    /// plan and in the new one keeps forwarding to its socket whatever its fingerprint.
    pub shared: bool,
}

pub fn render(model: &Model, runtime_dir: &Path) -> Rendered {
    let dir = runtime_dir.display();
    let socket = |id: &str| runtime_dir.join("s").join(format!("{id}.sock"));

    let mut cfg = format!(
        "global\n\
         \x20   log stdout format raw local0\n\
         \x20   stats socket {dir}/stats.sock mode 600 level admin expose-fd listeners\n\
         \x20   maxconn 8192\n\
         \x20   hard-stop-after 30m\n\
         \x20   mworker-max-reloads 50\n\
         \n\
         defaults\n\
         \x20   mode tcp\n\
         \x20   log global\n\
         \x20   option tcplog\n\
         \x20   option dontlognull\n\
         \x20   timeout connect 5s\n\
         \x20   timeout client 1h\n\
         \x20   timeout server 1h\n\
         \x20   timeout tunnel 1h\n\
         \x20   timeout http-request 10s\n\
         \x20   timeout http-keep-alive 60s\n\
         \x20   timeout client-hs 10s\n\
         \n\
         frontend idle\n\
         \x20   bind unix@{dir}/s/idle.sock mode 600\n\
         \x20   tcp-request connection reject\n\
         \n\
         frontend metrics\n\
         \x20   mode http\n\
         \x20   bind unix@{dir}/{METRICS_SOCKET} mode 600\n\
         \x20   acl metrics_path path /metrics\n\
         \x20   http-request use-service prometheus-exporter if metrics_path\n\
         \x20   no log\n"
    );

    let mut gateways: Vec<&GatewayModel> = model
        .gateways
        .iter()
        .filter(|g| g.accepted.is_ok())
        .collect();
    gateways.sort_by(|a, b| a.key.cmp(&b.key));

    let mut files: BTreeMap<String, String> = BTreeMap::new();
    let mut sockets: HashMap<&ObjRef, HashMap<ListenerKey, PortPlan>> = HashMap::new();
    let mut udp: HashMap<&ObjRef, BTreeMap<u16, Vec<UdpTarget>>> = HashMap::new();
    for gateway in &gateways {
        // UDP does not go through HAProxy: a UDP listener writes nothing into `cfg`.
        udp.insert(
            &gateway.key,
            gateway
                .listeners
                .iter()
                .filter(|l| l.serving() && l.transport() == Protocol::Udp)
                .map(|l| (l.port, udp_targets(&l.backends)))
                .collect(),
        );
        let per_gateway = sockets.entry(&gateway.key).or_default();
        // The port's own sections, which its fingerprint covers, after a comment that says
        // whose port it is.
        let mut add = |port: u16, id: &str, section: String, shared: bool| {
            let _ = write!(cfg, "\n# {} port {port}\n", gateway.key);
            cfg.push_str(&section);
            let digest = hex::encode(Sha256::digest(&section));
            per_gateway.insert(
                ListenerKey {
                    protocol: Protocol::Tcp,
                    port,
                },
                PortPlan {
                    socket: socket(id),
                    fingerprint: digest[..16].to_owned(),
                    shared,
                },
            );
        };
        // HTTP and HTTPS listeners are served through `http_ports`.
        let mut listeners: Vec<_> = gateway
            .listeners
            .iter()
            .filter(|l| l.serving() && l.protocol == "TCP")
            .collect();
        listeners.sort_by_key(|l| l.port);
        for listener in listeners {
            let id = port_id(&gateway.key, listener.port);
            let mut section = format!(
                "frontend fe_{id}\n\
                 \x20   bind unix@{dir}/s/{id}.sock accept-proxy mode 600\n\
                 \x20   default_backend be_{id}\n\
                 \n\
                 backend be_{id}\n"
            );
            servers(&mut section, &listener.backends);
            add(listener.port, &id, section, false);
        }
        let mut ports: Vec<&HttpPort> = gateway.http_ports.iter().collect();
        ports.sort_by_key(|p| p.port);
        for port in ports {
            let id = port_id(&gateway.key, port.port);
            let section = http_sections(&id, &dir, port, &mut files);
            add(port.port, &id, section, true);
        }
    }

    let mut edges: Vec<EdgePlan> = model
        .edges
        .iter()
        .filter(|e| e.accepted.is_ok())
        .filter_map(|e| {
            let gateway = e.gateway.as_ref()?;
            Some(EdgePlan {
                key: e.key.clone(),
                endpoint_id: e.endpoint_id?,
                address: e.address.clone(),
                gateway: gateway.clone(),
                sockets: sockets.get(gateway)?.clone(),
                udp: udp.get(gateway)?.clone(),
            })
        })
        .collect();
    edges.sort_by(|a, b| a.key.cmp(&b.key));

    Rendered {
        haproxy_cfg: cfg,
        files: files
            .into_iter()
            .map(|(name, contents)| SecretFile { name, contents })
            .collect(),
        edges,
    }
}

/// One `server` line per backend of positive weight, weights scaled by [`scale_weights`].
fn servers(section: &mut String, backends: &[Backend]) {
    let weights: Vec<u32> = backends.iter().map(|b| b.weight).collect();
    for (i, (backend, weight)) in backends.iter().zip(scale_weights(&weights)).enumerate() {
        if weight == 0 {
            continue;
        }
        let _ = match backend.ip {
            IpAddr::V4(ip) => writeln!(
                section,
                "    server s{i} {ip}:{} weight {weight}",
                backend.port
            ),
            IpAddr::V6(ip) => writeln!(
                section,
                "    server s{i} [{ip}]:{} weight {weight}",
                backend.port
            ),
        };
    }
}

/// A UDP listener's backends as its targets, in order.
fn udp_targets(backends: &[Backend]) -> Vec<UdpTarget> {
    backends
        .iter()
        .map(|b| UdpTarget {
            addr: SocketAddr::new(b.ip, b.port),
            weight: b.weight,
        })
        .collect()
}

/// The `frontend` and `backend` sections of an HTTP or HTTPS port; an HTTPS port's certificates
/// and their list go into `files`.
fn http_sections(
    id: &str,
    dir: &impl Display,
    port: &HttpPort,
    files: &mut BTreeMap<String, String>,
) -> String {
    let (tls, proto) = match &port.tls {
        None => (String::new(), "http"),
        Some(certificates) => {
            let mut list = String::new();
            for c in certificates {
                let _ = writeln!(list, "{dir}/{CERT_DIR}/{}", c.file_name);
                files.insert(c.file_name.clone(), c.pem.clone());
            }
            let name = format!("{id}.{}.list", &hex::encode(Sha256::digest(&list))[..16]);
            let tls = format!(
                " ssl crt-list {dir}/{CERT_DIR}/{name} strict-sni ssl-min-ver TLSv1.2 \
                 alpn h2,http/1.1"
            );
            files.insert(name, list);
            (tls, "https")
        }
    };
    let mut s = format!(
        "frontend fe_{id}\n\
         \x20   mode http\n\
         \x20   bind unix@{dir}/s/{id}.sock accept-proxy mode 600{tls}\n\
         \x20   option httplog\n\
         \x20   http-request set-header X-Forwarded-For %[src]\n\
         \x20   http-request set-header X-Forwarded-Proto {proto}\n\
         \x20   http-request set-header X-Forwarded-Host %[req.hdr(host)]\n\
         \x20   http-request set-header X-Forwarded-Port %[dst_port]\n\
         \x20   http-request del-header Forwarded\n\
         \x20   http-request del-header X-Real-IP\n"
    );
    for (r, rule) in port.rules.iter().enumerate() {
        use_backend(&mut s, id, r, rule);
    }
    let _ = writeln!(s, "    default_backend be_{id}_none");

    for (n, backend) in port.backends.iter().enumerate() {
        if !port.rules.iter().any(|r| r.backend == n) {
            continue;
        }
        let _ = write!(s, "\nbackend be_{id}_{n}\n    mode http\n");
        header_mods(&mut s, "http-request", &backend.request_headers);
        // `http-after-response`, not `http-response`: it also applies to the responses HAProxy
        // makes itself, a redirect's and a 500's.
        header_mods(&mut s, "http-after-response", &backend.response_headers);
        match &backend.action {
            HttpAction::Forward(backends) => servers(&mut s, backends),
            HttpAction::Fail => s.push_str("    http-request return status 500\n"),
            HttpAction::Redirect(r) => {
                let location = location(r, port.tls.is_some(), port.port);
                let _ = writeln!(
                    s,
                    "    http-request redirect location {} code {}",
                    quote(&location),
                    r.status
                );
            }
        }
    }
    let _ = write!(
        s,
        "\nbackend be_{id}_none\n    mode http\n    http-request return status 404\n"
    );
    s
}

/// The ACLs of rule number `r`, each on a line of its own, and then its `use_backend` line.
///
/// Every condition is a named ACL, never an anonymous `{ … }` one: HAProxy finds the end of an
/// anonymous ACL by comparing words after unquoting, so a value of exactly `}` would end it.
/// The ACLs are `r<r>_host`, `r<r>_path`, `r<r>_method` and `r<r>_h<j>` for header `j`, in that
/// order, each declared only when it applies. A path prefix other than `/` declares `r<r>_path`
/// twice, for the path itself and for what lies below it; HAProxy ORs the declarations of one
/// name. A rule without conditions is `use_backend` without `if`.
fn use_backend(s: &mut String, id: &str, r: usize, rule: &HttpRule) {
    let mut names = Vec::new();
    let mut acl = |s: &mut String, name: String, test: String| {
        let _ = writeln!(s, "    acl {name} {test}");
        if !names.contains(&name) {
            names.push(name);
        }
    };
    match &rule.host {
        HostMatch::Any => {}
        HostMatch::Exact(h) => acl(
            s,
            format!("r{r}_host"),
            format!("req.hdr(host),host_only,lower -m str -- {}", quote(h)),
        ),
        HostMatch::Wildcard(suffix) => acl(
            s,
            format!("r{r}_host"),
            format!("req.hdr(host),host_only,lower -m end -- {}", quote(suffix)),
        ),
    }
    match &rule.path {
        PathMatch::Prefix(p) if p == "/" => {}
        PathMatch::Exact(p) => acl(
            s,
            format!("r{r}_path"),
            format!("path -m str -- {}", quote(p)),
        ),
        PathMatch::Prefix(p) => {
            acl(
                s,
                format!("r{r}_path"),
                format!("path -m str -- {}", quote(p)),
            );
            acl(
                s,
                format!("r{r}_path"),
                format!("path -m beg -- {}", quote(&format!("{p}/"))),
            );
        }
    }
    if let Some(m) = &rule.method {
        acl(s, format!("r{r}_method"), format!("method {}", quote(m)));
    }
    for (j, (name, value)) in rule.headers.iter().enumerate() {
        acl(
            s,
            format!("r{r}_h{j}"),
            format!("req.fhdr({}) -m str -- {}", header_name(name), quote(value)),
        );
    }
    let _ = write!(s, "    use_backend be_{id}_{}", rule.backend);
    if !names.is_empty() {
        let _ = write!(s, " if {}", names.join(" "));
    }
    s.push('\n');
}

/// A header name as a sample fetch argument, which cannot be quoted: every character outside
/// `[A-Za-z0-9_-]` replaced by `_`.
fn header_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The `http-request` or `http-after-response` rules of `mods`: set, add, then remove.
fn header_mods(s: &mut String, directive: &str, mods: &HeaderMods) {
    for (name, value) in &mods.set {
        let _ = writeln!(
            s,
            "    {directive} set-header {} {}",
            quote(name),
            quote_format(value)
        );
    }
    for (name, value) in &mods.add {
        let _ = writeln!(
            s,
            "    {directive} add-header {} {}",
            quote(name),
            quote_format(value)
        );
    }
    for name in &mods.remove {
        let _ = writeln!(s, "    {directive} del-header {}", quote(name));
    }
}

/// Where a redirect sends a request to a port that is `tls` or not and listens on `port`, as a
/// log-format string that keeps the request's path and query.
fn location(r: &Redirect, tls: bool, port: u16) -> String {
    let scheme = r
        .scheme
        .as_deref()
        .unwrap_or(if tls { "https" } else { "http" });
    let host = match &r.hostname {
        Some(h) => h.replace('%', "%%"),
        None => "%[req.hdr(host),host_only]".to_owned(),
    };
    let port = match (r.port, &r.scheme) {
        (Some(p), _) => Some(p),
        (None, Some(_)) => None,
        (None, None) => Some(port),
    };
    let default = if scheme == "https" { 443 } else { 80 };
    let port = port
        .filter(|&p| p != default)
        .map(|p| format!(":{p}"))
        .unwrap_or_default();
    format!("{scheme}://{host}{port}%[pathq]")
}

/// `s` as one HAProxy configuration word: in single quotes, each `'` written as `'\''`, control
/// characters dropped. Inside single quotes HAProxy expands nothing.
///
/// `s` must not be empty: HAProxy takes an empty word for the end of a line's arguments.
pub(crate) fn quote(s: &str) -> String {
    debug_assert!(!s.is_empty(), "quote needs a non-empty string");
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        match c {
            '\'' => out.push_str(r"'\''"),
            c if c.is_ascii_control() => {}
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// `quote`, for arguments HAProxy reads as a log-format string: each `%` doubled first.
pub(crate) fn quote_format(s: &str) -> String {
    quote(&s.replace('%', "%%"))
}

/// First 16 hex characters of sha256("<namespace>/<name>:<port>").
pub fn port_id(gateway: &ObjRef, port: u16) -> String {
    let digest = Sha256::digest(format!("{}/{}:{port}", gateway.namespace, gateway.name));
    hex::encode(&digest[..8])
}

/// Scales weights so the largest becomes 256 and none that was positive becomes 0.
pub fn scale_weights(weights: &[u32]) -> Vec<u32> {
    let max = u64::from(weights.iter().copied().max().unwrap_or(0));
    weights
        .iter()
        .map(|&w| {
            if w == 0 {
                0
            } else {
                // Rounded to nearest; `w <= max`, so the result is at most 256.
                let w = u64::from(w);
                ((w * 256 + max / 2) / max).max(1) as u32
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::model::{
        Backend, Certificate, EdgeModel, GatewayModel, HeaderMods, HostMatch, HttpAction,
        HttpBackend, HttpPort, HttpRule, ListenerModel, PathMatch, Redirect, Reject,
    };

    const DIR: &str = "/run/igw";

    fn gw(ns: &str, name: &str) -> ObjRef {
        ObjRef::new(ns, name)
    }

    fn backend(ip: &str, port: u16, weight: u32) -> Backend {
        Backend {
            service: ObjRef::new("apps", "svc"),
            ip: ip.parse::<IpAddr>().unwrap(),
            port,
            weight,
        }
    }

    fn listener(port: u16, backends: Vec<Backend>) -> ListenerModel {
        ListenerModel {
            name: format!("l{port}"),
            port,
            protocol: "TCP".into(),
            hostname: HostMatch::Any,
            accepted: Ok(()),
            conflicted: None,
            resolved_refs: Ok(()),
            supported_kinds: vec!["TCPRoute".into()],
            allowed_namespaces: Default::default(),
            attached_routes: 1,
            backends,
            certificates: Vec::new(),
        }
    }

    fn gateway(key: ObjRef, listeners: Vec<ListenerModel>) -> GatewayModel {
        GatewayModel {
            key,
            generation: 1,
            accepted: Ok(()),
            listeners,
            edges: Vec::new(),
            http_ports: Vec::new(),
        }
    }

    fn edge(name: &str, seed: u8, gateway: &ObjRef) -> EdgeModel {
        EdgeModel {
            key: ObjRef::new(&gateway.namespace, name),
            generation: 1,
            accepted: Ok(()),
            endpoint_id: Some(iroh::SecretKey::from_bytes(&[seed; 32]).public()),
            address: Some("203.0.113.7:7842".into()),
            gateway: Some(gateway.clone()),
            public_addresses: Vec::new(),
        }
    }

    fn model(gateways: Vec<GatewayModel>, edges: Vec<EdgeModel>) -> Model {
        Model {
            classes: Vec::new(),
            gateways,
            edges,
            routes: Vec::new(),
        }
    }

    fn render_in(m: &Model) -> Rendered {
        render(m, Path::new(DIR))
    }

    fn tcp(port: u16) -> ListenerKey {
        ListenerKey {
            protocol: Protocol::Tcp,
            port,
        }
    }

    #[test]
    fn empty_model_renders_only_the_idle_frontend() {
        let r = render_in(&model(vec![], vec![]));
        assert_eq!(r.haproxy_cfg, include_str!("testdata/empty.cfg"));
        assert!(r.edges.is_empty());
    }

    #[test]
    fn one_gateway_one_port() {
        let g = gw("gw", "public");
        let m = model(
            vec![gateway(
                g.clone(),
                vec![listener(
                    5432,
                    vec![backend("10.0.0.1", 5432, 1), backend("10.0.0.2", 5432, 3)],
                )],
            )],
            vec![edge("e1", 1, &g)],
        );
        let r = render_in(&m);
        assert_eq!(r.haproxy_cfg, include_str!("testdata/one.cfg"));
        assert_eq!(r.edges.len(), 1);
        // The fingerprint covers the port's frontend and backend sections, to the end.
        let golden = include_str!("testdata/one.cfg");
        let section = &golden[golden.find("frontend fe_7903a80c6832446b").unwrap()..];
        let digest = hex::encode(Sha256::digest(section));
        assert_eq!(
            r.edges[0].sockets,
            HashMap::from([(
                tcp(5432),
                PortPlan {
                    socket: PathBuf::from("/run/igw/s/7903a80c6832446b.sock"),
                    fingerprint: digest[..16].to_owned(),
                    shared: false,
                }
            )])
        );
    }

    #[test]
    fn fingerprint_follows_the_ports_own_sections() {
        let g = gw("gw", "public");
        let plan = |backends: Vec<Backend>, other_port_backend: &str| {
            let m = model(
                vec![gateway(
                    g.clone(),
                    vec![
                        listener(80, backends),
                        listener(81, vec![backend(other_port_backend, 81, 1)]),
                    ],
                )],
                vec![edge("e", 1, &g)],
            );
            render_in(&m).edges[0].sockets.clone()
        };
        let base = plan(vec![backend("10.0.0.1", 80, 1)], "10.0.0.9");
        let fp = |s: &HashMap<ListenerKey, PortPlan>, port| s[&tcp(port)].fingerprint.clone();
        assert_eq!(fp(&base, 80).len(), 16);
        assert!(fp(&base, 80).chars().all(|c| c.is_ascii_hexdigit()));
        // Equal input, equal fingerprint.
        assert_eq!(plan(vec![backend("10.0.0.1", 80, 1)], "10.0.0.9"), base);
        // A server line differs: that port's fingerprint changes, the other's does not.
        let moved = plan(vec![backend("10.0.0.2", 80, 1)], "10.0.0.9");
        assert_ne!(fp(&moved, 80), fp(&base, 80));
        assert_eq!(fp(&moved, 81), fp(&base, 81));
        let weighted = plan(
            vec![backend("10.0.0.1", 80, 1), backend("10.0.0.3", 80, 2)],
            "10.0.0.9",
        );
        assert_ne!(fp(&weighted, 80), fp(&base, 80));
        // Another port's backend changing leaves this one alone.
        let elsewhere = plan(vec![backend("10.0.0.1", 80, 1)], "10.0.0.8");
        assert_eq!(fp(&elsewhere, 80), fp(&base, 80));
        assert_ne!(fp(&elsewhere, 81), fp(&base, 81));
        // The socket stays the same throughout.
        assert_eq!(moved[&tcp(80)].socket, base[&tcp(80)].socket);
    }

    #[test]
    fn two_gateways_are_ordered_by_key_then_port() {
        let a = gw("a", "x");
        let b = gw("b", "y");
        // Deliberately out of order in the model.
        let m = model(
            vec![
                gateway(
                    b.clone(),
                    vec![listener(5432, vec![backend("fd00::12", 5432, 1)])],
                ),
                gateway(
                    a.clone(),
                    vec![
                        listener(443, vec![backend("10.0.0.1", 443, 1)]),
                        listener(80, vec![backend("10.0.0.1", 80, 1)]),
                    ],
                ),
            ],
            vec![],
        );
        assert_eq!(render_in(&m).haproxy_cfg, include_str!("testdata/two.cfg"));
    }

    #[test]
    fn non_serving_listener_is_left_out() {
        let g = gw("gw", "public");
        let mut conflicted = listener(81, vec![backend("10.0.0.1", 81, 1)]);
        conflicted.conflicted = Some(Reject::new("ProtocolConflict", "x"));
        let mut refused = listener(82, vec![backend("10.0.0.1", 82, 1)]);
        refused.accepted = Err(Reject::new("PortUnavailable", "x"));
        let m = model(
            vec![gateway(
                g.clone(),
                vec![listener(80, vec![]), conflicted, refused],
            )],
            vec![edge("e1", 1, &g)],
        );
        let r = render_in(&m);
        assert_eq!(r.haproxy_cfg, include_str!("testdata/empty.cfg"));
        // The edge still gets a plan, with no ports open.
        assert_eq!(r.edges.len(), 1);
        assert!(r.edges[0].sockets.is_empty());
    }

    #[test]
    fn unaccepted_gateway_contributes_nothing() {
        let g = gw("gw", "public");
        let mut bad = gateway(
            g.clone(),
            vec![listener(80, vec![backend("10.0.0.1", 80, 1)])],
        );
        bad.accepted = Err(Reject::new("Invalid", "x"));
        let m = model(vec![bad], vec![edge("e1", 1, &g)]);
        let r = render_in(&m);
        assert_eq!(r.haproxy_cfg, include_str!("testdata/empty.cfg"));
        assert!(r.edges.is_empty());
    }

    #[test]
    fn unaccepted_edge_and_edge_of_unknown_gateway_get_no_plan() {
        let g = gw("gw", "public");
        let mut rejected = edge("e1", 1, &g);
        rejected.accepted = Err(Reject::new("Invalid", "x"));
        let orphan = edge("e2", 2, &gw("gw", "missing"));
        let m = model(vec![gateway(g.clone(), vec![])], vec![rejected, orphan]);
        assert!(render_in(&m).edges.is_empty());
    }

    #[test]
    fn edge_plan_carries_the_edge_identity() {
        let g = gw("gw", "public");
        let e2 = edge("b", 2, &g);
        let mut e1 = edge("a", 1, &g);
        e1.address = None;
        let m = model(
            vec![gateway(g.clone(), vec![])],
            vec![e2.clone(), e1.clone()],
        );
        let r = render_in(&m);
        assert_eq!(r.edges.len(), 2);
        // Sorted by key, whatever the model order.
        assert_eq!(r.edges[0].key, e1.key);
        assert_eq!(r.edges[0].endpoint_id, e1.endpoint_id.unwrap());
        assert_eq!(r.edges[0].address, None);
        assert_eq!(r.edges[0].gateway, g);
        assert_eq!(r.edges[1].key, e2.key);
        assert_eq!(r.edges[1].endpoint_id, e2.endpoint_id.unwrap());
        assert_eq!(r.edges[1].address.as_deref(), Some("203.0.113.7:7842"));
    }

    #[test]
    fn ipv6_backend_is_bracketed() {
        let g = gw("gw", "public");
        let m = model(
            vec![gateway(
                g,
                vec![listener(5432, vec![backend("fd00::12", 5432, 1)])],
            )],
            vec![],
        );
        assert!(
            render_in(&m)
                .haproxy_cfg
                .contains("server s0 [fd00::12]:5432 weight 256\n")
        );
    }

    #[test]
    fn zero_weight_backend_is_not_a_server_line() {
        let g = gw("gw", "public");
        let m = model(
            vec![gateway(
                g,
                vec![listener(
                    80,
                    vec![backend("10.0.0.1", 80, 0), backend("10.0.0.2", 80, 2)],
                )],
            )],
            vec![],
        );
        let cfg = render_in(&m).haproxy_cfg;
        assert!(!cfg.contains("10.0.0.1"));
        assert!(cfg.contains("server s1 10.0.0.2:80 weight 256\n"));
    }

    #[test]
    fn scale_weights_examples() {
        assert_eq!(scale_weights(&[1]), vec![256]);
        assert_eq!(scale_weights(&[3, 1]), vec![256, 85]);
        assert_eq!(scale_weights(&[1_000_000, 1]), vec![256, 1]);
        assert_eq!(scale_weights(&[5, 5, 5]), vec![256, 256, 256]);
        assert_eq!(scale_weights(&[]), Vec::<u32>::new());
        assert_eq!(scale_weights(&[0, 0]), vec![0, 0]);
        assert_eq!(scale_weights(&[0, 4]), vec![0, 256]);
        assert_eq!(scale_weights(&[u32::MAX, 1]), vec![256, 1]);
    }

    #[test]
    fn port_id_is_stable_and_short() {
        let id = port_id(&gw("gw", "public"), 5432);
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(id, port_id(&gw("gw", "public"), 5432));
        assert_eq!(id, "7903a80c6832446b");
        assert_ne!(id, port_id(&gw("gw", "public"), 5433));
    }

    #[test]
    fn long_names_give_short_socket_paths() {
        let g = gw(&"n".repeat(63), &"g".repeat(63));
        let dir = format!("/{}", "d".repeat(59));
        assert_eq!(dir.len(), crate::haproxy::MAX_RUNTIME_DIR_LEN);
        let m = model(
            vec![gateway(
                g.clone(),
                vec![listener(80, vec![backend("10.0.0.1", 80, 1)])],
            )],
            vec![edge("e", 1, &g)],
        );
        let r = render(&m, Path::new(&dir));
        // HAProxy appends `.<pid>.tmp` while it binds and refuses more than 93 bytes on macOS.
        for p in r.edges[0].sockets.values() {
            assert!(p.socket.as_os_str().len() <= 90, "{}", p.socket.display());
        }
        assert_eq!(r.edges[0].sockets.len(), 1);
    }

    #[test]
    fn render_is_deterministic() {
        let g = gw("gw", "public");
        let m = model(
            vec![gateway(
                g.clone(),
                vec![
                    listener(80, vec![backend("10.0.0.1", 80, 1)]),
                    listener(81, vec![backend("10.0.0.1", 81, 1)]),
                ],
            )],
            vec![edge("e", 1, &g)],
        );
        let first = render_in(&m);
        for _ in 0..20 {
            assert_eq!(render_in(&m), first);
        }
    }

    // ---- HTTP and HTTPS ----

    /// The base64 line of every fake key below; a test checks it never shows.
    const KEY_LINE: &str = "c2VjcmV0LWtleS1tYXRlcmlhbA";

    /// A certificate of Secret gw/<name> with a fake PEM and the file name `gw.<name>.<hash>.pem`.
    fn cert(name: &str, hash: &str) -> Certificate {
        Certificate {
            secret: ObjRef::new("gw", name),
            file_name: format!("gw.{name}.{hash}.pem"),
            pem: format!(
                "-----BEGIN CERTIFICATE-----\nQ0VSVC17bmFtZX0=\n-----END CERTIFICATE-----\n\
                 -----BEGIN PRIVATE KEY-----\n{KEY_LINE}{hash}\n-----END PRIVATE KEY-----\n"
            ),
        }
    }

    fn exact(h: &str) -> HostMatch {
        HostMatch::Exact(h.into())
    }

    fn prefix(p: &str) -> PathMatch {
        PathMatch::Prefix(p.into())
    }

    fn http_rule(host: HostMatch, path: PathMatch, backend: usize) -> HttpRule {
        HttpRule {
            host,
            path,
            method: None,
            headers: Vec::new(),
            backend,
        }
    }

    fn http_backend(action: HttpAction) -> HttpBackend {
        HttpBackend {
            route: ObjRef::new("gw", "r"),
            rule: 0,
            request_headers: HeaderMods::default(),
            response_headers: HeaderMods::default(),
            action,
        }
    }

    fn forward(backends: Vec<Backend>) -> HttpBackend {
        http_backend(HttpAction::Forward(backends))
    }

    fn http_port(
        port: u16,
        tls: Option<Vec<Certificate>>,
        rules: Vec<HttpRule>,
        backends: Vec<HttpBackend>,
    ) -> HttpPort {
        HttpPort {
            port,
            tls,
            rules,
            backends,
        }
    }

    /// A port with one rule for everything, to one backend.
    fn simple_port(port: u16, tls: Option<Vec<Certificate>>) -> HttpPort {
        http_port(
            port,
            tls,
            vec![http_rule(HostMatch::Any, prefix("/"), 0)],
            vec![forward(vec![backend("10.0.0.1", 8080, 1)])],
        )
    }

    /// A gateway with the given HTTP ports and no listeners.
    fn http_gateway(key: ObjRef, ports: Vec<HttpPort>) -> GatewayModel {
        let mut g = gateway(key, Vec::new());
        g.http_ports = ports;
        g
    }

    /// The rendering of gw/public with `ports` and one edge.
    fn render_ports(ports: Vec<HttpPort>) -> Rendered {
        let g = gw("gw", "public");
        render_in(&model(
            vec![http_gateway(g.clone(), ports)],
            vec![edge("e1", 1, &g)],
        ))
    }

    /// The lines of `cfg` that start with `prefix` after their indent, without the indent.
    fn lines_of<'a>(cfg: &'a str, prefix: &str) -> Vec<&'a str> {
        cfg.lines()
            .map(str::trim_start)
            .filter(|l| l.starts_with(prefix))
            .collect()
    }

    /// The fingerprint of the text from `frontend fe_<id>` up to the next `# ` comment or the end.
    fn fingerprint_of(cfg: &str, id: &str) -> String {
        let start = cfg.find(&format!("frontend fe_{id}\n")).unwrap();
        let rest = &cfg[start..];
        // The section ends in a newline; the next port's comment follows after a blank line.
        let section = &rest[..rest.find("\n# ").unwrap_or(rest.len())];
        hex::encode(Sha256::digest(section))[..16].to_owned()
    }

    #[test]
    fn quote_examples() {
        assert_eq!(quote("plain"), "'plain'");
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote("a b #c $HOME \"d\" \\e"), "'a b #c $HOME \"d\" \\e'");
        assert_eq!(quote("a\nb\r\0c\x7f"), "'abc'");
        assert_eq!(quote_format("100% it's"), r"'100%% it'\''s'");
        // More of the same.
        assert_eq!(quote("''"), r"''\'''\'''");
        assert_eq!(quote("end\\"), "'end\\'");
        assert_eq!(quote("gr\u{fc}\u{df}e"), "'gr\u{fc}\u{df}e'");
        assert_eq!(quote("%[src]"), "'%[src]'");
        assert_eq!(quote_format("%[src]"), "'%%[src]'");
        assert_eq!(quote_format("${HOME}"), "'${HOME}'");
        assert_eq!(quote_format("a\tb%"), "'ab%%'");
    }

    /// The model of `testdata/http.cfg`.
    fn http_golden_port() -> HttpPort {
        let a = || exact("a.example.com");
        let mut api = http_rule(a(), prefix("/api"), 1);
        api.method = Some("GET".into());
        api.headers = vec![("x-env".into(), "prod".into())];
        let mut filtered = forward(vec![
            backend("10.0.0.1", 8080, 1),
            backend("10.0.0.2", 8080, 3),
        ]);
        filtered.request_headers = HeaderMods {
            set: vec![("x-a".into(), "100%".into())],
            add: vec![("x-b".into(), "2".into())],
            remove: vec!["x-c".into()],
        };
        filtered.response_headers = HeaderMods {
            set: vec![("x-d".into(), "4".into())],
            add: vec![("x-e".into(), "5".into())],
            remove: vec!["server".into()],
        };
        http_port(
            80,
            None,
            vec![
                http_rule(a(), PathMatch::Exact("/x".into()), 0),
                api,
                http_rule(HostMatch::Wildcard(".example.com".into()), prefix("/"), 2),
                http_rule(HostMatch::Any, prefix("/fail"), 3),
                http_rule(HostMatch::Any, prefix("/"), 0),
            ],
            vec![
                filtered,
                forward(vec![backend("fd00::12", 8080, 1)]),
                HttpBackend {
                    response_headers: HeaderMods {
                        set: vec![(
                            "strict-transport-security".into(),
                            "max-age=31536000".into(),
                        )],
                        ..Default::default()
                    },
                    ..http_backend(HttpAction::Redirect(Redirect {
                        scheme: Some("https".into()),
                        hostname: None,
                        port: None,
                        status: 301,
                    }))
                },
                http_backend(HttpAction::Fail),
            ],
        )
    }

    #[test]
    fn http_port_matches_the_golden_file() {
        let r = render_ports(vec![http_golden_port()]);
        let golden = include_str!("testdata/http.cfg");
        assert_eq!(r.haproxy_cfg, golden);
        assert!(r.files.is_empty());
        assert_eq!(r.edges.len(), 1);
        let id = "473034e7d07ecf67";
        assert_eq!(port_id(&gw("gw", "public"), 80), id);
        let section = &golden[golden.find(&format!("frontend fe_{id}")).unwrap()..];
        let digest = hex::encode(Sha256::digest(section));
        assert_eq!(
            r.edges[0].sockets,
            HashMap::from([(
                tcp(80),
                PortPlan {
                    socket: PathBuf::from(format!("/run/igw/s/{id}.sock")),
                    fingerprint: digest[..16].to_owned(),
                    shared: true,
                }
            )])
        );
    }

    #[test]
    fn https_port_matches_the_golden_file() {
        let (a, b) = (
            cert("site-a", "1111111111111111"),
            cert("site-b", "2222222222222222"),
        );
        let mut port = simple_port(443, Some(vec![a.clone(), b.clone()]));
        // The golden file's server is on 8443.
        port.backends = vec![forward(vec![backend("10.0.0.1", 8443, 1)])];
        let r = render_ports(vec![port]);
        assert_eq!(r.haproxy_cfg, include_str!("testdata/https.cfg"));
        let list = "/run/igw/certs/gw.site-a.1111111111111111.pem\n\
                    /run/igw/certs/gw.site-b.2222222222222222.pem\n";
        let list_name = format!(
            "a43c3fd7a81ccec0.{}.list",
            &hex::encode(Sha256::digest(list))[..16]
        );
        assert_eq!(list_name, "a43c3fd7a81ccec0.a372a6265b8479fc.list");
        assert_eq!(
            r.files,
            [
                SecretFile {
                    name: list_name,
                    contents: list.to_owned(),
                },
                SecretFile {
                    name: a.file_name.clone(),
                    contents: a.pem.clone(),
                },
                SecretFile {
                    name: b.file_name.clone(),
                    contents: b.pem.clone(),
                },
            ]
        );
        assert_eq!(
            r.edges[0].sockets[&tcp(443)].fingerprint,
            fingerprint_of(&r.haproxy_cfg, "a43c3fd7a81ccec0")
        );
    }

    /// The lines of the frontend from the first `acl` or `use_backend` line up to
    /// `default_backend`, without their indent.
    fn rule_lines(cfg: &str) -> Vec<&str> {
        cfg.lines()
            .map(str::trim_start)
            .filter(|l| l.starts_with("acl ") || l.starts_with("use_backend "))
            .filter(|l| !l.starts_with("acl metrics_path "))
            .collect()
    }

    #[test]
    fn prefix_gives_two_path_acls_and_root_prefix_none() {
        let r = render_ports(vec![http_port(
            80,
            None,
            vec![
                http_rule(HostMatch::Any, prefix("/foo"), 0),
                http_rule(exact("a.example.com"), prefix("/"), 1),
                http_rule(HostMatch::Any, prefix("/"), 1),
            ],
            vec![
                forward(vec![backend("10.0.0.1", 80, 1)]),
                forward(vec![backend("10.0.0.2", 80, 1)]),
            ],
        )]);
        let id = port_id(&gw("gw", "public"), 80);
        assert_eq!(
            rule_lines(&r.haproxy_cfg),
            [
                "acl r0_path path -m str -- '/foo'".to_owned(),
                "acl r0_path path -m beg -- '/foo/'".to_owned(),
                format!("use_backend be_{id}_0 if r0_path"),
                "acl r1_host req.hdr(host),host_only,lower -m str -- 'a.example.com'".to_owned(),
                format!("use_backend be_{id}_1 if r1_host"),
                format!("use_backend be_{id}_1"),
            ]
        );
    }

    #[test]
    fn rule_without_conditions_has_no_if() {
        let r = render_ports(vec![simple_port(80, None)]);
        let id = port_id(&gw("gw", "public"), 80);
        assert_eq!(
            rule_lines(&r.haproxy_cfg),
            [format!("use_backend be_{id}_0")]
        );
        assert!(
            r.haproxy_cfg
                .contains(&format!("\n    use_backend be_{id}_0\n"))
        );
    }

    #[test]
    fn header_name_with_odd_characters_is_made_safe() {
        let mut rule = http_rule(HostMatch::Any, prefix("/"), 0);
        rule.headers = vec![("x)y z".into(), "v".into())];
        let mut port = simple_port(80, None);
        port.rules = vec![rule];
        let r = render_ports(vec![port]);
        let id = port_id(&gw("gw", "public"), 80);
        assert_eq!(
            rule_lines(&r.haproxy_cfg),
            [
                "acl r0_h0 req.fhdr(x_y_z) -m str -- 'v'".to_owned(),
                format!("use_backend be_{id}_0 if r0_h0"),
            ]
        );
        assert!(!r.haproxy_cfg.contains("x)y"));
    }

    #[test]
    fn conditions_are_named_acls() {
        // Values that are HAProxy syntax on their own.
        let words = ["}", "{", "||", "!", "if", "unless", "--", "-m", "-i", "or"];
        let mut rules = Vec::new();
        for (i, w) in words.iter().enumerate() {
            let mut r = http_rule(
                if i % 2 == 0 {
                    exact("a.example.com")
                } else {
                    HostMatch::Wildcard(".example.com".into())
                },
                if i % 3 == 0 {
                    PathMatch::Exact(format!("/{w}"))
                } else {
                    prefix(&format!("/{w}"))
                },
                0,
            );
            r.method = Some("GET".into());
            r.headers = vec![("x-a".into(), (*w).into()), ("x-b".into(), "{ }".into())];
            rules.push(r);
        }
        rules.push(http_rule(HostMatch::Any, prefix("/"), 0));
        let mut port = simple_port(80, None);
        port.rules = rules;
        port.backends[0].request_headers.set = vec![("x-c".into(), "}".into())];
        let r = render_ports(vec![port]);
        let cfg = &r.haproxy_cfg;
        for (i, w) in words.iter().enumerate() {
            assert!(
                cfg.contains(&format!(
                    "    acl r{i}_h0 req.fhdr(x-a) -m str -- {}\n",
                    quote(w)
                )),
                "{w}\n{cfg}"
            );
        }
        // Braces only inside quoted words, never as words of their own.
        let mut stripped = cfg.clone();
        for q in ["'{ }'", "'}'", "'{'", "'/}'", "'/{'", "'/}/'", "'/{/'"] {
            stripped = stripped.replace(q, "<quoted>");
        }
        assert!(!stripped.contains('{'), "{stripped}");
        assert!(!stripped.contains('}'), "{stripped}");
        // Every `use_backend` line is the keyword, the backend, and ACL names.
        let id = port_id(&gw("gw", "public"), 80);
        let lines = lines_of(cfg, "use_backend");
        assert_eq!(lines.len(), words.len() + 1);
        for (i, line) in lines[..words.len()].iter().enumerate() {
            assert_eq!(
                *line,
                format!("use_backend be_{id}_0 if r{i}_host r{i}_path r{i}_method r{i}_h0 r{i}_h1")
            );
        }
        assert_eq!(lines[words.len()], format!("use_backend be_{id}_0"));
    }

    #[test]
    fn sixteen_header_matches_are_named_acls_on_one_line() {
        let mut rule = http_rule(exact("a.example.com"), PathMatch::Exact("/x".into()), 0);
        rule.method = Some("GET".into());
        rule.headers = (0..16)
            .map(|i| (format!("x-h{i:02}"), format!("v{i}")))
            .collect();
        let mut port = simple_port(80, None);
        port.rules = vec![rule];
        let r = render_ports(vec![port]);
        let id = port_id(&gw("gw", "public"), 80);
        let mut want = vec![
            "acl r0_host req.hdr(host),host_only,lower -m str -- 'a.example.com'".to_owned(),
            "acl r0_path path -m str -- '/x'".to_owned(),
            "acl r0_method method 'GET'".to_owned(),
        ];
        want.extend((0..16).map(|i| format!("acl r0_h{i} req.fhdr(x-h{i:02}) -m str -- 'v{i}'")));
        let names: String = (0..16).map(|i| format!(" r0_h{i}")).collect();
        want.push(format!(
            "use_backend be_{id}_0 if r0_host r0_path r0_method{names}"
        ));
        let got = rule_lines(&r.haproxy_cfg);
        assert_eq!(got, want);
        // Well within the 64 words HAProxy reads on a line.
        assert_eq!(got.last().unwrap().split_whitespace().count(), 3 + 3 + 16);
    }

    /// The `location` of a port with one redirecting rule, and its status code.
    fn location(tls: bool, port: u16, redirect: Redirect) -> String {
        let p = http_port(
            port,
            tls.then(|| vec![cert("site", "1111111111111111")]),
            vec![http_rule(HostMatch::Any, prefix("/"), 0)],
            vec![http_backend(HttpAction::Redirect(redirect))],
        );
        let r = render_ports(vec![p]);
        let lines = lines_of(&r.haproxy_cfg, "http-request redirect");
        assert_eq!(lines.len(), 1, "{}", r.haproxy_cfg);
        lines[0]
            .strip_prefix("http-request redirect location ")
            .unwrap()
            .to_owned()
    }

    #[test]
    fn redirect_locations() {
        let redirect = |scheme: Option<&str>, hostname: Option<&str>, port: Option<u16>| Redirect {
            scheme: scheme.map(Into::into),
            hostname: hostname.map(Into::into),
            port,
            status: 302,
        };
        let cases = [
            (
                false,
                80,
                redirect(Some("https"), None, None),
                "'https://%[req.hdr(host),host_only]%[pathq]' code 302",
            ),
            (
                false,
                8080,
                redirect(None, None, None),
                "'http://%[req.hdr(host),host_only]:8080%[pathq]' code 302",
            ),
            (
                true,
                443,
                redirect(None, Some("b.example.com"), None),
                "'https://b.example.com%[pathq]' code 302",
            ),
            (
                false,
                80,
                redirect(Some("https"), None, Some(8443)),
                "'https://%[req.hdr(host),host_only]:8443%[pathq]' code 302",
            ),
            (
                false,
                80,
                redirect(Some("http"), None, Some(80)),
                "'http://%[req.hdr(host),host_only]%[pathq]' code 302",
            ),
            // More of the same.
            (
                false,
                80,
                redirect(None, None, None),
                "'http://%[req.hdr(host),host_only]%[pathq]' code 302",
            ),
            (
                true,
                8443,
                redirect(None, None, None),
                "'https://%[req.hdr(host),host_only]:8443%[pathq]' code 302",
            ),
            (
                true,
                8443,
                redirect(Some("http"), None, None),
                "'http://%[req.hdr(host),host_only]%[pathq]' code 302",
            ),
            (
                false,
                80,
                redirect(Some("https"), None, Some(443)),
                "'https://%[req.hdr(host),host_only]%[pathq]' code 302",
            ),
            (
                false,
                80,
                redirect(None, Some("b.example.com"), Some(8080)),
                "'http://b.example.com:8080%[pathq]' code 302",
            ),
            // A '%' in the host name, which the model never lets through, stays literal.
            (
                false,
                80,
                redirect(None, Some("b%[src]"), None),
                "'http://b%%[src]%[pathq]' code 302",
            ),
        ];
        for (tls, port, r, want) in cases {
            assert_eq!(location(tls, port, r.clone()), want, "{tls} {port} {r:?}");
        }
        for status in [301, 302, 303, 307, 308] {
            let mut r = redirect(None, None, None);
            r.status = status;
            assert!(location(false, 80, r).ends_with(&format!(" code {status}")));
        }
    }

    #[test]
    fn backend_no_rule_points_at_is_not_rendered() {
        let r = render_ports(vec![http_port(
            80,
            None,
            vec![
                http_rule(exact("a.example.com"), prefix("/"), 2),
                http_rule(HostMatch::Any, prefix("/"), 0),
            ],
            vec![
                forward(vec![backend("10.0.0.1", 80, 1)]),
                forward(vec![backend("10.0.0.2", 80, 1)]),
                forward(vec![backend("10.0.0.3", 80, 1)]),
            ],
        )]);
        let id = port_id(&gw("gw", "public"), 80);
        assert_eq!(
            lines_of(&r.haproxy_cfg, "backend "),
            [
                format!("backend be_{id}_0"),
                format!("backend be_{id}_2"),
                format!("backend be_{id}_none"),
            ]
        );
        assert!(!r.haproxy_cfg.contains("10.0.0.2"));
        assert!(r.haproxy_cfg.contains("server s0 10.0.0.3:80 weight 256\n"));
    }

    #[test]
    fn certificate_shared_by_two_ports_is_one_file() {
        let (a, b) = (
            cert("site-a", "1111111111111111"),
            cert("site-b", "2222222222222222"),
        );
        let r = render_ports(vec![
            simple_port(443, Some(vec![a.clone()])),
            simple_port(8443, Some(vec![a.clone(), b.clone()])),
        ]);
        let names: Vec<&str> = r.files.iter().map(|f| f.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(names, sorted, "sorted, without repeats");
        let pems: Vec<&str> = names
            .iter()
            .copied()
            .filter(|n| n.ends_with(".pem"))
            .collect();
        assert_eq!(pems, [a.file_name.as_str(), b.file_name.as_str()]);
        let lists: Vec<&SecretFile> = r
            .files
            .iter()
            .filter(|f| f.name.ends_with(".list"))
            .collect();
        assert_eq!(lists.len(), 2);
        let g = gw("gw", "public");
        for (port, certs) in [(443, vec![&a]), (8443, vec![&a, &b])] {
            let id = port_id(&g, port);
            let list = lists.iter().find(|f| f.name.starts_with(&id)).unwrap();
            let want: String = certs
                .iter()
                .map(|c| format!("/run/igw/certs/{}\n", c.file_name))
                .collect();
            assert_eq!(list.contents, want);
            assert!(r.haproxy_cfg.contains(&format!(
                "ssl crt-list /run/igw/certs/{} strict-sni",
                list.name
            )));
        }
    }

    #[test]
    fn rotated_certificate_changes_list_name_configuration_and_fingerprint() {
        let render_with = |c: Certificate| {
            render_ports(vec![simple_port(443, Some(vec![c])), simple_port(80, None)])
        };
        let old = render_with(cert("site", "1111111111111111"));
        let new = render_with(cert("site", "3333333333333333"));
        let list = |r: &Rendered| {
            r.files
                .iter()
                .find(|f| f.name.ends_with(".list"))
                .unwrap()
                .name
                .clone()
        };
        assert_ne!(list(&old), list(&new));
        assert_ne!(old.haproxy_cfg, new.haproxy_cfg);
        assert!(new.haproxy_cfg.contains(&list(&new)));
        assert!(!new.haproxy_cfg.contains(&list(&old)));
        let names: Vec<&str> = new.files.iter().map(|f| f.name.as_str()).collect();
        assert!(
            !names.contains(&"gw.site.1111111111111111.pem"),
            "{names:?}"
        );
        assert!(names.contains(&"gw.site.3333333333333333.pem"), "{names:?}");
        let (o, n) = (&old.edges[0].sockets, &new.edges[0].sockets);
        assert_ne!(o[&tcp(443)].fingerprint, n[&tcp(443)].fingerprint);
        assert_eq!(o[&tcp(443)].socket, n[&tcp(443)].socket);
        // The other port is untouched.
        assert_eq!(o[&tcp(80)], n[&tcp(80)]);
    }

    #[test]
    fn http_ports_are_in_the_edge_plan() {
        let r = render_ports(vec![
            simple_port(80, None),
            simple_port(443, Some(vec![cert("site", "1111111111111111")])),
        ]);
        let g = gw("gw", "public");
        assert_eq!(r.edges.len(), 1);
        let sockets = &r.edges[0].sockets;
        let mut keys: Vec<ListenerKey> = sockets.keys().copied().collect();
        keys.sort_by_key(|k| k.port);
        assert_eq!(keys, [tcp(80), tcp(443)]);
        for port in [80, 443] {
            let id = port_id(&g, port);
            assert_eq!(
                sockets[&tcp(port)],
                PortPlan {
                    socket: PathBuf::from(format!("/run/igw/s/{id}.sock")),
                    fingerprint: fingerprint_of(&r.haproxy_cfg, &id),
                    shared: true,
                }
            );
        }
    }

    #[test]
    fn tcp_and_http_ports_of_one_gateway_render_together() {
        let a = gw("a", "x");
        let b = gw("b", "y");
        let mut first = http_gateway(
            a.clone(),
            // Out of order in the model.
            vec![simple_port(8080, None), simple_port(80, None)],
        );
        first.listeners = vec![listener(5432, vec![backend("10.0.0.5", 5432, 1)])];
        let second = gateway(
            b.clone(),
            vec![listener(81, vec![backend("10.0.0.6", 81, 1)])],
        );
        let m = model(
            vec![second, first],
            vec![edge("e1", 1, &a), edge("e2", 2, &b)],
        );
        let r = render_in(&m);
        let comments = lines_of(&r.haproxy_cfg, "# ");
        // TCP ports first, then HTTP ports ascending; then the next gateway.
        assert_eq!(
            comments,
            [
                "# a/x port 5432",
                "# a/x port 80",
                "# a/x port 8080",
                "# b/y port 81"
            ]
        );
        assert!(
            r.haproxy_cfg
                .contains(&format!("frontend fe_{}\n    bind", port_id(&a, 5432)))
        );
        assert!(
            r.haproxy_cfg
                .contains(&format!("frontend fe_{}\n    mode http\n", port_id(&a, 80)))
        );
        assert_eq!(r.edges.len(), 2);
        let mut ports: Vec<u16> = r.edges[0].sockets.keys().map(|k| k.port).collect();
        ports.sort_unstable();
        assert_eq!(ports, [80, 5432, 8080]);
        let ports: Vec<u16> = r.edges[1].sockets.keys().map(|k| k.port).collect();
        assert_eq!(ports, [81]);
        // The TCP port's fingerprint covers only its own sections.
        let id = port_id(&a, 5432);
        assert_eq!(
            r.edges[0].sockets[&tcp(5432)].fingerprint,
            fingerprint_of(&r.haproxy_cfg, &id)
        );
    }

    #[test]
    fn http_listeners_render_from_http_ports() {
        // A serving HTTP listener gets no TCP frontend of its own; its port renders from the
        // gateway's `http_ports`, and only if there is one.
        let g = gw("gw", "public");
        let mut http = listener(80, vec![backend("10.0.0.9", 80, 1)]);
        http.protocol = "HTTP".into();
        http.supported_kinds = vec!["HTTPRoute".into()];
        assert!(http.serving(), "precondition");
        let mut without = gateway(g.clone(), vec![http.clone()]);
        let r = render_in(&model(vec![without.clone()], vec![edge("e1", 1, &g)]));
        assert_eq!(r.haproxy_cfg, include_str!("testdata/empty.cfg"));
        assert!(r.edges[0].sockets.is_empty());

        without.http_ports = vec![simple_port(80, None)];
        let r = render_in(&model(vec![without], vec![edge("e1", 1, &g)]));
        assert_eq!(lines_of(&r.haproxy_cfg, "frontend fe_").len(), 1);
        assert!(r.haproxy_cfg.contains("    mode http\n"));
        // The listener's own backend is not what the port serves.
        assert!(!r.haproxy_cfg.contains("10.0.0.9"));
        assert_eq!(
            r.edges[0].sockets.keys().copied().collect::<Vec<_>>(),
            [tcp(80)]
        );
    }

    #[test]
    fn debug_of_rendered_hides_key_material() {
        let c = cert("site", "1111111111111111");
        let r = render_ports(vec![simple_port(443, Some(vec![c.clone()]))]);
        let file = r.files.iter().find(|f| f.name == c.file_name).unwrap();
        assert!(file.contents.contains(KEY_LINE), "precondition");
        for shown in [format!("{r:?}"), format!("{r:#?}")] {
            assert!(shown.contains(&c.file_name), "{shown}");
            assert!(!shown.contains("PRIVATE KEY"), "{shown}");
            assert!(!shown.contains(KEY_LINE), "{shown}");
        }
        // Nor does the configuration name anything but the file.
        assert!(!r.haproxy_cfg.contains(KEY_LINE));
    }

    // ---- UDP listeners ----

    fn udp_listener(port: u16, backends: Vec<Backend>) -> ListenerModel {
        let mut l = listener(port, backends);
        l.protocol = "UDP".into();
        l.supported_kinds = vec!["UDPRoute".into()];
        l
    }

    fn target(addr: &str, weight: u32) -> UdpTarget {
        UdpTarget {
            addr: addr.parse().unwrap(),
            weight,
        }
    }

    /// The plan of the one edge of gateway `gw/public` with `listeners`.
    fn plan_of(listeners: Vec<ListenerModel>) -> (Rendered, EdgePlan) {
        let g = gw("gw", "public");
        let r = render_in(&model(
            vec![gateway(g.clone(), listeners)],
            vec![edge("e1", 1, &g)],
        ));
        assert_eq!(r.edges.len(), 1);
        let plan = r.edges[0].clone();
        (r, plan)
    }

    #[test]
    fn udp_listener_adds_nothing_to_the_configuration() {
        // The model of `one_gateway_one_port`.
        let tcp_only = vec![listener(
            5432,
            vec![backend("10.0.0.1", 5432, 1), backend("10.0.0.2", 5432, 3)],
        )];
        let mut with_udp = tcp_only.clone();
        let udp = udp_listener(53, vec![backend("10.0.0.2", 53, 1)]);
        assert!(udp.serving(), "precondition");
        with_udp.push(udp);
        let (without, plan_without) = plan_of(tcp_only);
        let (with, plan_with) = plan_of(with_udp);
        assert_eq!(with.haproxy_cfg, without.haproxy_cfg);
        assert_eq!(with.haproxy_cfg, include_str!("testdata/one.cfg"));
        assert_eq!(with.files, without.files);
        assert_eq!(plan_with.sockets, plan_without.sockets);
        assert!(plan_without.udp.is_empty());
        assert!(!plan_with.udp.is_empty());
    }

    #[test]
    fn udp_targets_follow_the_listener_backends() {
        let (r, plan) = plan_of(vec![udp_listener(
            53,
            vec![backend("10.0.0.1", 53, 1), backend("10.0.0.2", 53, 3)],
        )]);
        assert_eq!(
            plan.udp,
            BTreeMap::from([(53, vec![target("10.0.0.1:53", 1), target("10.0.0.2:53", 3)])])
        );
        assert!(plan.sockets.is_empty());
        assert_eq!(r.haproxy_cfg, include_str!("testdata/empty.cfg"));
    }

    #[test]
    fn udp_listener_without_a_route_has_no_targets() {
        let mut l = udp_listener(53, vec![]);
        l.attached_routes = 0;
        assert!(!l.serving(), "precondition");
        let (r, plan) = plan_of(vec![l]);
        assert!(!plan.udp.contains_key(&53), "{:?}", plan.udp);
        assert_eq!(r.haproxy_cfg, include_str!("testdata/empty.cfg"));
    }

    #[test]
    fn tcp_and_udp_on_one_port_give_a_socket_and_targets() {
        let (r, plan) = plan_of(vec![
            listener(53, vec![backend("10.0.0.1", 53, 1)]),
            udp_listener(53, vec![backend("10.0.0.2", 53, 1)]),
        ]);
        assert_eq!(plan.sockets.keys().copied().collect::<Vec<_>>(), [tcp(53)]);
        assert_eq!(
            plan.udp,
            BTreeMap::from([(53, vec![target("10.0.0.2:53", 1)])])
        );
        // Only the TCP listener is in the configuration.
        assert_eq!(lines_of(&r.haproxy_cfg, "frontend fe_").len(), 1);
        assert!(r.haproxy_cfg.contains("10.0.0.1:53"));
        assert!(!r.haproxy_cfg.contains("10.0.0.2"));
    }

    #[test]
    fn ipv6_backend_is_a_target() {
        let (_, plan) = plan_of(vec![udp_listener(53, vec![backend("fd00::53", 5353, 2)])]);
        assert_eq!(
            plan.udp,
            BTreeMap::from([(53, vec![target("[fd00::53]:5353", 2)])])
        );
    }
}
