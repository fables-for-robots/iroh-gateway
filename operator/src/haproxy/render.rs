//! Render a [`Model`] into the HAProxy configuration and one [`EdgePlan`] per accepted edge.
//!
//! Everything here is pure and its output is byte-for-byte stable for equal models: the engine
//! reloads HAProxy only when the text changes.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use iroh_gateway_proto::control::{ListenerKey, Protocol};
use sha2::{Digest, Sha256};

use crate::model::{GatewayModel, Model, ObjRef};

/// What the model asks of HAProxy and of the edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub haproxy_cfg: String,
    /// One per accepted edge of an accepted Gateway, sorted by key.
    pub edges: Vec<EdgePlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgePlan {
    pub key: ObjRef,
    pub endpoint_id: iroh::EndpointId,
    pub address: Option<String>,
    pub gateway: ObjRef,
    /// The Gateway's serving TCP ports and what HAProxy serves behind each.
    pub sockets: HashMap<ListenerKey, PortPlan>,
}

/// One port of an [`EdgePlan`]: HAProxy's socket for it, and a fingerprint of what is behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortPlan {
    pub socket: PathBuf,
    /// The first 16 hex characters of SHA-256 over the exact text of the port's `frontend` and
    /// `backend` sections: equal fingerprints, equal traffic behind the socket.
    pub fingerprint: String,
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
         \n\
         frontend idle\n\
         \x20   bind unix@{dir}/s/idle.sock mode 600\n\
         \x20   tcp-request connection reject\n"
    );

    let mut gateways: Vec<&GatewayModel> = model
        .gateways
        .iter()
        .filter(|g| g.accepted.is_ok())
        .collect();
    gateways.sort_by(|a, b| a.key.cmp(&b.key));

    let mut sockets: HashMap<&ObjRef, HashMap<ListenerKey, PortPlan>> = HashMap::new();
    for gateway in &gateways {
        let per_gateway = sockets.entry(&gateway.key).or_default();
        let mut listeners: Vec<_> = gateway.listeners.iter().filter(|l| l.serving()).collect();
        listeners.sort_by_key(|l| l.port);
        for listener in listeners {
            let id = port_id(&gateway.key, listener.port);
            let _ = write!(cfg, "\n# {} port {}\n", gateway.key, listener.port);
            // The port's own sections, which its fingerprint covers.
            let mut section = format!(
                "frontend fe_{id}\n\
                 \x20   bind unix@{dir}/s/{id}.sock accept-proxy mode 600\n\
                 \x20   default_backend be_{id}\n\
                 \n\
                 backend be_{id}\n"
            );
            let weights: Vec<u32> = listener.backends.iter().map(|b| b.weight).collect();
            for (i, (backend, weight)) in listener
                .backends
                .iter()
                .zip(scale_weights(&weights))
                .enumerate()
            {
                if weight == 0 {
                    continue;
                }
                let _ = match backend.ip {
                    IpAddr::V4(ip) => {
                        writeln!(
                            section,
                            "    server s{i} {ip}:{} weight {weight}",
                            backend.port
                        )
                    }
                    IpAddr::V6(ip) => writeln!(
                        section,
                        "    server s{i} [{ip}]:{} weight {weight}",
                        backend.port
                    ),
                };
            }
            cfg.push_str(&section);
            let digest = hex::encode(Sha256::digest(&section));
            per_gateway.insert(
                ListenerKey {
                    protocol: Protocol::Tcp,
                    port: listener.port,
                },
                PortPlan {
                    socket: socket(&id),
                    fingerprint: digest[..16].to_owned(),
                },
            );
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
            })
        })
        .collect();
    edges.sort_by(|a, b| a.key.cmp(&b.key));

    Rendered {
        haproxy_cfg: cfg,
        edges,
    }
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
    use crate::model::{Backend, EdgeModel, GatewayModel, HostMatch, ListenerModel, Reject};

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
            addresses: Vec::new(),
            addresses_dropped: 0,
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
}
