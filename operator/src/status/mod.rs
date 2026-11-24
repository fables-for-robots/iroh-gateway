//! What status every resource should carry, computed from the model and the runtime facts.
//!
//! [`compute`] is pure: equal inputs give equal [`DesiredStatus`]. [`conditions::merge`] folds the
//! desired conditions into those an object already has.

pub mod conditions;

use std::collections::BTreeMap;

use iroh_gateway_proto::control::Protocol;

use crate::crd::EdgeListenerStatus;
use crate::model::{
    EdgeModel, GatewayAddress, GatewayModel, ListenerModel, MAX_GATEWAY_ADDRESSES, Model, ObjRef,
    ParentKey, Reject, RouteKind,
};
use crate::tunnel::{EdgeState, ListenerState};

/// What the engine reports about the running system.
#[derive(Debug, Clone)]
pub struct Facts {
    pub operator_id: iroh::EndpointId,
    /// Result of the last HAProxy apply.
    pub haproxy: Result<(), String>,
    pub edges: BTreeMap<ObjRef, EdgeState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cond {
    pub type_: String,
    pub status: bool,
    pub reason: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredStatus {
    pub classes: Vec<ClassStatus>,
    pub gateways: Vec<GatewayStatusOut>,
    pub routes: Vec<RouteStatusOut>,
    pub edges: Vec<EdgeStatusOut>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassStatus {
    pub name: String,
    pub generation: i64,
    pub conditions: Vec<Cond>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayStatusOut {
    pub key: ObjRef,
    pub generation: i64,
    pub conditions: Vec<Cond>,
    pub addresses: Vec<GatewayAddress>,
    pub listeners: Vec<ListenerStatusOut>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerStatusOut {
    pub name: String,
    pub supported_kinds: Vec<String>,
    pub attached_routes: i32,
    pub conditions: Vec<Cond>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteStatusOut {
    pub kind: RouteKind,
    pub key: ObjRef,
    pub generation: i64,
    pub parents: Vec<(ParentKey, Vec<Cond>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeStatusOut {
    pub key: ObjRef,
    pub generation: i64,
    pub gateway_endpoint_id: String,
    pub conditions: Vec<Cond>,
    pub listeners: Vec<EdgeListenerStatus>,
}

const NOT_STARTED: &str = "the link has not started yet";

fn cond(type_: &str, ok: bool, reason: &str, message: impl Into<String>) -> Cond {
    Cond {
        type_: type_.to_owned(),
        status: ok,
        reason: reason.to_owned(),
        message: message.into(),
    }
}

/// True with reason `ok_reason` when `r` is Ok, otherwise False with the reject's reason.
fn from_result(type_: &str, r: &Result<(), Reject>, ok_reason: &str) -> Cond {
    match r {
        Ok(()) => cond(type_, true, ok_reason, ""),
        Err(rej) => cond(type_, false, &rej.reason, rej.message.clone()),
    }
}

/// The status every resource in the model should carry, given what the engine reports.
pub fn compute(model: &Model, facts: &Facts) -> DesiredStatus {
    let mut classes: Vec<ClassStatus> = model
        .classes
        .iter()
        .map(|c| ClassStatus {
            name: c.name.clone(),
            generation: c.generation,
            conditions: vec![cond("Accepted", true, "Accepted", "")],
        })
        .collect();
    classes.sort_by(|a, b| a.name.cmp(&b.name));

    let mut gateways: Vec<GatewayStatusOut> = model
        .gateways
        .iter()
        .map(|g| gateway_status(g, facts))
        .collect();
    gateways.sort_by(|a, b| a.key.cmp(&b.key));

    let mut routes: Vec<RouteStatusOut> = model
        .routes
        .iter()
        .map(|r| {
            let mut parents: Vec<(ParentKey, Vec<Cond>)> = r
                .parents
                .iter()
                .map(|p| {
                    (
                        p.parent.clone(),
                        vec![
                            from_result("Accepted", &p.accepted, "Accepted"),
                            from_result("ResolvedRefs", &p.resolved_refs, "ResolvedRefs"),
                        ],
                    )
                })
                .collect();
            parents.sort_by(|a, b| a.0.cmp(&b.0));
            RouteStatusOut {
                kind: r.kind,
                key: r.key.clone(),
                generation: r.generation,
                parents,
            }
        })
        .collect();
    routes.sort_by(|a, b| (a.kind, &a.key).cmp(&(b.kind, &b.key)));

    let mut edges: Vec<EdgeStatusOut> = model
        .edges
        .iter()
        .map(|e| edge_status(model, e, facts))
        .collect();
    edges.sort_by(|a, b| a.key.cmp(&b.key));

    DesiredStatus {
        classes,
        gateways,
        routes,
        edges,
    }
}

/// The ports of the listeners that get a frontend and an open port on the edges, ascending.
fn serving_ports(gateway: &GatewayModel) -> Vec<u16> {
    let mut ports: Vec<u16> = gateway
        .listeners
        .iter()
        .filter(|l| l.serving())
        .map(|l| l.port)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn tcp_port(state: &EdgeState, port: u16) -> Option<&ListenerState> {
    state
        .listeners
        .iter()
        .find(|l| l.key.protocol == Protocol::Tcp && l.key.port == port)
}

/// The first of `ports` (given ascending) that the edge does not report as bound, with why.
fn first_unbound(state: &EdgeState, ports: &[u16]) -> Option<(u16, Option<String>)> {
    ports.iter().find_map(|&port| match tcp_port(state, port) {
        Some(ListenerState { bound: Ok(()), .. }) => None,
        Some(ListenerState { bound: Err(e), .. }) => Some((port, Some(e.clone()))),
        None => Some((port, None)),
    })
}

/// None when the edge is ready, otherwise why it is not.
fn not_ready(state: Option<&EdgeState>, ports: &[u16]) -> Option<String> {
    let Some(state) = state else {
        return Some(NOT_STARTED.to_owned());
    };
    if !state.connected {
        return Some(
            state
                .last_error
                .clone()
                .unwrap_or_else(|| NOT_STARTED.to_owned()),
        );
    }
    first_unbound(state, ports).map(|(port, why)| match why {
        Some(e) => format!("connected, port {port}: {e}"),
        None => format!("connected, port {port} not reported yet"),
    })
}

fn gateway_status(g: &GatewayModel, facts: &Facts) -> GatewayStatusOut {
    let ports = serving_ports(g);
    let mut edge_keys = g.edges.clone();
    edge_keys.sort();
    let problems: Vec<(&ObjRef, Option<String>)> = edge_keys
        .iter()
        .map(|k| (k, not_ready(facts.edges.get(k), &ports)))
        .collect();
    let any_ready = problems.iter().any(|(_, p)| p.is_none());

    let all_listeners_fine = g
        .listeners
        .iter()
        .all(|l| l.accepted.is_ok() && l.conflicted.is_none());
    let accepted = match &g.accepted {
        Ok(()) if all_listeners_fine => cond("Accepted", true, "Accepted", ""),
        Ok(()) => cond(
            "Accepted",
            true,
            "ListenersNotValid",
            "some listeners are not valid; see the listener conditions",
        ),
        Err(rej) => cond("Accepted", false, &rej.reason, rej.message.clone()),
    };

    let programmed = if let Err(rej) = &g.accepted {
        cond("Programmed", false, "Invalid", rej.message.clone())
    } else if let Err(e) = &facts.haproxy {
        cond("Programmed", false, "Invalid", e.clone())
    } else if g.edges.is_empty() {
        cond(
            "Programmed",
            false,
            "AddressNotAssigned",
            "no accepted Edge is bound to this Gateway",
        )
    } else if !any_ready {
        let why: Vec<String> = problems
            .iter()
            .map(|(k, p)| format!("edge {k}: {}", p.as_deref().unwrap_or("ready")))
            .collect();
        cond(
            "Programmed",
            false,
            "Pending",
            format!("no edge is ready: {}", why.join("; ")),
        )
    } else {
        cond("Programmed", true, "Programmed", "")
    };
    let (accepted, programmed) = note_dropped_addresses(g.addresses_dropped, accepted, programmed);

    let mut listeners: Vec<ListenerStatusOut> = g
        .listeners
        .iter()
        .map(|l| listener_status(g, l, facts, &edge_keys))
        .collect();
    listeners.sort_by(|a, b| a.name.cmp(&b.name));

    GatewayStatusOut {
        key: g.key.clone(),
        generation: g.generation,
        conditions: vec![accepted, programmed],
        addresses: g.addresses.clone(),
        listeners,
    }
}

/// When the Gateway lists fewer addresses than its edges have, says so in `Programmed`'s message
/// when it is True, otherwise in `Accepted`'s.
fn note_dropped_addresses(
    dropped: usize,
    mut accepted: Cond,
    mut programmed: Cond,
) -> (Cond, Cond) {
    if dropped > 0 {
        let verb = if dropped == 1 { "is" } else { "are" };
        let note = format!(
            "{dropped} of the edges' addresses {verb} not listed: a Gateway lists at most \
             {MAX_GATEWAY_ADDRESSES}"
        );
        let target = if programmed.status {
            &mut programmed
        } else {
            &mut accepted
        };
        target.message = if target.message.is_empty() {
            note
        } else {
            format!("{}; {note}", target.message)
        };
    }
    (accepted, programmed)
}

fn listener_status(
    g: &GatewayModel,
    l: &ListenerModel,
    facts: &Facts,
    edge_keys: &[ObjRef],
) -> ListenerStatusOut {
    let conflicted = match &l.conflicted {
        Some(rej) => cond("Conflicted", true, &rej.reason, rej.message.clone()),
        None => cond("Conflicted", false, "NoConflicts", ""),
    };
    let programmed = if let Err(rej) = &l.accepted {
        cond("Programmed", false, "Invalid", rej.message.clone())
    } else if let Some(rej) = &l.conflicted {
        cond("Programmed", false, "Invalid", rej.message.clone())
    } else if l.protocol == "HTTPS" && l.certificates.is_empty() {
        let message = match &l.resolved_refs {
            Err(rej) => rej.message.clone(),
            Ok(()) => "the listener has no usable certificate".to_owned(),
        };
        cond("Programmed", false, "Invalid", message)
    } else if let Err(rej) = &g.accepted {
        cond(
            "Programmed",
            false,
            "Invalid",
            format!("the Gateway is not accepted: {}", rej.message),
        )
    } else if let Err(e) = &facts.haproxy {
        cond("Programmed", false, "Invalid", e.clone())
    } else {
        listener_programmed(l, facts, edge_keys)
    };
    ListenerStatusOut {
        name: l.name.clone(),
        supported_kinds: l.supported_kinds.clone(),
        attached_routes: l.attached_routes,
        conditions: vec![
            from_result("Accepted", &l.accepted, "Accepted"),
            conflicted,
            from_result("ResolvedRefs", &l.resolved_refs, "ResolvedRefs"),
            programmed,
        ],
    }
}

/// `Programmed` of a listener that is valid, of an accepted Gateway, with HAProxy fine: True once
/// an accepted, connected edge of the Gateway reports the listener's port bound, or, for a
/// listener that is not serving, once one is connected.
fn listener_programmed(l: &ListenerModel, facts: &Facts, edge_keys: &[ObjRef]) -> Cond {
    let serving = l.serving();
    let connected = |k: &ObjRef| facts.edges.get(k).filter(|s| s.connected);
    let ready = edge_keys.iter().filter_map(connected).any(|state| {
        !serving
            || matches!(
                tcp_port(state, l.port),
                Some(ListenerState { bound: Ok(()), .. })
            )
    });
    if ready {
        return cond("Programmed", true, "Programmed", "");
    }
    if edge_keys.is_empty() {
        return cond(
            "Programmed",
            false,
            "Pending",
            "no accepted Edge is bound to this Gateway",
        );
    }
    let mut bind_errors = Vec::new();
    let mut others = Vec::new();
    for k in edge_keys {
        match facts.edges.get(k) {
            Some(state) if state.connected => match tcp_port(state, l.port) {
                Some(ListenerState { bound: Err(e), .. }) => {
                    bind_errors.push(format!("edge {k} cannot bind port {}: {e}", l.port));
                }
                _ => others.push(format!("edge {k} has not reported port {} yet", l.port)),
            },
            state => {
                let why = state
                    .and_then(|s| s.last_error.as_deref())
                    .unwrap_or(NOT_STARTED);
                others.push(format!("edge {k} is not connected: {why}"));
            }
        }
    }
    let message = if bind_errors.is_empty() {
        others.join("; ")
    } else {
        bind_errors.join("; ")
    };
    cond("Programmed", false, "Pending", message)
}

fn edge_status(model: &Model, e: &EdgeModel, facts: &Facts) -> EdgeStatusOut {
    // An edge the model rejects is never connected or programmed, whatever the facts say.
    let state = facts.edges.get(&e.key).filter(|_| e.accepted.is_ok());
    let accepted = e.accepted.is_ok();
    let connected = state.is_some_and(|s| s.connected);
    let not_connected_message = match state {
        _ if !accepted => "the edge is not accepted".to_owned(),
        Some(s) => s
            .last_error
            .clone()
            .unwrap_or_else(|| NOT_STARTED.to_owned()),
        None => NOT_STARTED.to_owned(),
    };
    let connected_cond = if connected {
        cond("Connected", true, "Connected", "")
    } else {
        cond(
            "Connected",
            false,
            "NotConnected",
            not_connected_message.clone(),
        )
    };
    let ports = e
        .gateway
        .as_ref()
        .and_then(|k| model.gateways.iter().find(|g| &g.key == k))
        .map(serving_ports)
        .unwrap_or_default();
    let programmed = match state {
        Some(s) if connected => {
            // A port the edge reported as failed comes before one it has not reported yet.
            let failed = ports.iter().find_map(|&port| match tcp_port(s, port) {
                Some(ListenerState { bound: Err(e), .. }) => Some((port, e)),
                _ => None,
            });
            match (failed, first_unbound(s, &ports)) {
                (Some((port, why)), _) => cond(
                    "Programmed",
                    false,
                    "BindFailed",
                    format!("port {port} is not bound: {why}"),
                ),
                (None, Some((port, _))) => cond(
                    "Programmed",
                    false,
                    "Pending",
                    format!("port {port} not reported yet"),
                ),
                (None, None) => cond("Programmed", true, "Programmed", ""),
            }
        }
        _ => cond("Programmed", false, "NotConnected", not_connected_message),
    };
    let mut listeners: Vec<EdgeListenerStatus> = state
        .map(|s| {
            s.listeners
                .iter()
                .map(|l| EdgeListenerStatus {
                    protocol: match l.key.protocol {
                        Protocol::Tcp => "TCP",
                        Protocol::Udp => "UDP",
                    }
                    .to_owned(),
                    port: l.key.port,
                    bound: l.bound.is_ok(),
                    message: l.bound.as_ref().err().cloned(),
                })
                .collect()
        })
        .unwrap_or_default();
    listeners.sort_by(|a, b| (a.port, &a.protocol).cmp(&(b.port, &b.protocol)));
    EdgeStatusOut {
        key: e.key.clone(),
        generation: e.generation,
        gateway_endpoint_id: facts.operator_id.to_string(),
        conditions: vec![
            from_result("Accepted", &e.accepted, "Accepted"),
            connected_cond,
            programmed,
        ],
        listeners,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_gateway_proto::control::ListenerKey;

    const NOT_STARTED: &str = "the link has not started yet";

    fn op_id() -> iroh::EndpointId {
        iroh::SecretKey::from_bytes(&[9; 32]).public()
    }

    fn listener(name: &str, port: u16, serving: bool) -> ListenerModel {
        ListenerModel {
            name: name.into(),
            port,
            protocol: "TCP".into(),
            hostname: crate::model::HostMatch::Any,
            accepted: Ok(()),
            conflicted: None,
            resolved_refs: Ok(()),
            supported_kinds: vec!["TCPRoute".into()],
            allowed_namespaces: Default::default(),
            attached_routes: i32::from(serving),
            backends: if serving {
                vec![crate::model::Backend {
                    service: ObjRef::new("ns", "svc"),
                    ip: "10.0.0.1".parse().unwrap(),
                    port: 80,
                    weight: 1,
                }]
            } else {
                vec![]
            },
            certificates: Vec::new(),
        }
    }

    fn gateway(listeners: Vec<ListenerModel>, edges: &[&str]) -> GatewayModel {
        GatewayModel {
            key: ObjRef::new("ns", "gw"),
            generation: 4,
            accepted: Ok(()),
            listeners,
            edges: edges.iter().map(|e| ObjRef::new("ns", *e)).collect(),
            addresses: vec![],
            addresses_dropped: 0,
            http_ports: Vec::new(),
        }
    }

    fn edge(name: &str, accepted: Result<(), Reject>) -> EdgeModel {
        EdgeModel {
            key: ObjRef::new("ns", name),
            generation: 2,
            accepted,
            endpoint_id: None,
            address: None,
            gateway: Some(ObjRef::new("ns", "gw")),
            public_addresses: vec![],
        }
    }

    fn model(gw: GatewayModel, edges: Vec<EdgeModel>) -> Model {
        Model {
            classes: vec![crate::model::ClassModel {
                name: "cls".into(),
                generation: 1,
            }],
            gateways: vec![gw],
            edges,
            routes: vec![],
        }
    }

    fn bound(port: u16, r: Result<(), &str>) -> ListenerState {
        ListenerState {
            key: ListenerKey {
                protocol: Protocol::Tcp,
                port,
            },
            bound: r.map_err(str::to_owned),
        }
    }

    fn up(listeners: Vec<ListenerState>) -> EdgeState {
        EdgeState {
            connected: true,
            listeners,
            ..Default::default()
        }
    }

    fn down(err: Option<&str>) -> EdgeState {
        EdgeState {
            connected: false,
            last_error: err.map(str::to_owned),
            ..Default::default()
        }
    }

    fn facts(edges: Vec<(&str, EdgeState)>) -> Facts {
        Facts {
            operator_id: op_id(),
            haproxy: Ok(()),
            edges: edges
                .into_iter()
                .map(|(n, s)| (ObjRef::new("ns", n), s))
                .collect(),
        }
    }

    fn get<'a>(conds: &'a [Cond], type_: &str) -> &'a Cond {
        conds.iter().find(|c| c.type_ == type_).unwrap()
    }

    fn check(c: &Cond, status: bool, reason: &str) {
        assert_eq!((c.status, c.reason.as_str()), (status, reason), "{c:?}");
    }

    fn types(conds: &[Cond]) -> Vec<&str> {
        conds.iter().map(|c| c.type_.as_str()).collect()
    }

    #[test]
    fn healthy_gateway_is_programmed() {
        let m = model(
            gateway(vec![listener("a", 80, true)], &["e"]),
            vec![edge("e", Ok(()))],
        );
        let d = compute(&m, &facts(vec![("e", up(vec![bound(80, Ok(()))]))]));
        assert_eq!(types(&d.classes[0].conditions), ["Accepted"]);
        check(get(&d.classes[0].conditions, "Accepted"), true, "Accepted");
        let g = &d.gateways[0];
        assert_eq!(types(&g.conditions), ["Accepted", "Programmed"]);
        check(get(&g.conditions, "Accepted"), true, "Accepted");
        check(get(&g.conditions, "Programmed"), true, "Programmed");
        let l = &g.listeners[0];
        assert_eq!(
            types(&l.conditions),
            ["Accepted", "Conflicted", "ResolvedRefs", "Programmed"]
        );
        check(get(&l.conditions, "Accepted"), true, "Accepted");
        check(get(&l.conditions, "Conflicted"), false, "NoConflicts");
        check(get(&l.conditions, "ResolvedRefs"), true, "ResolvedRefs");
        check(get(&l.conditions, "Programmed"), true, "Programmed");
        let e = &d.edges[0];
        assert_eq!(
            types(&e.conditions),
            ["Accepted", "Connected", "Programmed"]
        );
        check(get(&e.conditions, "Accepted"), true, "Accepted");
        check(get(&e.conditions, "Connected"), true, "Connected");
        check(get(&e.conditions, "Programmed"), true, "Programmed");
        assert_eq!(e.listeners.len(), 1);
        assert_eq!(e.listeners[0].protocol, "TCP");
        assert!(e.listeners[0].bound);
        assert_eq!(e.listeners[0].message, None);
    }

    #[test]
    fn no_edge_is_address_not_assigned() {
        let m = model(gateway(vec![listener("a", 80, true)], &[]), vec![]);
        let d = compute(&m, &facts(vec![]));
        let g = &d.gateways[0];
        check(
            get(&g.conditions, "Programmed"),
            false,
            "AddressNotAssigned",
        );
        assert!(g.addresses.is_empty());
    }

    #[test]
    fn dropped_addresses_are_counted_in_programmed_or_accepted() {
        let mut gw = gateway(vec![listener("a", 80, true)], &["e"]);
        gw.addresses_dropped = 3;
        let m = model(gw, vec![edge("e", Ok(()))]);
        // Programmed is True: its message says it.
        let d = compute(&m, &facts(vec![("e", up(vec![bound(80, Ok(()))]))]));
        let g = &d.gateways[0];
        let p = get(&g.conditions, "Programmed");
        check(p, true, "Programmed");
        assert!(
            p.message
                .contains("3 of the edges' addresses are not listed"),
            "{}",
            p.message
        );
        assert_eq!(get(&g.conditions, "Accepted").message, "");
        // Programmed is False: the Accepted message says it.
        let d = compute(&m, &facts(vec![("e", down(Some("boom")))]));
        let g = &d.gateways[0];
        let p = get(&g.conditions, "Programmed");
        check(p, false, "Pending");
        assert!(!p.message.contains("not listed"), "{}", p.message);
        let a = get(&g.conditions, "Accepted");
        check(a, true, "Accepted");
        assert!(
            a.message
                .contains("3 of the edges' addresses are not listed"),
            "{}",
            a.message
        );
        // Nothing dropped, nothing said.
        let m = model(
            gateway(vec![listener("a", 80, true)], &["e"]),
            vec![edge("e", Ok(()))],
        );
        let d = compute(&m, &facts(vec![("e", up(vec![bound(80, Ok(()))]))]));
        assert_eq!(get(&d.gateways[0].conditions, "Programmed").message, "");
    }

    #[test]
    fn disconnected_edge_keeps_addresses_and_is_pending() {
        let mut gw = gateway(vec![listener("a", 80, true)], &["e"]);
        gw.addresses = vec![GatewayAddress::parse("203.0.113.7").unwrap()];
        let m = model(gw, vec![edge("e", Ok(()))]);
        let d = compute(&m, &facts(vec![("e", down(Some("dial timed out")))]));
        let g = &d.gateways[0];
        let p = get(&g.conditions, "Programmed");
        check(p, false, "Pending");
        assert!(p.message.contains("ns/e"), "{}", p.message);
        assert!(p.message.contains("dial timed out"), "{}", p.message);
        assert_eq!(
            g.addresses,
            vec![GatewayAddress::parse("203.0.113.7").unwrap()]
        );
        let e = &d.edges[0];
        let c = get(&e.conditions, "Connected");
        check(c, false, "NotConnected");
        assert_eq!(c.message, "dial timed out");
        check(get(&e.conditions, "Programmed"), false, "NotConnected");
    }

    #[test]
    fn missing_state_means_link_not_started() {
        let m = model(
            gateway(vec![listener("a", 80, true)], &["e"]),
            vec![edge("e", Ok(()))],
        );
        let d = compute(&m, &facts(vec![]));
        let c = get(&d.edges[0].conditions, "Connected");
        check(c, false, "NotConnected");
        assert_eq!(c.message, NOT_STARTED);
        assert!(d.edges[0].listeners.is_empty());
        let p = get(&d.gateways[0].conditions, "Programmed");
        check(p, false, "Pending");
        assert!(p.message.contains(NOT_STARTED), "{}", p.message);
    }

    #[test]
    fn bind_error_shows_on_listener_and_edge() {
        let m = model(
            gateway(
                vec![listener("a", 80, true), listener("b", 81, true)],
                &["e"],
            ),
            vec![edge("e", Ok(()))],
        );
        let st = up(vec![bound(81, Ok(())), bound(80, Err("address in use"))]);
        let d = compute(&m, &facts(vec![("e", st)]));
        let g = &d.gateways[0];
        let a = get(&g.listeners[0].conditions, "Programmed");
        check(a, false, "Pending");
        assert!(a.message.contains("address in use"), "{}", a.message);
        let p = get(&g.conditions, "Programmed");
        check(p, false, "Pending");
        assert!(
            p.message.contains("port 80: address in use"),
            "{}",
            p.message
        );
        let e = &d.edges[0];
        let bp = get(&e.conditions, "Programmed");
        check(bp, false, "BindFailed");
        assert!(bp.message.contains("80") && bp.message.contains("address in use"));
        check(get(&e.conditions, "Connected"), true, "Connected");
        let ports: Vec<u16> = e.listeners.iter().map(|l| l.port).collect();
        assert_eq!(ports, [80, 81]);
        assert!(!e.listeners[0].bound);
        assert_eq!(e.listeners[0].message.as_deref(), Some("address in use"));
        // The listener whose port is bound is programmed and not told about the other's error.
        let b = get(&g.listeners[1].conditions, "Programmed");
        check(b, true, "Programmed");
        assert!(!b.message.contains("address in use"), "{}", b.message);
    }

    #[test]
    fn listener_programmed_needs_its_own_port_bound() {
        let gw = || {
            gateway(
                vec![listener("a", 80, true), listener("b", 81, true)],
                &["e", "f"],
            )
        };
        let m = model(gw(), vec![edge("e", Ok(())), edge("f", Ok(()))]);
        let programmed = |d: &DesiredStatus, i: usize| -> Cond {
            get(&d.gateways[0].listeners[i].conditions, "Programmed").clone()
        };
        // Each port is bound by a different edge: both listeners are programmed, the Gateway
        // is not (no edge has every port).
        let d = compute(
            &m,
            &facts(vec![
                ("e", up(vec![bound(80, Ok(()))])),
                ("f", up(vec![bound(81, Ok(()))])),
            ]),
        );
        check(&programmed(&d, 0), true, "Programmed");
        check(&programmed(&d, 1), true, "Programmed");
        check(
            get(&d.gateways[0].conditions, "Programmed"),
            false,
            "Pending",
        );

        // Port 81 not reported by a connected edge, the other edge down.
        let d = compute(
            &m,
            &facts(vec![
                ("e", up(vec![bound(80, Ok(()))])),
                ("f", down(Some("dial timed out"))),
            ]),
        );
        check(&programmed(&d, 0), true, "Programmed");
        let b = programmed(&d, 1);
        check(&b, false, "Pending");
        assert!(
            b.message.contains("edge ns/e has not reported port 81 yet"),
            "{}",
            b.message
        );
        assert!(
            b.message
                .contains("edge ns/f is not connected: dial timed out"),
            "{}",
            b.message
        );

        // A bind error for the port is what the message gives.
        let d = compute(
            &m,
            &facts(vec![
                (
                    "e",
                    up(vec![bound(80, Ok(())), bound(81, Err("address in use"))]),
                ),
                ("f", down(Some("dial timed out"))),
            ]),
        );
        let b = programmed(&d, 1);
        check(&b, false, "Pending");
        assert_eq!(b.message, "edge ns/e cannot bind port 81: address in use");

        // No edge at all.
        let d = compute(
            &model(gateway(vec![listener("a", 80, true)], &[]), vec![]),
            &facts(vec![]),
        );
        let a = get(&d.gateways[0].listeners[0].conditions, "Programmed");
        check(a, false, "Pending");
        assert!(a.message.contains("no accepted Edge"), "{}", a.message);
    }

    #[test]
    fn listener_without_a_route_is_programmed_once_an_edge_is_connected() {
        let m = model(
            gateway(vec![listener("idle", 90, false)], &["e"]),
            vec![edge("e", Ok(()))],
        );
        let d = compute(&m, &facts(vec![("e", up(vec![]))]));
        check(
            get(&d.gateways[0].listeners[0].conditions, "Programmed"),
            true,
            "Programmed",
        );
        let d = compute(&m, &facts(vec![("e", down(Some("boom")))]));
        let l = get(&d.gateways[0].listeners[0].conditions, "Programmed");
        check(l, false, "Pending");
        assert!(l.message.contains("boom"), "{}", l.message);
    }

    #[test]
    fn edge_is_pending_until_it_reports_and_bind_failed_only_on_a_reported_failure() {
        let m = model(
            gateway(
                vec![listener("a", 80, true), listener("b", 81, true)],
                &["e"],
            ),
            vec![edge("e", Ok(()))],
        );
        let edge_programmed = |st: EdgeState| -> Cond {
            let d = compute(&m, &facts(vec![("e", st)]));
            get(&d.edges[0].conditions, "Programmed").clone()
        };
        let p = edge_programmed(up(vec![bound(80, Ok(()))]));
        check(&p, false, "Pending");
        assert_eq!(p.message, "port 81 not reported yet");
        let p = edge_programmed(up(vec![bound(80, Ok(())), bound(81, Err("in use"))]));
        check(&p, false, "BindFailed");
        assert!(
            p.message.contains("81") && p.message.contains("in use"),
            "{}",
            p.message
        );
        // A reported failure wins over a port not reported yet.
        let p = edge_programmed(up(vec![bound(81, Err("in use"))]));
        check(&p, false, "BindFailed");
        let p = edge_programmed(up(vec![bound(80, Ok(())), bound(81, Ok(()))]));
        check(&p, true, "Programmed");
    }

    #[test]
    fn unreported_port_is_not_reported_yet() {
        let m = model(
            gateway(vec![listener("a", 80, true)], &["e"]),
            vec![edge("e", Ok(()))],
        );
        let d = compute(&m, &facts(vec![("e", up(vec![]))]));
        let bp = get(&d.edges[0].conditions, "Programmed");
        check(bp, false, "Pending");
        assert!(bp.message.contains("not reported yet"), "{}", bp.message);
        let p = get(&d.gateways[0].conditions, "Programmed");
        assert!(
            p.message.contains("port 80 not reported yet"),
            "{}",
            p.message
        );
    }

    #[test]
    fn haproxy_failure_is_invalid_everywhere() {
        let m = model(
            gateway(vec![listener("a", 80, true)], &["e"]),
            vec![edge("e", Ok(()))],
        );
        let mut f = facts(vec![("e", up(vec![bound(80, Ok(()))]))]);
        f.haproxy = Err("config says nope".into());
        let d = compute(&m, &f);
        let g = &d.gateways[0];
        let p = get(&g.conditions, "Programmed");
        check(p, false, "Invalid");
        assert!(p.message.contains("nope"));
        let l = get(&g.listeners[0].conditions, "Programmed");
        check(l, false, "Invalid");
        assert!(l.message.contains("nope"));
    }

    #[test]
    fn https_listener_without_usable_certificates_is_not_programmed() {
        let https = |certificates: Vec<crate::model::Certificate>| {
            let mut l = listener("tls", 443, false);
            l.protocol = "HTTPS".into();
            l.supported_kinds = vec!["HTTPRoute".into()];
            l.attached_routes = 1;
            if certificates.is_empty() {
                l.resolved_refs = Err(Reject::new(
                    "InvalidCertificateRef",
                    "secret ns/site-tls not found",
                ));
            }
            l.certificates = certificates;
            l
        };
        let edge_facts = || facts(vec![("e", up(vec![bound(80, Ok(())), bound(443, Ok(()))]))]);

        let m = model(
            gateway(vec![listener("a", 80, true), https(vec![])], &["e"]),
            vec![edge("e", Ok(()))],
        );
        let d = compute(&m, &edge_facts());
        let g = &d.gateways[0];
        let tls = &g.listeners[1].conditions;
        check(get(tls, "Accepted"), true, "Accepted");
        check(get(tls, "Conflicted"), false, "NoConflicts");
        check(get(tls, "ResolvedRefs"), false, "InvalidCertificateRef");
        let p = get(tls, "Programmed");
        check(p, false, "Invalid");
        assert_eq!(p.message, "secret ns/site-tls not found");
        // The rest of the Gateway is not held back.
        check(
            get(&g.listeners[0].conditions, "Programmed"),
            true,
            "Programmed",
        );
        check(get(&g.conditions, "Programmed"), true, "Programmed");

        // With a certificate, the same listener is programmed.
        let certificate = crate::model::Certificate {
            secret: ObjRef::new("ns", "site-tls"),
            file_name: "ns.site-tls.0000000000000000.pem".into(),
            pem: String::new(),
        };
        let m = model(
            gateway(
                vec![listener("a", 80, true), https(vec![certificate])],
                &["e"],
            ),
            vec![edge("e", Ok(()))],
        );
        let d = compute(&m, &edge_facts());
        let tls = &d.gateways[0].listeners[1].conditions;
        check(get(tls, "ResolvedRefs"), true, "ResolvedRefs");
        check(get(tls, "Programmed"), true, "Programmed");
    }

    #[test]
    fn unaccepted_gateway_reports_its_reason() {
        let mut gw = gateway(vec![listener("a", 80, true)], &[]);
        gw.accepted = Err(Reject {
            reason: "InvalidParameters".into(),
            message: "bad things".into(),
        });
        let d = compute(&model(gw, vec![]), &facts(vec![]));
        let g = &d.gateways[0];
        check(get(&g.conditions, "Accepted"), false, "InvalidParameters");
        assert_eq!(get(&g.conditions, "Accepted").message, "bad things");
        let p = get(&g.conditions, "Programmed");
        check(p, false, "Invalid");
        assert_eq!(p.message, "bad things");
        check(
            get(&g.listeners[0].conditions, "Programmed"),
            false,
            "Invalid",
        );
    }

    #[test]
    fn some_invalid_listeners_keep_the_gateway_accepted() {
        let mut bad = listener("b", 81, false);
        bad.accepted = Err(Reject {
            reason: "PortUnavailable".into(),
            message: "no".into(),
        });
        let mut conflicted = listener("c", 82, false);
        conflicted.conflicted = Some(Reject {
            reason: "ProtocolConflict".into(),
            message: "clash".into(),
        });
        let m = model(
            gateway(vec![listener("a", 80, true), bad, conflicted], &["e"]),
            vec![edge("e", Ok(()))],
        );
        let d = compute(&m, &facts(vec![("e", up(vec![bound(80, Ok(()))]))]));
        let g = &d.gateways[0];
        check(get(&g.conditions, "Accepted"), true, "ListenersNotValid");
        check(get(&g.conditions, "Programmed"), true, "Programmed");
        let b = &g.listeners[1].conditions;
        check(get(b, "Accepted"), false, "PortUnavailable");
        check(get(b, "Programmed"), false, "Invalid");
        let c = &g.listeners[2].conditions;
        check(get(c, "Conflicted"), true, "ProtocolConflict");
        check(get(c, "Programmed"), false, "Invalid");
    }

    #[test]
    fn route_parent_conditions_follow_the_model() {
        let key = |n: &str| ParentKey {
            group: "gateway.networking.k8s.io".into(),
            kind: "Gateway".into(),
            namespace: "ns".into(),
            name: n.into(),
            section_name: None,
            port: None,
        };
        let mut m = model(gateway(vec![], &[]), vec![]);
        m.routes = vec![crate::model::RouteModel {
            kind: crate::model::RouteKind::Tcp,
            key: ObjRef::new("ns", "r"),
            generation: 6,
            parents: vec![
                crate::model::RouteParent {
                    parent: key("z"),
                    accepted: Ok(()),
                    resolved_refs: Err(Reject {
                        reason: "BackendNotFound".into(),
                        message: "no svc".into(),
                    }),
                },
                crate::model::RouteParent {
                    parent: key("a"),
                    accepted: Err(Reject {
                        reason: "NotAllowedByListeners".into(),
                        message: "nope".into(),
                    }),
                    resolved_refs: Ok(()),
                },
            ],
        }];
        let d = compute(&m, &facts(vec![]));
        let r = &d.routes[0];
        assert_eq!(r.kind, crate::model::RouteKind::Tcp);
        assert_eq!(r.generation, 6);
        assert_eq!(r.parents[0].0, key("a"));
        assert_eq!(types(&r.parents[0].1), ["Accepted", "ResolvedRefs"]);
        check(
            get(&r.parents[0].1, "Accepted"),
            false,
            "NotAllowedByListeners",
        );
        check(get(&r.parents[0].1, "ResolvedRefs"), true, "ResolvedRefs");
        check(get(&r.parents[1].1, "Accepted"), true, "Accepted");
        check(
            get(&r.parents[1].1, "ResolvedRefs"),
            false,
            "BackendNotFound",
        );
        assert_eq!(get(&r.parents[1].1, "ResolvedRefs").message, "no svc");
    }

    #[test]
    fn route_status_carries_its_kind() {
        use crate::model::{RouteKind, RouteModel, RouteParent};
        let parent = ParentKey {
            group: "gateway.networking.k8s.io".into(),
            kind: "Gateway".into(),
            namespace: "ns".into(),
            name: "gw".into(),
            section_name: None,
            port: None,
        };
        let route = |kind, name: &str, generation| RouteModel {
            kind,
            key: ObjRef::new("ns", name),
            generation,
            parents: vec![RouteParent {
                parent: parent.clone(),
                accepted: Ok(()),
                resolved_refs: Ok(()),
            }],
        };
        let mut m = model(gateway(vec![], &[]), vec![]);
        // Same key, both kinds; given out of order.
        m.routes = vec![
            route(RouteKind::Http, "web", 2),
            route(RouteKind::Tcp, "web", 1),
            route(RouteKind::Http, "a", 3),
        ];
        let d = compute(&m, &facts(vec![]));
        let got: Vec<(RouteKind, &str, i64)> = d
            .routes
            .iter()
            .map(|r| (r.kind, r.key.name.as_str(), r.generation))
            .collect();
        assert_eq!(
            got,
            [
                (RouteKind::Tcp, "web", 1),
                (RouteKind::Http, "a", 3),
                (RouteKind::Http, "web", 2),
            ]
        );
        assert!(d.routes.iter().all(|r| r.parents.len() == 1));
    }

    #[test]
    fn every_edge_gets_the_operator_id() {
        let m = model(
            gateway(vec![], &["e"]),
            vec![
                edge("e", Ok(())),
                edge(
                    "f",
                    Err(Reject {
                        reason: "InvalidEndpointId".into(),
                        message: "bad id".into(),
                    }),
                ),
            ],
        );
        let d = compute(&m, &facts(vec![]));
        assert_eq!(d.edges.len(), 2);
        for e in &d.edges {
            assert_eq!(e.gateway_endpoint_id, op_id().to_string());
        }
        let f = &d.edges[1];
        check(get(&f.conditions, "Accepted"), false, "InvalidEndpointId");
        let c = get(&f.conditions, "Connected");
        check(c, false, "NotConnected");
        assert_eq!(c.message, "the edge is not accepted");
    }

    #[test]
    fn one_ready_edge_is_enough() {
        let m = model(
            gateway(vec![listener("a", 80, true)], &["e", "f"]),
            vec![edge("e", Ok(())), edge("f", Ok(()))],
        );
        let d = compute(
            &m,
            &facts(vec![
                ("e", down(Some("boom"))),
                ("f", up(vec![bound(80, Ok(()))])),
            ]),
        );
        check(
            get(&d.gateways[0].conditions, "Programmed"),
            true,
            "Programmed",
        );
        check(
            get(&d.gateways[0].listeners[0].conditions, "Programmed"),
            true,
            "Programmed",
        );
    }

    #[test]
    fn non_serving_listener_does_not_block_readiness() {
        let m = model(
            gateway(
                vec![listener("a", 80, true), listener("idle", 90, false)],
                &["e"],
            ),
            vec![edge("e", Ok(()))],
        );
        let d = compute(&m, &facts(vec![("e", up(vec![bound(80, Ok(()))]))]));
        let g = &d.gateways[0];
        check(get(&g.conditions, "Programmed"), true, "Programmed");
        check(
            get(&g.listeners[1].conditions, "Programmed"),
            true,
            "Programmed",
        );
        check(
            get(&d.edges[0].conditions, "Programmed"),
            true,
            "Programmed",
        );
    }

    #[test]
    fn no_serving_ports_a_connected_edge_is_ready() {
        let m = model(gateway(vec![], &["e"]), vec![edge("e", Ok(()))]);
        let d = compute(&m, &facts(vec![("e", up(vec![]))]));
        check(
            get(&d.gateways[0].conditions, "Programmed"),
            true,
            "Programmed",
        );
    }

    #[test]
    fn equal_inputs_give_equal_output_and_sorted_order() {
        let mut m = model(
            gateway(vec![], &[]),
            vec![edge("b", Ok(())), edge("a", Ok(()))],
        );
        m.edges.sort_by(|x, y| x.key.cmp(&y.key));
        let f = facts(vec![]);
        assert_eq!(compute(&m, &f), compute(&m, &f));
        assert_eq!(d_names(&compute(&m, &f)), ["a", "b"]);
    }

    fn reject(reason: &str, message: &str) -> Reject {
        Reject {
            reason: reason.into(),
            message: message.into(),
        }
    }

    fn other_gateway(name: &str, listeners: Vec<ListenerModel>, edges: &[&str]) -> GatewayModel {
        let mut g = gateway(listeners, edges);
        g.key = ObjRef::new("ns", name);
        g
    }

    fn gw_cond<'a>(d: &'a DesiredStatus, name: &str, type_: &str) -> &'a Cond {
        let g = d.gateways.iter().find(|g| g.key.name == name).unwrap();
        get(&g.conditions, type_)
    }

    #[test]
    fn rejected_edge_is_never_connected_or_programmed() {
        let m = model(
            gateway(vec![listener("a", 80, true)], &["e"]),
            vec![
                edge("e", Ok(())),
                edge("f", Err(reject("InvalidEndpointId", "bad id"))),
            ],
        );
        let stale = up(vec![bound(80, Ok(()))]);
        let d = compute(
            &m,
            &facts(vec![("e", up(vec![bound(80, Ok(()))])), ("f", stale)]),
        );
        let f = d.edges.iter().find(|e| e.key.name == "f").unwrap();
        check(get(&f.conditions, "Accepted"), false, "InvalidEndpointId");
        for t in ["Connected", "Programmed"] {
            let c = get(&f.conditions, t);
            check(c, false, "NotConnected");
            assert_eq!(c.message, "the edge is not accepted");
        }
        assert!(f.listeners.is_empty());
    }

    #[test]
    fn gateway_not_accepted_beats_haproxy_error() {
        let mut gw = gateway(vec![listener("a", 80, true)], &[]);
        gw.accepted = Err(reject("InvalidParameters", "gateway rejected"));
        let mut f = facts(vec![]);
        f.haproxy = Err("haproxy nope".into());
        let d = compute(&model(gw, vec![]), &f);
        let p = gw_cond(&d, "gw", "Programmed");
        check(p, false, "Invalid");
        assert_eq!(p.message, "gateway rejected");
        let l = get(&d.gateways[0].listeners[0].conditions, "Programmed");
        check(l, false, "Invalid");
        assert!(l.message.contains("gateway rejected"), "{}", l.message);
        assert!(!l.message.contains("haproxy nope"), "{}", l.message);
    }

    #[test]
    fn haproxy_error_beats_no_edge_and_pending() {
        let mut f = facts(vec![]);
        f.haproxy = Err("haproxy nope".into());
        // No edge at all.
        let m = model(gateway(vec![listener("a", 80, true)], &[]), vec![]);
        let d = compute(&m, &f);
        let p = gw_cond(&d, "gw", "Programmed");
        check(p, false, "Invalid");
        assert!(p.message.contains("haproxy nope"), "{}", p.message);
        let l = get(&d.gateways[0].listeners[0].conditions, "Programmed");
        check(l, false, "Invalid");
        assert!(l.message.contains("haproxy nope"), "{}", l.message);
        // An edge exists but is not ready.
        let m = model(
            gateway(vec![listener("a", 80, true)], &["e"]),
            vec![edge("e", Ok(()))],
        );
        let mut f = facts(vec![("e", down(Some("dial timed out")))]);
        f.haproxy = Err("haproxy nope".into());
        let d = compute(&m, &f);
        let p = gw_cond(&d, "gw", "Programmed");
        check(p, false, "Invalid");
        assert!(p.message.contains("haproxy nope"), "{}", p.message);
        assert!(!p.message.contains("dial timed out"), "{}", p.message);
        let l = get(&d.gateways[0].listeners[0].conditions, "Programmed");
        check(l, false, "Invalid");
        assert!(l.message.contains("haproxy nope"), "{}", l.message);
    }

    #[test]
    fn listener_invalid_rows_and_their_messages() {
        let mut unaccepted = listener("u", 81, false);
        unaccepted.accepted = Err(reject("PortUnavailable", "port taken"));
        let mut conflicted = listener("c", 82, false);
        conflicted.conflicted = Some(reject("ProtocolConflict", "clash on 82"));
        let mut gw = gateway(vec![unaccepted, conflicted], &[]);
        let d = compute(&model(gw.clone(), vec![]), &facts(vec![]));
        let u = get(&d.gateways[0].listeners[1].conditions, "Programmed");
        check(u, false, "Invalid");
        assert!(u.message.contains("port taken"), "{}", u.message);
        let c = get(&d.gateways[0].listeners[0].conditions, "Programmed");
        check(c, false, "Invalid");
        assert!(c.message.contains("clash on 82"), "{}", c.message);
        // The listener's own problem wins over the Gateway being rejected.
        gw.accepted = Err(reject("InvalidParameters", "gateway rejected"));
        let d = compute(&model(gw, vec![]), &facts(vec![]));
        let u = get(&d.gateways[0].listeners[1].conditions, "Programmed");
        assert!(u.message.contains("port taken"), "{}", u.message);
        assert!(!u.message.contains("gateway rejected"), "{}", u.message);
        let c = get(&d.gateways[0].listeners[0].conditions, "Programmed");
        assert!(c.message.contains("clash on 82"), "{}", c.message);
    }

    #[test]
    fn listener_invalid_beats_pending() {
        let mut f = facts(vec![]);
        f.haproxy = Err("haproxy nope".into());
        let m = model(
            gateway(vec![listener("a", 80, true)], &["e"]),
            vec![edge("e", Ok(()))],
        );
        let st = up(vec![bound(80, Err("address in use"))]);
        f.edges.insert(ObjRef::new("ns", "e"), st);
        let d = compute(&m, &f);
        let l = get(&d.gateways[0].listeners[0].conditions, "Programmed");
        check(l, false, "Invalid");
        assert!(l.message.contains("haproxy nope"), "{}", l.message);
    }

    #[test]
    fn connected_edge_of_another_gateway_does_not_count() {
        let m = Model {
            gateways: vec![
                other_gateway("gw", vec![listener("a", 80, true)], &[]),
                other_gateway("gw2", vec![listener("a", 80, true)], &["x"]),
            ],
            edges: vec![{
                let mut x = edge("x", Ok(()));
                x.gateway = Some(ObjRef::new("ns", "gw2"));
                x
            }],
            ..model(gateway(vec![], &[]), vec![])
        };
        let d = compute(&m, &facts(vec![("x", up(vec![bound(80, Ok(()))]))]));
        let p = gw_cond(&d, "gw", "Programmed");
        check(p, false, "AddressNotAssigned");
        check(gw_cond(&d, "gw2", "Programmed"), true, "Programmed");
    }

    #[test]
    fn stale_state_of_unaccepted_or_absent_edge_does_not_count() {
        let m = model(
            gateway(vec![listener("a", 80, true)], &[]),
            vec![edge("f", Err(reject("InvalidEndpointId", "bad id")))],
        );
        let stale = || up(vec![bound(80, Ok(()))]);
        let d = compute(&m, &facts(vec![("f", stale()), ("ghost", stale())]));
        let p = gw_cond(&d, "gw", "Programmed");
        check(p, false, "AddressNotAssigned");
        let l = get(&d.gateways[0].listeners[0].conditions, "Programmed");
        assert!(!l.status, "{l:?}");
    }

    #[test]
    fn only_the_other_gateways_edge_is_ready() {
        let m = Model {
            gateways: vec![
                other_gateway("gw", vec![listener("a", 80, true)], &["e", "e2"]),
                other_gateway("gw2", vec![listener("a", 80, true)], &["x"]),
            ],
            edges: vec![edge("e", Ok(())), edge("e2", Ok(())), {
                let mut x = edge("x", Ok(()));
                x.gateway = Some(ObjRef::new("ns", "gw2"));
                x
            }],
            ..model(gateway(vec![], &[]), vec![])
        };
        let d = compute(
            &m,
            &facts(vec![
                ("e", down(Some("boom"))),
                ("e2", up(vec![bound(80, Err("address in use"))])),
                ("x", up(vec![bound(80, Ok(()))])),
            ]),
        );
        let p = gw_cond(&d, "gw", "Programmed");
        check(p, false, "Pending");
        assert!(p.message.contains("ns/e") && p.message.contains("ns/e2"));
        assert!(!p.message.contains("ns/x"), "{}", p.message);
        check(gw_cond(&d, "gw2", "Programmed"), true, "Programmed");
    }

    fn d_names(d: &DesiredStatus) -> Vec<String> {
        d.edges.iter().map(|e| e.key.name.clone()).collect()
    }
}
