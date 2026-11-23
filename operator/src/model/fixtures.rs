//! Builders for real Gateway API and `Edge` objects, so tests read like the cases they cover.

use std::collections::BTreeMap;

use gateway_api::gatewayclasses::v1::{GatewayClass, GatewayClassSpec};
use gateway_api::gateways::v1::{
    Gateway, GatewayAddresses, GatewayListeners, GatewayListenersAllowedRoutes,
    GatewayListenersAllowedRoutesKinds, GatewayListenersAllowedRoutesNamespaces,
    GatewayListenersAllowedRoutesNamespacesFrom, GatewayListenersAllowedRoutesNamespacesSelector,
    GatewaySpec,
};
use iroh_gateway_proto::transport::Relay;
use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};

use super::Settings;
use crate::crd::{Edge, EdgeGatewayRef, EdgeSpec};

pub const CONTROLLER: &str = "gateway.fables-for-robots.ch/controller";

pub fn class(name: &str) -> GatewayClass {
    class_of(name, CONTROLLER)
}

pub fn foreign_class(name: &str) -> GatewayClass {
    class_of(name, "example.com/other-controller")
}

fn class_of(name: &str, controller: &str) -> GatewayClass {
    GatewayClass::new(
        name,
        GatewayClassSpec {
            controller_name: controller.into(),
            ..Default::default()
        },
    )
}

/// A gateway of class `ours`, with no listeners.
pub fn gateway(ns: &str, name: &str) -> Gateway {
    let mut gw = Gateway::new(
        name,
        GatewaySpec {
            gateway_class_name: "ours".into(),
            ..Default::default()
        },
    );
    gw.metadata.namespace = Some(ns.into());
    gw
}

pub trait GatewayExt: Sized {
    fn class(self, name: &str) -> Self;
    fn listener(self, name: &str, port: i32, protocol: &str) -> Self;
    /// Applies to the last listener.
    fn allowed_kinds(self, kinds: &[(&str, &str)]) -> Self;
    fn allow_all_namespaces(self) -> Self;
    fn allow_selector(self, labels: &[(&str, &str)]) -> Self;
    fn requested_address(self, value: &str) -> Self;
}

fn last(gw: &mut Gateway) -> &mut GatewayListeners {
    gw.spec.listeners.last_mut().expect("add a listener first")
}

fn namespaces(l: &mut GatewayListeners) -> &mut GatewayListenersAllowedRoutesNamespaces {
    l.allowed_routes
        .get_or_insert_with(GatewayListenersAllowedRoutes::default)
        .namespaces
        .get_or_insert_with(GatewayListenersAllowedRoutesNamespaces::default)
}

impl GatewayExt for Gateway {
    fn class(mut self, name: &str) -> Self {
        self.spec.gateway_class_name = name.into();
        self
    }

    fn listener(mut self, name: &str, port: i32, protocol: &str) -> Self {
        self.spec.listeners.push(GatewayListeners {
            name: name.into(),
            port,
            protocol: protocol.into(),
            ..Default::default()
        });
        self
    }

    fn allowed_kinds(mut self, kinds: &[(&str, &str)]) -> Self {
        last(&mut self)
            .allowed_routes
            .get_or_insert_with(GatewayListenersAllowedRoutes::default)
            .kinds = Some(
            kinds
                .iter()
                .map(|(g, k)| GatewayListenersAllowedRoutesKinds {
                    group: Some((*g).into()),
                    kind: (*k).into(),
                })
                .collect(),
        );
        self
    }

    fn allow_all_namespaces(mut self) -> Self {
        namespaces(last(&mut self)).from = Some(GatewayListenersAllowedRoutesNamespacesFrom::All);
        self
    }

    fn allow_selector(mut self, labels: &[(&str, &str)]) -> Self {
        let ns = namespaces(last(&mut self));
        ns.from = Some(GatewayListenersAllowedRoutesNamespacesFrom::Selector);
        ns.selector = Some(GatewayListenersAllowedRoutesNamespacesSelector {
            match_labels: Some(
                labels
                    .iter()
                    .map(|(k, v)| ((*k).into(), (*v).into()))
                    .collect(),
            ),
            ..Default::default()
        });
        self
    }

    fn requested_address(mut self, value: &str) -> Self {
        self.spec
            .addresses
            .get_or_insert_with(Vec::new)
            .push(GatewayAddresses {
                value: Some(value.into()),
                ..Default::default()
            });
        self
    }
}

/// An edge whose endpoint id is derived from `key_seed`, with an address, bound to gateway
/// `public`.
pub fn edge(ns: &str, name: &str, key_seed: u8) -> Edge {
    let id = iroh::SecretKey::from_bytes(&[key_seed; 32]).public();
    let mut e = Edge::new(
        name,
        EdgeSpec {
            endpoint_id: id.to_string(),
            address: Some("203.0.113.7:7842".into()),
            gateway_ref: EdgeGatewayRef {
                name: "public".into(),
            },
            public_addresses: Vec::new(),
        },
    );
    e.metadata.namespace = Some(ns.into());
    e
}

pub trait EdgeExt: Sized {
    fn address(self, address: &str) -> Self;
    fn no_address(self) -> Self;
    fn gateway(self, name: &str) -> Self;
    fn public(self, address: &str) -> Self;
    /// Creation time, in seconds after the epoch.
    fn created(self, seconds: i64) -> Self;
}

impl EdgeExt for Edge {
    fn address(mut self, address: &str) -> Self {
        self.spec.address = Some(address.into());
        self
    }

    fn no_address(mut self) -> Self {
        self.spec.address = None;
        self
    }

    fn gateway(mut self, name: &str) -> Self {
        self.spec.gateway_ref.name = name.into();
        self
    }

    fn public(mut self, address: &str) -> Self {
        self.spec.public_addresses.push(address.into());
        self
    }

    fn created(mut self, seconds: i64) -> Self {
        self.metadata.creation_timestamp = Some(Time(
            k8s_openapi::jiff::Timestamp::from_second(seconds).expect("in range"),
        ));
        self
    }
}

/// Our controller, no relay, serving the given namespaces.
pub fn settings(namespaces: &[&str]) -> Settings {
    Settings {
        controller_name: CONTROLLER.into(),
        gateway_namespaces: namespaces.iter().map(|n| (*n).to_owned()).collect(),
        relay: Relay::Disabled,
    }
}

pub fn ns(name: &str, labels: &[(&str, &str)]) -> Namespace {
    let labels: BTreeMap<String, String> = labels
        .iter()
        .map(|(k, v)| ((*k).into(), (*v).into()))
        .collect();
    Namespace {
        metadata: ObjectMeta {
            name: Some(name.into()),
            labels: Some(labels),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_rules_land_on_the_last_listener() {
        let gw = gateway("infra", "gw")
            .listener("a", 1, "TCP")
            .listener("b", 2, "TCP")
            .allow_all_namespaces()
            .listener("c", 3, "TCP")
            .allow_selector(&[("team", "db")]);
        let from = |i: usize| {
            gw.spec.listeners[i]
                .allowed_routes
                .as_ref()
                .and_then(|a| a.namespaces.as_ref())
        };
        assert!(from(0).is_none());
        assert_eq!(
            from(1).unwrap().from,
            Some(GatewayListenersAllowedRoutesNamespacesFrom::All)
        );
        let sel = from(2).unwrap();
        assert_eq!(
            sel.from,
            Some(GatewayListenersAllowedRoutesNamespacesFrom::Selector)
        );
        assert_eq!(
            sel.selector
                .as_ref()
                .unwrap()
                .match_labels
                .as_ref()
                .unwrap()["team"],
            "db"
        );
    }

    #[test]
    fn namespace_carries_labels() {
        let n = ns("apps", &[("team", "db")]);
        assert_eq!(n.metadata.name.as_deref(), Some("apps"));
        assert_eq!(n.metadata.labels.unwrap()["team"], "db");
    }
}
