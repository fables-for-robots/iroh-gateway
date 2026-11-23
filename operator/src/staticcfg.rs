//! The static configuration file of `iroh-gateway-operator static`.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, bail};
use iroh::EndpointId;
use iroh_gateway_proto::control::Protocol;
use iroh_gateway_proto::transport::Relay;
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticConfig {
    pub key_file: PathBuf,
    pub relay: Relay,
    pub edges: Vec<StaticEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticEdge {
    pub endpoint_id: EndpointId,
    pub address: Option<String>,
    pub listeners: Vec<StaticListener>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticListener {
    pub protocol: Protocol,
    pub port: u16,
    pub target: SocketAddr,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    key_file: PathBuf,
    relay: Option<String>,
    #[serde(default)]
    edge: Vec<RawEdge>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEdge {
    endpoint_id: EndpointId,
    address: Option<String>,
    #[serde(default)]
    listener: Vec<RawListener>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListener {
    protocol: Protocol,
    port: u16,
    target: SocketAddr,
}

/// Parses and validates the configuration text.
pub fn parse(text: &str) -> anyhow::Result<StaticConfig> {
    let raw: RawConfig = toml::from_str(text).context("invalid configuration")?;
    let relay: Relay = match raw.relay {
        Some(r) => r.parse()?,
        None => Relay::Disabled,
    };
    let mut seen_edges = HashSet::new();
    let mut edges = Vec::new();
    for e in raw.edge {
        let id = e.endpoint_id;
        if !seen_edges.insert(id) {
            bail!("edge {id} is configured twice");
        }
        if e.address.is_none() && relay == Relay::Disabled {
            bail!("edge {id} has no address, which is required while relay is \"disabled\"");
        }
        if e.listener.is_empty() {
            bail!("edge {id} has no listeners");
        }
        let mut seen = HashSet::new();
        let mut listeners = Vec::new();
        for l in e.listener {
            if !seen.insert((l.protocol, l.port)) {
                bail!(
                    "edge {id} has two {:?} listeners on port {}",
                    l.protocol,
                    l.port
                );
            }
            listeners.push(StaticListener {
                protocol: l.protocol,
                port: l.port,
                target: l.target,
            });
        }
        edges.push(StaticEdge {
            endpoint_id: id,
            address: e.address,
            listeners,
        });
    }
    Ok(StaticConfig {
        key_file: raw.key_file,
        relay,
        edges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn id() -> String {
        SecretKey::generate().public().to_string()
    }

    fn example(relay_line: &str, id: &str) -> String {
        format!(
            r#"
key_file = "operator.key"
{relay_line}

[[edge]]
endpoint_id = "{id}"
address = "203.0.113.7:7842"

[[edge.listener]]
protocol = "tcp"
port = 8080
target = "127.0.0.1:3000"
"#
        )
    }

    #[test]
    fn parses_the_documented_example() {
        let id = id();
        let cfg = parse(&example(r#"relay = "disabled""#, &id)).unwrap();
        assert_eq!(cfg.key_file, PathBuf::from("operator.key"));
        assert_eq!(cfg.relay, Relay::Disabled);
        assert_eq!(cfg.edges.len(), 1);
        let edge = &cfg.edges[0];
        assert_eq!(edge.endpoint_id.to_string(), id);
        assert_eq!(edge.address.as_deref(), Some("203.0.113.7:7842"));
        assert_eq!(edge.listeners.len(), 1);
        assert_eq!(edge.listeners[0].protocol, Protocol::Tcp);
        assert_eq!(edge.listeners[0].port, 8080);
        assert_eq!(edge.listeners[0].target, "127.0.0.1:3000".parse().unwrap());
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = parse(&example(r#"colour = "red""#, &id())).unwrap_err();
        assert!(format!("{err:#}").contains("colour"), "{err:#}");
        let nested = example("", &id()).replace("port = 8080", "port = 8080\nflavour = 1");
        let err = parse(&nested).unwrap_err();
        assert!(format!("{err:#}").contains("flavour"), "{err:#}");
    }

    #[test]
    fn rejects_duplicate_listener() {
        let text = example("", &id())
            + r#"
[[edge.listener]]
protocol = "tcp"
port = 8080
target = "127.0.0.1:3001"
"#;
        let err = parse(&text).unwrap_err();
        assert!(format!("{err:#}").contains("8080"), "{err:#}");
    }

    #[test]
    fn same_port_on_different_protocols_is_allowed() {
        let text = example("", &id())
            + r#"
[[edge.listener]]
protocol = "udp"
port = 8080
target = "127.0.0.1:3001"
"#;
        assert_eq!(parse(&text).unwrap().edges[0].listeners.len(), 2);
    }

    #[test]
    fn rejects_duplicate_edge() {
        let id = id();
        let text = example("", &id)
            + &example("", &id)
                .split_once("[[edge]]")
                .map(|(_, rest)| format!("[[edge]]{rest}"))
                .unwrap();
        let err = parse(&text).unwrap_err();
        assert!(format!("{err:#}").contains(&id), "{err:#}");
    }

    #[test]
    fn rejects_edge_without_listeners() {
        let text = format!(
            "key_file = \"k\"\n[[edge]]\nendpoint_id = \"{}\"\naddress = \"203.0.113.7:7842\"\n",
            id()
        );
        let err = parse(&text).unwrap_err();
        assert!(format!("{err:#}").contains("no listeners"), "{err:#}");
    }

    #[test]
    fn relay_defaults_to_disabled() {
        let cfg = parse(&example("", &id())).unwrap();
        assert_eq!(cfg.relay, Relay::Disabled);
    }

    #[test]
    fn address_is_optional_only_with_relay() {
        let no_address = |relay: &str| {
            let text = example(&format!("relay = \"{relay}\""), &id())
                .replace("address = \"203.0.113.7:7842\"\n", "");
            parse(&text)
        };
        let err = no_address("disabled").unwrap_err();
        assert!(format!("{err:#}").contains("address"), "{err:#}");
        let cfg = no_address("n0").unwrap();
        assert_eq!(cfg.edges[0].address, None);
        assert!(no_address("nonsense").is_err());
    }
}
