//! The static configuration file of `iroh-gateway-operator static`.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

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

/// Parses and validates the configuration text. A relative `key_file` is taken relative to
/// `base_dir`, the directory of the configuration file.
pub fn parse(text: &str, base_dir: &Path) -> anyhow::Result<StaticConfig> {
    let raw: RawConfig = toml::from_str(text).context("invalid configuration")?;
    if raw.edge.is_empty() {
        bail!("no [[edge]] is configured");
    }
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
        if let Some(address) = &e.address {
            check_address(address).with_context(|| format!("edge {id}"))?;
        }
        if e.listener.is_empty() {
            bail!("edge {id} has no listeners");
        }
        let mut seen = HashSet::new();
        let mut listeners = Vec::new();
        for l in e.listener {
            if l.port == 0 {
                bail!("edge {id} has a {:?} listener on port 0", l.protocol);
            }
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
        key_file: base_dir.join(raw.key_file),
        relay,
        edges,
    })
}

/// `address` is `host:port`: an IP address (IPv6 in brackets) or a DNS name, and a port in
/// 1..=65535.
pub(crate) fn check_address(address: &str) -> anyhow::Result<()> {
    let bad = || format!("address {address:?} is not host:port");
    if let Ok(addr) = address.parse::<SocketAddr>() {
        if addr.port() == 0 {
            bail!("address {address:?} has port 0");
        }
        return Ok(());
    }
    let (host, port) = address.rsplit_once(':').with_context(bad)?;
    port.parse::<u16>()
        .ok()
        .filter(|&p| p != 0)
        .with_context(|| format!("address {address:?} needs a port from 1 to 65535"))?;
    if !is_dns_name(host) {
        bail!(
            "address {address:?}: {host:?} is neither an IP address (IPv6 in brackets) nor a \
             host name"
        );
    }
    Ok(())
}

/// Letters, digits and inner hyphens in dot-separated labels, with an optional final dot; the
/// last label not all digits, so a malformed IPv4 address is not taken for a name.
fn is_dns_name(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    host.len() <= 253
        && host.split('.').all(label_ok)
        && host
            .rsplit('.')
            .next()
            .is_some_and(|last| !last.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    /// `parse` with the config file in `/etc/iroh-gateway`.
    fn parse_in(text: &str) -> anyhow::Result<StaticConfig> {
        parse(text, Path::new("/etc/iroh-gateway"))
    }

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
        let cfg = parse_in(&example(r#"relay = "disabled""#, &id)).unwrap();
        assert_eq!(
            cfg.key_file,
            PathBuf::from("/etc/iroh-gateway/operator.key")
        );
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
        let err = parse_in(&example(r#"colour = "red""#, &id())).unwrap_err();
        assert!(format!("{err:#}").contains("colour"), "{err:#}");
        let nested = example("", &id()).replace("port = 8080", "port = 8080\nflavour = 1");
        let err = parse_in(&nested).unwrap_err();
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
        let err = parse_in(&text).unwrap_err();
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
        assert_eq!(parse_in(&text).unwrap().edges[0].listeners.len(), 2);
    }

    #[test]
    fn rejects_duplicate_edge() {
        let id = id();
        let text = example("", &id)
            + &example("", &id)
                .split_once("[[edge]]")
                .map(|(_, rest)| format!("[[edge]]{rest}"))
                .unwrap();
        let err = parse_in(&text).unwrap_err();
        assert!(format!("{err:#}").contains(&id), "{err:#}");
    }

    #[test]
    fn rejects_edge_without_listeners() {
        let text = format!(
            "key_file = \"k\"\n[[edge]]\nendpoint_id = \"{}\"\naddress = \"203.0.113.7:7842\"\n",
            id()
        );
        let err = parse_in(&text).unwrap_err();
        assert!(format!("{err:#}").contains("no listeners"), "{err:#}");
    }

    #[test]
    fn key_file_is_relative_to_the_config_directory() {
        let text = example("", &id());
        let cfg = parse(&text, Path::new("conf")).unwrap();
        assert_eq!(cfg.key_file, Path::new("conf").join("operator.key"));
        let cfg = parse(&text, Path::new("")).unwrap();
        assert_eq!(cfg.key_file, PathBuf::from("operator.key"));
        let absolute = text.replace("\"operator.key\"", "\"/var/lib/o.key\"");
        assert_eq!(
            parse_in(&absolute).unwrap().key_file,
            PathBuf::from("/var/lib/o.key")
        );
    }

    #[test]
    fn rejects_a_file_without_edges() {
        let err = parse_in("key_file = \"k\"\n").unwrap_err();
        assert!(format!("{err:#}").contains("[[edge]]"), "{err:#}");
    }

    #[test]
    fn rejects_listener_port_zero() {
        let text = example("", &id()).replace("port = 8080", "port = 0");
        let err = parse_in(&text).unwrap_err();
        assert!(format!("{err:#}").contains("port 0"), "{err:#}");
    }

    #[test]
    fn address_must_be_host_and_port() {
        let with_address =
            |address: &str| parse_in(&example("", &id()).replace("203.0.113.7:7842", address));
        for good in [
            "203.0.113.7:7842",
            "[2001:db8::1]:7842",
            "edge.example.com:7842",
            "edge-1.example.com.:65535",
            "localhost:1",
        ] {
            assert!(
                with_address(good).is_ok(),
                "{good}: {:#}",
                with_address(good).unwrap_err()
            );
        }
        for bad in [
            "203.0.113.7",
            "203.0.113.7:0",
            "203.0.113.7:65536",
            "edge.example.com",
            "edge.example.com:",
            "edge.example.com:port",
            ":7842",
            "2001:db8::1:7842",
            "[2001:db8::1]",
            "[edge.example.com]:7842",
            "edge example.com:7842",
            "-edge.example.com:7842",
            "999.1.1.1:7842",
            "https://edge.example.com:7842",
        ] {
            let err = with_address(bad).unwrap_err();
            assert!(format!("{err:#}").contains("address"), "{bad}: {err:#}");
        }
    }

    #[test]
    fn relay_defaults_to_disabled() {
        let cfg = parse_in(&example("", &id())).unwrap();
        assert_eq!(cfg.relay, Relay::Disabled);
    }

    #[test]
    fn address_is_optional_only_with_relay() {
        let no_address = |relay: &str| {
            let text = example(&format!("relay = \"{relay}\""), &id())
                .replace("address = \"203.0.113.7:7842\"\n", "");
            parse_in(&text)
        };
        let err = no_address("disabled").unwrap_err();
        assert!(format!("{err:#}").contains("address"), "{err:#}");
        let cfg = no_address("n0").unwrap();
        assert_eq!(cfg.edges[0].address, None);
        assert!(no_address("nonsense").is_err());
    }
}
