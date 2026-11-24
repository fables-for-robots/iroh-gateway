//! QUIC transport settings and endpoint construction shared by edge and operator.

use std::{fmt, str::FromStr, time::Duration};

use anyhow::{Context, bail};
use iroh::{
    RelayMode, RelayUrl, SecretKey,
    address_lookup::{DnsAddressLookup, PkarrPublisher, PkarrResolver},
    endpoint::{Builder, PortmapperConfig, QuicTransportConfig, VarInt, presets},
};

pub const KEEP_ALIVE: Duration = Duration::from_secs(5);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(20);
/// iroh's maximum per-path idle timeout; larger values are clamped with a warning.
pub const PATH_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
/// How many visitor streams one edge may have open towards the operator. With up to three
/// 64 KiB copy buffers per stream and [`OPERATOR_RECEIVE_WINDOW`], one edge can make the operator
/// hold about 4096 × 192 KiB + 64 MiB ≈ 830 MiB in the worst case.
pub const MAX_TUNNEL_STREAMS: u32 = 4_096;
/// How much the peer may send on one stream before we read it, on both roles. Worst-case
/// receive memory is about this times the number of open streams.
pub const STREAM_RECEIVE_WINDOW: u32 = 256 * 1024;
/// How much one edge may send across all streams before the operator reads it.
pub const OPERATOR_RECEIVE_WINDOW: u32 = 64 * 1024 * 1024;
/// Datagrams queued for sending, per connection. When it is full the oldest are dropped, which
/// is what UDP does under load.
pub const DATAGRAM_SEND_BUFFER: usize = 256 * 1024;
/// Datagrams received and not yet read, per connection; the oldest are dropped beyond it.
pub const DATAGRAM_RECEIVE_BUFFER: usize = 1024 * 1024;

/// `incoming_bidi_streams` is how many streams the peer may have open towards us.
///
/// Only `Role::Operator` caps the connection-level receive window: it bounds what one
/// (possibly compromised) edge can make the operator buffer, and a full window stalls only that
/// edge's own link. `Role::Edge` deliberately keeps noq's unbounded connection window: there
/// every stream is a visitor, and a connection-level cap would let a few hundred slow-reading
/// visitors stall every other visitor. The edge's bound is the per-stream window times its
/// connection cap instead.
pub fn transport_config(incoming_bidi_streams: u32, role: Role) -> QuicTransportConfig {
    let builder = QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(VarInt::from_u32(incoming_bidi_streams))
        .stream_receive_window(VarInt::from_u32(STREAM_RECEIVE_WINDOW));
    let builder = match role {
        Role::Edge => builder,
        Role::Operator => builder.receive_window(VarInt::from_u32(OPERATOR_RECEIVE_WINDOW)),
    };
    builder
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .datagram_send_buffer_size(DATAGRAM_SEND_BUFFER)
        .datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER))
        .keep_alive_interval(KEEP_ALIVE)
        .max_idle_timeout(Some(
            IDLE_TIMEOUT
                .try_into()
                .expect("idle timeout fits a QUIC varint"),
        ))
        .default_path_keep_alive_interval(KEEP_ALIVE)
        .default_path_max_idle_timeout(PATH_IDLE_TIMEOUT)
        .build()
}

/// Parses from and displays as "disabled", "n0", or an https relay URL.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Relay {
    #[default]
    Disabled,
    N0,
    Custom(RelayUrl),
}

impl FromStr for Relay {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s {
            "disabled" => Ok(Relay::Disabled),
            "n0" => Ok(Relay::N0),
            _ => {
                let url: RelayUrl = s.parse().with_context(|| {
                    format!("relay must be \"disabled\", \"n0\" or an https URL, got {s:?}")
                })?;
                if url.scheme() != "https" {
                    bail!("relay URL must use https, got {s:?}");
                }
                Ok(Relay::Custom(url))
            }
        }
    }
}

impl fmt::Display for Relay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Relay::Disabled => f.write_str("disabled"),
            Relay::N0 => f.write_str("n0"),
            Relay::Custom(url) => write!(f, "{url}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Edge,
    Operator,
}

/// Builder with `presets::Minimal`, the key, the transport config, and relay settings.
///
/// `Disabled` and `Custom` use no address lookup. `N0` makes the edge publish its relay URL
/// (only) via pkarr and the operator resolve only; the operator never publishes.
///
/// Port mapping (UPnP, NAT-PMP, PCP) is disabled: neither side may ask its LAN gateway to open
/// an inbound port, since the operator's network must need none and the edge has a public IP.
pub fn endpoint_builder(
    key: SecretKey,
    incoming_bidi_streams: u32,
    relay: &Relay,
    role: Role,
) -> Builder {
    let builder = Builder::new(presets::Minimal)
        .secret_key(key)
        .transport_config(transport_config(incoming_bidi_streams, role))
        .portmapper_config(PortmapperConfig::Disabled)
        .clear_address_lookup();
    match (relay, role) {
        (Relay::Disabled, _) => builder.relay_mode(RelayMode::Disabled),
        (Relay::Custom(url), _) => builder.relay_mode(RelayMode::Custom(url.clone().into())),
        (Relay::N0, Role::Edge) => builder
            .relay_mode(RelayMode::Default)
            .address_lookup(PkarrPublisher::n0_dns()),
        (Relay::N0, Role::Operator) => builder
            .relay_mode(RelayMode::Default)
            .address_lookup(PkarrResolver::n0_dns())
            .address_lookup(DnsAddressLookup::n0_dns()),
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use iroh::{EndpointAddr, tls::CaTlsConfig};

    use super::*;
    use crate::ALPN;

    #[tokio::test]
    async fn two_endpoints_connect_directly_by_key() {
        let a = endpoint_builder(SecretKey::generate(), 4, &Relay::Disabled, Role::Edge)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let b = endpoint_builder(SecretKey::generate(), 4, &Relay::Disabled, Role::Operator)
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let addr = EndpointAddr::new(a.id()).with_ip_addr(a.bound_sockets()[0]);
        let accept = async { a.accept().await.unwrap().await.unwrap() };
        let (conn_b, conn_a) = tokio::join!(b.connect(addr, ALPN), accept);
        assert_eq!(conn_b.unwrap().remote_id(), a.id());
        assert_eq!(conn_a.remote_id(), b.id());
    }

    #[tokio::test]
    async fn datagrams_pass_between_two_endpoints() {
        let a = endpoint_builder(SecretKey::generate(), 4, &Relay::Disabled, Role::Edge)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let b = endpoint_builder(SecretKey::generate(), 4, &Relay::Disabled, Role::Operator)
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let addr = EndpointAddr::new(a.id()).with_ip_addr(a.bound_sockets()[0]);
        let accept = async { a.accept().await.unwrap().await.unwrap() };
        let (conn_b, conn_a) = tokio::join!(b.connect(addr, ALPN), accept);
        let conn_b = conn_b.unwrap();
        for (from, to) in [(&conn_a, &conn_b), (&conn_b, &conn_a)] {
            let size = from.max_datagram_size();
            assert!(
                size.is_some_and(|n| n >= 1100 + crate::datagram::HEADER_LEN),
                "{size:?}"
            );
            let got = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    from.send_datagram(Bytes::from_static(b"ping")).unwrap();
                    if let Ok(got) =
                        tokio::time::timeout(Duration::from_millis(200), to.read_datagram()).await
                    {
                        break got.unwrap();
                    }
                }
            })
            .await
            .expect("datagram arrives");
            assert_eq!(got.as_ref(), b"ping");
        }
    }

    #[test]
    fn relay_parses_and_displays() {
        assert_eq!("disabled".parse::<Relay>().unwrap(), Relay::Disabled);
        assert_eq!("n0".parse::<Relay>().unwrap(), Relay::N0);
        let r: Relay = "https://relay.example.com".parse().unwrap();
        assert!(matches!(r, Relay::Custom(_)));
        assert_eq!(
            r.to_string().trim_end_matches('/'),
            "https://relay.example.com"
        );
        assert_eq!(Relay::default(), Relay::Disabled);
        for bad in ["", "N0 ", "relay.example.com", "ftp://x"] {
            assert!(bad.parse::<Relay>().is_err(), "{bad:?}");
        }
    }

    /// Writes to `send` until a write makes no progress for 500 ms; returns the bytes accepted.
    async fn accepted_while_unread(send: &mut iroh::endpoint::SendStream) -> usize {
        let chunk = vec![7u8; 16 << 10];
        let mut total = 0;
        loop {
            match tokio::time::timeout(Duration::from_millis(500), send.write(&chunk)).await {
                Ok(Ok(n)) => total += n,
                Ok(Err(e)) => panic!("write failed after {total} bytes: {e}"),
                Err(_) => return total,
            }
        }
    }

    #[tokio::test]
    async fn unread_stream_holds_about_one_stream_window() {
        let edge = endpoint_builder(SecretKey::generate(), 4, &Relay::Disabled, Role::Edge)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let operator = endpoint_builder(SecretKey::generate(), 4, &Relay::Disabled, Role::Operator)
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let addr = EndpointAddr::new(edge.id()).with_ip_addr(edge.bound_sockets()[0]);
        let accept = async { edge.accept().await.unwrap().await.unwrap() };
        let (to_edge, to_operator) = tokio::join!(operator.connect(addr, ALPN), accept);
        let to_edge = to_edge.unwrap();

        // Each receiver accepts the stream and then never reads from it.
        let range = 128 << 10..=1 << 20;
        for (opener, acceptor) in [(&to_edge, &to_operator), (&to_operator, &to_edge)] {
            let (mut send, _recv) = opener.open_bi().await.unwrap();
            send.write_all(b"x").await.unwrap();
            let (_far_send, _far_recv) = acceptor.accept_bi().await.unwrap();
            let accepted = accepted_while_unread(&mut send).await;
            assert!(range.contains(&accepted), "{accepted} bytes accepted");
        }
    }

    /// The built config has no getters; its `Debug` output is the only way to read it back.
    #[test]
    fn transport_config_values() {
        let edge = format!("{:?}", transport_config(4, Role::Edge));
        let operator = format!("{:?}", transport_config(MAX_TUNNEL_STREAMS, Role::Operator));
        for (cfg, streams) in [(&edge, 4), (&operator, MAX_TUNNEL_STREAMS)] {
            for field in [
                format!("max_concurrent_bidi_streams: {streams},"),
                "max_concurrent_uni_streams: 0,".to_string(),
                "max_idle_timeout: Some(20000),".to_string(),
                format!("datagram_receive_buffer_size: Some({DATAGRAM_RECEIVE_BUFFER}),"),
                format!("datagram_send_buffer_size: {DATAGRAM_SEND_BUFFER},"),
                format!("stream_receive_window: {STREAM_RECEIVE_WINDOW},"),
                "keep_alive_interval: Some(5s),".to_string(),
                "default_path_max_idle_timeout: Some(15s),".to_string(),
                "default_path_keep_alive_interval: Some(5s),".to_string(),
            ] {
                assert!(cfg.contains(&field), "{field} missing in {cfg}");
            }
        }
        let unbounded = format!("receive_window: {},", VarInt::MAX);
        assert!(edge.contains(&unbounded), "{edge}");
        let bounded = format!("receive_window: {OPERATOR_RECEIVE_WINDOW},");
        assert!(operator.contains(&bounded), "{operator}");
    }

    #[tokio::test]
    async fn connects_through_a_relay_with_no_direct_address() {
        let (_map, relay_url, _server) = iroh::test_utils::run_relay_server().await.unwrap();
        let relay = Relay::Custom(relay_url.clone());
        let a = endpoint_builder(SecretKey::generate(), 4, &relay, Role::Edge)
            .alpns(vec![ALPN.to_vec()])
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let b = endpoint_builder(SecretKey::generate(), 4, &relay, Role::Operator)
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        a.online().await;

        let addr = EndpointAddr::new(a.id()).with_relay_url(relay_url);
        let serve = async {
            let conn = a.accept().await.unwrap().await.unwrap();
            let (mut tx, mut rx) = conn.accept_bi().await.unwrap();
            assert_eq!(rx.read_to_end(16).await.unwrap(), b"x");
            tx.write_all(b"x").await.unwrap();
            tx.finish().unwrap();
            conn.closed().await;
            conn.remote_id()
        };
        let dial = async {
            let conn = b.connect(addr, ALPN).await.unwrap();
            assert_eq!(conn.remote_id(), a.id());
            let (mut tx, mut rx) = conn.open_bi().await.unwrap();
            tx.write_all(b"x").await.unwrap();
            tx.finish().unwrap();
            assert_eq!(rx.read_to_end(16).await.unwrap(), b"x");
            conn.close(0u32.into(), b"done");
        };
        let (remote, ()) = tokio::join!(serve, dial);
        assert_eq!(remote, b.id());
    }
}
