//! Control-stream messages.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ListenerKey {
    pub protocol: Protocol,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listener {
    pub id: u32,
    pub protocol: Protocol,
    pub port: u16,
}

impl Listener {
    pub fn key(&self) -> ListenerKey {
        ListenerKey {
            protocol: self.protocol,
            port: self.port,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub generation: u64,
    pub listeners: Vec<Listener>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindState {
    Bound,
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerStatus {
    pub id: u32,
    pub state: BindState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub generation: u64,
    pub listeners: Vec<ListenerStatus>,
    pub version: String,
}

/// Upper bound on the encoded body of a `StreamHeader` frame; a reader may refuse any longer
/// length before reading or allocating for it.
pub const MAX_STREAM_HEADER_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamHeader {
    pub listener_id: u32,
    pub visitor: SocketAddr,
    pub local: SocketAddr,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn largest_stream_header_fits_its_cap() {
        let widest: SocketAddr = "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"
            .parse()
            .unwrap();
        let header = StreamHeader {
            listener_id: u32::MAX,
            visitor: widest,
            local: widest,
        };
        let mut body = Vec::new();
        ciborium::into_writer(&header, &mut body).unwrap();
        assert!(body.len() <= MAX_STREAM_HEADER_LEN, "{} bytes", body.len());
    }

    #[test]
    fn listener_key_drops_id() {
        let l = Listener {
            id: 9,
            protocol: Protocol::Udp,
            port: 53,
        };
        assert_eq!(
            l.key(),
            ListenerKey {
                protocol: Protocol::Udp,
                port: 53
            }
        );
    }
}
