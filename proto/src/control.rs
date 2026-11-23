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
