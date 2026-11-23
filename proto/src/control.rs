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

    /// Encodes `value`, checks the bytes against `golden` (hex) and decodes them back.
    fn assert_wire<T>(value: &T, golden: &str)
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let mut body = Vec::new();
        ciborium::into_writer(value, &mut body).unwrap();
        assert_eq!(
            hex::encode(&body),
            golden,
            "wire format of {value:?} changed"
        );
        let decoded: T = ciborium::from_reader(&hex::decode(golden).unwrap()[..]).unwrap();
        assert_eq!(&decoded, value);
    }

    #[test]
    fn config_wire_format() {
        let cfg = Config {
            generation: 7,
            listeners: vec![
                Listener {
                    id: 1,
                    protocol: Protocol::Tcp,
                    port: 8080,
                },
                Listener {
                    id: 2,
                    protocol: Protocol::Udp,
                    port: 53,
                },
            ],
        };
        // {"generation": 7, "listeners": [{"id": 1, "protocol": "tcp", "port": 8080},
        //  {"id": 2, "protocol": "udp", "port": 53}]}
        assert_wire(
            &cfg,
            "a26a67656e65726174696f6e07696c697374656e65727382\
             a3626964016870726f746f636f6c6374637064706f7274191f90\
             a3626964026870726f746f636f6c6375647064706f72741835",
        );
    }

    #[test]
    fn status_wire_format() {
        let bound = Status {
            generation: 7,
            listeners: vec![ListenerStatus {
                id: 1,
                state: BindState::Bound,
            }],
            version: "0.1.0".into(),
        };
        // {"generation": 7, "listeners": [{"id": 1, "state": "Bound"}], "version": "0.1.0"}
        assert_wire(
            &bound,
            "a36a67656e65726174696f6e07696c697374656e65727381\
             a26269640165737461746565426f756e64\
             6776657273696f6e65302e312e30",
        );
        let error = Status {
            generation: 8,
            listeners: vec![ListenerStatus {
                id: 2,
                state: BindState::Error("busy".into()),
            }],
            version: "0.1.0".into(),
        };
        // {"generation": 8, "listeners": [{"id": 2, "state": {"Error": "busy"}}],
        //  "version": "0.1.0"}
        assert_wire(
            &error,
            "a36a67656e65726174696f6e08696c697374656e65727381\
             a262696402657374617465a1654572726f726462757379\
             6776657273696f6e65302e312e30",
        );
    }

    #[test]
    fn stream_header_wire_format() {
        let header = StreamHeader {
            listener_id: 1,
            visitor: "198.51.100.9:50000".parse().unwrap(),
            local: "[2001:db8::1]:443".parse().unwrap(),
        };
        // {"listener_id": 1, "visitor": {"V4": [[198, 51, 100, 9], 50000]},
        //  "local": {"V6": [[0x20, 0x01, 0x0d, 0xb8, 0, …, 0, 1], 443]}}
        assert_wire(
            &header,
            "a36b6c697374656e65725f696401\
             6776697369746f72a1625634828418c6183318640919c350\
             656c6f63616ca162563682901820010d18b80000000000000000000000011901bb",
        );
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
