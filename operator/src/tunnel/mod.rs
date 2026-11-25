//! Links to edges: dialing, configuration push and dispatch of visitor streams.

mod connector;
mod haproxy_connector;
mod link;
pub mod proxyv2;
mod udp;

pub use connector::{Connector, StaticConnector};
pub use haproxy_connector::HaproxyConnector;
pub use link::{
    EdgeLink, EdgeState, LinkHandle, LinkOptions, ListenerState, MAX_STATUS_TEXT, bind_endpoint,
    truncate_status_text,
};
pub use udp::{UdpTarget, UdpTargets, pick};
