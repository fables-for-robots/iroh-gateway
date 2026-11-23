//! Links to edges: dialing, configuration push and dispatch of visitor streams.

mod connector;
mod link;

pub use connector::{Connector, StaticConnector};
pub use link::{EdgeLink, EdgeState, LinkHandle, LinkOptions, ListenerState, bind_endpoint};
