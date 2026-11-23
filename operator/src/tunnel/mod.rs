//! Links to edges: dialing, configuration push and dispatch of visitor streams.

mod connector;
mod link;

pub use connector::{Connector, StaticConnector};
pub use link::{
    EdgeLink, EdgeState, LinkHandle, LinkOptions, ListenerState, MAX_STATUS_TEXT, bind_endpoint,
    truncate_status_text,
};
