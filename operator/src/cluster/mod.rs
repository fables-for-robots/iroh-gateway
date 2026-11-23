//! The operator's side of the Kubernetes API: watching resources, keeping its key in a Secret,
//! and writing status back.

pub mod identity;
mod status_writer;
mod stores;

pub use status_writer::{STATUS_REQUEST_TIMEOUT, StatusSink, StatusWriter};
pub use stores::{SnapshotSource, Stores};
