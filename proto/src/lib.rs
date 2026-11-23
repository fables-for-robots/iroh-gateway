//! Wire protocol shared by the iroh-gateway edge and operator.

pub mod control;
pub mod frame;
pub mod key;
pub mod splice;
pub mod tcp;
pub mod throttle;
pub mod transport;

pub const ALPN: &[u8] = b"iroh-gateway/0";
pub const DEFAULT_IROH_PORT: u16 = 7842;

/// Stream reset codes.
pub const RESET_ABORTED: u32 = 1;
pub const RESET_UNKNOWN_LISTENER: u32 = 2;
pub const RESET_BACKEND_UNAVAILABLE: u32 = 3;
pub const RESET_BAD_HEADER: u32 = 4;

/// Connection close codes.
pub const CLOSE_UNAUTHORIZED: u32 = 1;
pub const CLOSE_REPLACED: u32 = 2;
pub const CLOSE_SHUTDOWN: u32 = 3;
