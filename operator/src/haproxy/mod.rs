//! HAProxy as a supervised child process.

mod supervisor;

pub mod render;

pub use supervisor::{
    Applied, ApplyError, DEFAULT_RELOAD_TIMEOUT, MAX_RUNTIME_DIR_LEN, Supervisor, SupervisorOptions,
};
