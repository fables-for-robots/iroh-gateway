//! HAProxy as a supervised child process.

mod supervisor;

pub mod render;

use std::fmt;

pub use supervisor::{
    Applied, ApplyError, CERT_DIR, DEFAULT_RELOAD_TIMEOUT, MAX_RUNTIME_DIR_LEN, Supervisor,
    SupervisorOptions,
};

/// A file HAProxy reads besides its configuration: a certificate with its key, or a list of them.
///
/// The supervisor writes it as `<runtime_dir>/certs/<name>`. Its `Debug` shows the name only,
/// so that key material stays out of logs.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretFile {
    pub name: String,
    pub contents: String,
}

impl fmt::Debug for SecretFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretFile")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::haproxy::render::Rendered;

    #[test]
    fn debug_of_a_secret_file_hides_its_contents() {
        let file = SecretFile {
            name: "0123abcd.pem".to_owned(),
            contents: "-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n"
                .to_owned(),
        };
        let shown = format!("{file:?}");
        assert!(shown.contains("0123abcd.pem"), "{shown}");
        assert!(!shown.contains("PRIVATE KEY"), "{shown}");
        assert!(!shown.contains("c2VjcmV0"), "{shown}");
        let rendered = Rendered {
            haproxy_cfg: String::new(),
            files: vec![file],
            edges: Vec::new(),
        };
        let shown = format!("{rendered:?} {rendered:#?}");
        assert!(shown.contains("0123abcd.pem"), "{shown}");
        assert!(!shown.contains("PRIVATE KEY"), "{shown}");
        assert!(!shown.contains("c2VjcmV0"), "{shown}");
    }
}
