//! Secret key files: 64 lowercase hex characters and a newline.

use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::Path,
};

use anyhow::{Context, bail};
use iroh::SecretKey;

/// Reads the key at `path`; if the file does not exist, generates one and writes it.
/// Any other problem (unreadable, wrong length, not hex) is an error.
pub fn load_or_generate(path: &Path) -> anyhow::Result<SecretKey> {
    match fs::read_to_string(path) {
        Ok(text) => parse(&text).with_context(|| format!("key file {}", path.display())),
        Err(e) if e.kind() == ErrorKind::NotFound => generate(path),
        Err(e) => Err(e).with_context(|| format!("reading key file {}", path.display())),
    }
}

fn parse(text: &str) -> anyhow::Result<SecretKey> {
    let bytes = hex::decode(text.trim_end()).context("not valid hex")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|b: Vec<u8>| anyhow::anyhow!("expected 32 bytes, found {}", b.len()))?;
    Ok(SecretKey::from(bytes))
}

fn generate(path: &Path) -> anyhow::Result<SecretKey> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_private_dir(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }
    let key = SecretKey::generate();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = match options.open(path) {
        Ok(f) => f,
        // Lost a race with another process creating the same file: use theirs.
        Err(e) if e.kind() == ErrorKind::AlreadyExists => return load_or_generate(path),
        Err(e) => {
            return Err(e).with_context(|| format!("creating key file {}", path.display()));
        }
    };
    let line = format!("{}\n", hex::encode(key.to_bytes()));
    if let Err(e) = file
        .write_all(line.as_bytes())
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(path);
        bail!("writing key file {}: {e}", path.display());
    }
    Ok(key)
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_then_reloads_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/edge.key");
        let a = load_or_generate(&path).unwrap();
        let b = load_or_generate(&path).unwrap();
        assert_eq!(a.public(), b.public());
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.trim().len(), 64);
        assert!(text.ends_with('\n'));
    }

    #[cfg(unix)]
    #[test]
    fn new_key_file_and_dir_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/edge.key");
        load_or_generate(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn load_rejects_malformed_key_file() {
        for bad in ["", "abcd", &"zz".repeat(32), &"ab".repeat(31)] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("k.key");
            std::fs::write(&path, bad).unwrap();
            assert!(load_or_generate(&path).is_err(), "accepted {bad:?}");
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                bad,
                "file was rewritten"
            );
        }
    }
}
