//! Certificates of HTTPS listeners, from Secrets of type `kubernetes.io/tls`.

use std::collections::BTreeMap;
use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use gateway_api::gateways::v1::{GatewayListenersTls, GatewayListenersTlsCertificateRefs};
use k8s_openapi::api::core::v1::Secret;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ParsedCertificate;
use rustls::sign::{CertifiedKey, SigningKey};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::{ObjRef, Reject};

/// A certificate chain with its private key, as HAProxy reads it.
#[derive(Clone, PartialEq, Eq)]
pub struct Certificate {
    pub secret: ObjRef,
    /// See `file_name`.
    pub file_name: String,
    /// Re-encoded from what was checked, so HAProxy reads nothing else: every certificate of
    /// `tls.crt`, in order, as a `CERTIFICATE` block, then the private key: PKCS#8 as
    /// `PRIVATE KEY`, PKCS#1 as `RSA PRIVATE KEY`, and a SEC1 EC key converted to PKCS#8 as
    /// `PRIVATE KEY` (OpenSSL does not read SEC1 without curve parameters). Standard base64 with padding
    /// in lines of 64 characters; every line ends in one `\n`. Key material.
    pub pem: String,
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("secret", &self.secret)
            .field("file_name", &self.file_name)
            .finish_non_exhaustive()
    }
}

/// `<the first 80 characters of "<namespace>.<name>", every character outside [a-z0-9.-] replaced by '_'>`
/// `.<the first 16 hex characters of SHA-256 over pem>.pem`
///
/// `pem` is [`Certificate::pem`], the re-encoded text, so equal certificates and keys give equal
/// names whatever the whitespace or extra text in the Secret.
pub(crate) fn file_name(secret: &ObjRef, pem: &str) -> String {
    let stem: String = format!("{}.{}", secret.namespace, secret.name)
        .chars()
        .take(80)
        .map(|c| match c {
            'a'..='z' | '0'..='9' | '.' | '-' => c,
            _ => '_',
        })
        .collect();
    let digest = hex::encode(Sha256::digest(pem.as_bytes()));
    format!("{stem}.{}.pem", &digest[..16])
}

/// Appends `der` to `out` as a PEM block with `label`: standard base64 with padding in lines of 64
/// characters, every line ending in `\n`.
fn push_block(out: &mut String, label: &str, der: &[u8]) {
    let b64 = BASE64.encode(der);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.extend(line.iter().map(|&b| char::from(b)));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
}

const SECRET_TYPE: &str = "kubernetes.io/tls";

fn invalid(message: impl Into<String>) -> Reject {
    Reject::new("InvalidCertificateRef", message)
}

/// The certificates of an HTTPS listener's `certificateRefs`, in order, when every one is usable.
///
/// Every message is built from the reference and fixed text: never from a Secret's data, nor from
/// an error that could quote it.
pub(super) fn resolve(
    tls: Option<&GatewayListenersTls>,
    gateway_ns: &str,
    secrets: &BTreeMap<ObjRef, &Secret>,
) -> Result<Vec<Certificate>, Reject> {
    let refs = tls
        .and_then(|t| t.certificate_refs.as_deref())
        .unwrap_or_default();
    if refs.is_empty() {
        return Err(invalid(
            "an HTTPS listener needs at least one certificateRef",
        ));
    }
    refs.iter()
        .map(|r| reference(r, gateway_ns, secrets))
        .collect()
}

/// The certificate one `certificateRef` names.
fn reference(
    r: &GatewayListenersTlsCertificateRefs,
    gateway_ns: &str,
    secrets: &BTreeMap<ObjRef, &Secret>,
) -> Result<Certificate, Reject> {
    let name = &r.name;
    let group = r.group.as_deref().unwrap_or("");
    let kind = r.kind.as_deref().unwrap_or("Secret");
    if !group.is_empty() || kind != "Secret" {
        return Err(invalid(format!(
            "certificateRef {name:?} is of group {group:?} and kind {kind:?}; \
             only core Secrets are supported"
        )));
    }
    if let Some(ns) = r.namespace.as_deref().filter(|ns| *ns != gateway_ns) {
        return Err(Reject::new(
            "RefNotPermitted",
            format!(
                "certificateRef {name:?} is in namespace {ns:?}; \
                 only Secrets in the Gateway's namespace are permitted"
            ),
        ));
    }
    let key = ObjRef::new(gateway_ns, name.as_str());
    let secret = secrets
        .get(&key)
        .ok_or_else(|| invalid(format!("secret {key} not found")))?;
    certificate(key, secret)
}

/// The certificate in a Secret, checked with rustls.
fn certificate(key: ObjRef, secret: &Secret) -> Result<Certificate, Reject> {
    let refuse = |what: &str| invalid(format!("secret {key}: {what}"));
    if secret.type_.as_deref() != Some(SECRET_TYPE) {
        return Err(refuse(&format!("the type is not {SECRET_TYPE}")));
    }
    let field = |name: &str| -> Result<&str, Reject> {
        let bytes = secret
            .data
            .as_ref()
            .and_then(|d| d.get(name))
            .ok_or_else(|| refuse(&format!("{name} is missing")))?;
        std::str::from_utf8(&bytes.0).map_err(|_| refuse(&format!("{name} is not UTF-8")))
    };
    let crt = field("tls.crt")?;
    let tls_key = field("tls.key")?;

    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(crt.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|_| refuse("tls.crt is not valid PEM"))?;
    if chain.is_empty() {
        return Err(refuse("tls.crt holds no certificate"));
    }
    // HAProxy reads both parts as one file: tls.crt may not bring a key of its own.
    if PrivateKeyDer::pem_slice_iter(crt.as_bytes())
        .next()
        .is_some()
    {
        return Err(refuse("tls.crt holds a private key"));
    }
    // Every element, not only the end entity: HAProxy refuses the whole configuration over a
    // chain element it cannot read. The parse error is never formatted.
    for (n, c) in chain.iter().enumerate() {
        if ParsedCertificate::try_from(c).is_err() {
            return Err(refuse(&format!(
                "certificate {} in tls.crt cannot be read",
                n + 1
            )));
        }
    }
    let mut keys = PrivateKeyDer::pem_slice_iter(tls_key.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| refuse("tls.key is not valid PEM"))?;
    if keys.len() != 1 {
        return Err(refuse("tls.key must hold exactly one private key"));
    }
    let unsupported = || refuse("unsupported private key type");
    let (der, key_label, signing_key) = match keys.remove(0) {
        // OpenSSL refuses a SEC1 key without its optional curve parameters, which ring accepts.
        PrivateKeyDer::Sec1(sec1) => {
            let (der, signing_key) =
                sec1_as_pkcs8(sec1.secret_sec1_der()).ok_or_else(unsupported)?;
            (der, "PRIVATE KEY", signing_key)
        }
        der @ (PrivateKeyDer::Pkcs8(_) | PrivateKeyDer::Pkcs1(_)) => {
            let signing_key = any_supported_type(&der).map_err(|_| unsupported())?;
            let label = match der {
                PrivateKeyDer::Pkcs8(_) => "PRIVATE KEY",
                _ => "RSA PRIVATE KEY",
            };
            (der, label, signing_key)
        }
        _ => return Err(unsupported()),
    };
    let mut pem = String::new();
    for c in &chain {
        push_block(&mut pem, "CERTIFICATE", c);
    }
    push_block(&mut pem, key_label, der.secret_der());
    match CertifiedKey::new(chain, signing_key).keys_match() {
        Ok(()) => {}
        Err(rustls::Error::InconsistentKeys(_)) => {
            return Err(refuse("the private key does not match the certificate"));
        }
        Err(_) => return Err(refuse("certificate 1 in tls.crt cannot be read")),
    }

    Ok(Certificate {
        file_name: file_name(&key, &pem),
        secret: key,
        pem,
    })
}

/// The start of a PKCS#8 `PrivateKeyInfo` for an EC key, before the `OCTET STRING` that holds
/// the SEC1 `ECPrivateKey`: `INTEGER 0` (the version), then the `AlgorithmIdentifier`
/// `SEQUENCE { id-ecPublicKey, <the curve> }`. The same bytes rustls uses in
/// `crypto/ring/sign.rs` to read a SEC1 key.
const PKCS8_PREFIXES: [&[u8]; 2] = [
    // prime256v1
    b"\x02\x01\x00\
      \x30\x13\
      \x06\x07\x2a\x86\x48\xce\x3d\x02\x01\
      \x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
    // secp384r1
    b"\x02\x01\x00\
      \x30\x10\
      \x06\x07\x2a\x86\x48\xce\x3d\x02\x01\
      \x06\x05\x2b\x81\x04\x00\x22",
];

/// A SEC1 EC key as PKCS#8, with the signing key read from that PKCS#8: wrapped with the
/// algorithm of P-256, else of P-384, whichever ring accepts. ring checks the private key's length
/// and public key against the curve, and any `[0]` parameters against the algorithm.
fn sec1_as_pkcs8(sec1: &[u8]) -> Option<(PrivateKeyDer<'static>, Arc<dyn SigningKey>)> {
    PKCS8_PREFIXES.iter().find_map(|prefix| {
        let octets = der(0x04, &[sec1]);
        let der = PrivateKeyDer::Pkcs8(der(0x30, &[prefix, &octets]).into());
        let signing_key = any_supported_type(&der).ok()?;
        Some((der, signing_key))
    })
}

/// A DER element with `tag` and the concatenation of `parts` as its content.
fn der(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let len: usize = parts.iter().map(|p| p.len()).sum();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

#[cfg(test)]
mod tests {
    use gateway_api::gateways::v1::{
        Gateway, GatewayListenersTls, GatewayListenersTlsCertificateRefs, GatewayListenersTlsMode,
    };
    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::Secret;
    use sha2::{Digest, Sha256};

    use super::super::fixtures::*;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    use super::super::{ListenerModel, Model, ObjRef, Reject, Snapshot, build};
    use super::file_name;

    const NS: &str = "gw";

    /// A Gateway `gw/<name>` with one HTTPS listener `tls` on port 443 for `app.example.com`,
    /// referring to the given Secrets.
    fn https(name: &str, secrets: &[&str]) -> Gateway {
        let mut gw = gateway(NS, name)
            .listener("tls", 443, "HTTPS")
            .hostname("app.example.com");
        for s in secrets {
            gw = gw.certificate(s);
        }
        gw
    }

    /// [`https`] with the given `tls` instead.
    fn https_with(tls: GatewayListenersTls) -> Gateway {
        gateway(NS, "public")
            .listener("tls", 443, "HTTPS")
            .hostname("app.example.com")
            .tls(tls)
    }

    fn cert_ref(
        group: Option<&str>,
        kind: Option<&str>,
        namespace: Option<&str>,
        name: &str,
    ) -> GatewayListenersTlsCertificateRefs {
        GatewayListenersTlsCertificateRefs {
            group: group.map(Into::into),
            kind: kind.map(Into::into),
            namespace: namespace.map(Into::into),
            name: name.into(),
        }
    }

    fn refs(refs: Vec<GatewayListenersTlsCertificateRefs>) -> GatewayListenersTls {
        GatewayListenersTls {
            certificate_refs: Some(refs),
            ..Default::default()
        }
    }

    fn model_of(gateways: Vec<Gateway>, secrets: Vec<Secret>) -> Model {
        let s = Snapshot {
            gateway_classes: vec![class("ours")],
            gateways,
            secrets,
            ..Default::default()
        };
        build(&s, &settings(&[NS]))
    }

    fn listener<'m>(m: &'m Model, gw: &str, name: &str) -> &'m ListenerModel {
        m.gateways
            .iter()
            .find(|g| g.key == ObjRef::new(NS, gw))
            .and_then(|g| g.listeners.iter().find(|l| l.name == name))
            .expect("listener exists")
    }

    /// The only listener of the only Gateway.
    fn only(m: &Model) -> &ListenerModel {
        assert_eq!(m.gateways.len(), 1);
        assert_eq!(m.gateways[0].listeners.len(), 1);
        let l = &m.gateways[0].listeners[0];
        assert_eq!(l.accepted, Ok(()));
        l
    }

    /// What refuses the only listener of a model of `gw` and `secrets`; it has no certificates.
    fn refusal(gw: Gateway, secrets: Vec<Secret>) -> Reject {
        let m = model_of(vec![gw], secrets);
        let l = only(&m);
        assert!(l.certificates.is_empty(), "{l:?}");
        l.resolved_refs.clone().expect_err("refused")
    }

    fn invalid(r: &Reject) {
        assert_eq!(r.reason, "InvalidCertificateRef", "{r:?}");
    }

    fn sha16(pem: &str) -> String {
        hex::encode(Sha256::digest(pem.as_bytes()))[..16].to_owned()
    }

    /// `secret` with `key` set to `value`, or removed when `None`.
    fn with_data(mut secret: Secret, key: &str, value: Option<&[u8]>) -> Secret {
        let data = secret.data.get_or_insert_with(Default::default);
        match value {
            Some(v) => data.insert(key.to_owned(), ByteString(v.to_vec())),
            None => data.remove(key),
        };
        secret
    }

    /// One PEM block as the operator must write it: base64 with padding in lines of 64, every
    /// line ending in `\n`.
    fn block(label: &str, der: &[u8]) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let mut lines = Vec::new();
        let mut rest = b64.as_str();
        while !rest.is_empty() {
            let (line, tail) = rest.split_at(rest.len().min(64));
            lines.push(line);
            rest = tail;
        }
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            lines.join("\n")
        )
    }

    /// The certificates of `crt` and the PKCS#8 key of `key`, re-encoded from their DER.
    fn canonical(crt: &str, key: &str) -> String {
        let mut out = String::new();
        for c in CertificateDer::pem_slice_iter(crt.as_bytes()) {
            out.push_str(&block("CERTIFICATE", &c.unwrap()));
        }
        let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
        out.push_str(&block("PRIVATE KEY", key.secret_der()));
        out
    }

    /// `pem` with every `\n` made `\r\n`.
    fn crlf(pem: &str) -> String {
        pem.replace('\n', "\r\n")
    }

    /// `pem`'s blocks with `label` put in place of their own.
    fn relabel(pem: &str, label: &str) -> String {
        pem.lines()
            .map(|l| match l.strip_prefix("-----BEGIN ") {
                Some(_) => format!("-----BEGIN {label}-----\n"),
                None if l.starts_with("-----END ") => format!("-----END {label}-----\n"),
                None => format!("{l}\n"),
            })
            .collect()
    }

    /// The base64 lines of a PEM key: every line that is not a marker.
    fn key_lines(pem: &str) -> Vec<&str> {
        pem.lines()
            .filter(|l| !l.is_empty() && !l.starts_with("-----"))
            .collect()
    }

    #[test]
    fn valid_secret_gives_one_certificate() {
        let (crt, key) = self_signed();
        let m = model_of(
            vec![https("public", &["site-tls"])],
            vec![tls_secret(NS, "site-tls", &crt, &key)],
        );
        let l = only(&m);
        assert_eq!(l.resolved_refs, Ok(()));
        assert_eq!(l.certificates.len(), 1);
        let c = &l.certificates[0];
        assert_eq!(c.secret, ObjRef::new(NS, "site-tls"));
        // rcgen writes canonical PEM already: LF, lines of 64.
        let pem = format!("{}\n{}\n", crt.trim_end(), key.trim_end());
        assert_eq!(pem, canonical(&crt, &key));
        assert_eq!(c.pem, pem);
        assert_eq!(c.file_name, format!("gw.site-tls.{}.pem", sha16(&pem)));

        // Extra blank lines around the parts do not reach the file.
        let m = model_of(
            vec![https("public", &["site-tls"])],
            vec![tls_secret(
                NS,
                "site-tls",
                &format!("{}\n\n\n", crt.trim_end()),
                key.trim_end(),
            )],
        );
        assert_eq!(only(&m).certificates[0].pem, pem);
    }

    #[test]
    fn file_name_is_stable_and_changes_with_the_content() {
        let k = ObjRef::new("gw", "site-tls");
        // SHA-256("a") = ca978112ca1bbdca…
        assert_eq!(file_name(&k, "a"), "gw.site-tls.ca978112ca1bbdca.pem");
        assert_eq!(file_name(&k, "a"), file_name(&k, "a"));
        assert_ne!(file_name(&k, "a"), file_name(&k, "b"));
        assert_ne!(
            file_name(&k, "a"),
            file_name(&ObjRef::new("gw", "other"), "a")
        );
    }

    #[test]
    fn long_names_are_cut() {
        let name = "a".repeat(253);
        let f = file_name(&ObjRef::new("gw", name), "x");
        assert!(f.len() <= 80 + 1 + 16 + 4, "{f}");
        assert_eq!(f.len(), 80 + 1 + 16 + 4);
        assert!(f.starts_with(&format!("gw.{}.", "a".repeat(77))), "{f}");
        assert!(f.ends_with(".pem"));
    }

    #[test]
    fn odd_characters_in_names_become_underscores() {
        let f = file_name(&ObjRef::new("a/b", "c d"), "x");
        assert!(!f.contains('/') && !f.contains(' '), "{f}");
        assert!(f.starts_with("a_b.c_d."), "{f}");

        let f = file_name(&ObjRef::new("../..", "Up\n\u{e9}"), "x");
        // Upper case, a line break and a non-ASCII letter are outside the set too.
        assert!(f.starts_with(".._..._p__."), "{f}");
        assert!(
            f.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c)),
            "{f}"
        );
    }

    #[test]
    fn missing_certificate_refs_are_invalid() {
        let no_tls = gateway(NS, "public")
            .listener("tls", 443, "HTTPS")
            .hostname("app.example.com");
        let no_refs = https_with(GatewayListenersTls {
            mode: Some(GatewayListenersTlsMode::Terminate),
            ..Default::default()
        });
        let empty_refs = https_with(refs(vec![]));
        for gw in [no_tls, no_refs, empty_refs] {
            let r = refusal(gw, vec![]);
            invalid(&r);
            assert_eq!(
                r.message,
                "an HTTPS listener needs at least one certificateRef"
            );
        }
    }

    #[test]
    fn secret_in_another_namespace_is_not_permitted() {
        let (crt, key) = self_signed();
        let secrets = vec![
            tls_secret("other", "site-tls", &crt, &key),
            tls_secret(NS, "site-tls", &crt, &key),
        ];
        let gw = https_with(refs(vec![cert_ref(None, None, Some("other"), "site-tls")]));
        let r = refusal(gw, secrets.clone());
        assert_eq!(r.reason, "RefNotPermitted");
        assert_eq!(
            r.message,
            "certificateRef \"site-tls\" is in namespace \"other\"; only Secrets in the Gateway's namespace are permitted"
        );

        // Naming the Gateway's own namespace is fine.
        let gw = https_with(refs(vec![cert_ref(None, None, Some(NS), "site-tls")]));
        let m = model_of(vec![gw], secrets);
        assert_eq!(only(&m).resolved_refs, Ok(()));
        assert_eq!(only(&m).certificates.len(), 1);
    }

    #[test]
    fn ref_to_another_kind_is_invalid() {
        let (crt, key) = self_signed();
        let secrets = vec![tls_secret(NS, "site-tls", &crt, &key)];
        for (group, kind) in [
            (None, Some("ConfigMap")),
            (Some("example.com"), None),
            (Some("example.com"), Some("Secret")),
            (Some("v1"), Some("Secret")),
        ] {
            let gw = https_with(refs(vec![cert_ref(group, kind, None, "site-tls")]));
            let r = refusal(gw, secrets.clone());
            invalid(&r);
            assert_eq!(
                r.message,
                format!(
                    "certificateRef \"site-tls\" is of group {:?} and kind {:?}; only core Secrets are supported",
                    group.unwrap_or(""),
                    kind.unwrap_or("Secret")
                )
            );
        }

        // The defaults, written out, are fine.
        let gw = https_with(refs(vec![cert_ref(
            Some(""),
            Some("Secret"),
            None,
            "site-tls",
        )]));
        let m = model_of(vec![gw], secrets);
        assert_eq!(only(&m).certificates.len(), 1);
    }

    #[test]
    fn missing_secret_is_invalid() {
        let (crt, key) = self_signed();
        let r = refusal(
            https("public", &["site-tls"]),
            vec![tls_secret(NS, "other-tls", &crt, &key)],
        );
        invalid(&r);
        assert_eq!(r.message, "secret gw/site-tls not found");
    }

    #[test]
    fn wrong_secret_type_is_invalid() {
        let (crt, key) = self_signed();
        for type_ in [Some("Opaque"), None] {
            let mut secret = tls_secret(NS, "site-tls", &crt, &key);
            secret.type_ = type_.map(Into::into);
            let r = refusal(https("public", &["site-tls"]), vec![secret]);
            invalid(&r);
            assert_eq!(
                r.message,
                "secret gw/site-tls: the type is not kubernetes.io/tls"
            );
        }
    }

    #[test]
    fn missing_tls_key_is_invalid() {
        let (crt, key) = self_signed();
        let good = tls_secret(NS, "site-tls", &crt, &key);
        let no_data = Secret {
            data: None,
            ..good.clone()
        };
        for (secret, field) in [
            (with_data(good.clone(), "tls.key", None), "tls.key"),
            (with_data(good, "tls.crt", None), "tls.crt"),
            (no_data, "tls.crt"),
        ] {
            let r = refusal(https("public", &["site-tls"]), vec![secret]);
            invalid(&r);
            assert_eq!(r.message, format!("secret gw/site-tls: {field} is missing"));
        }
    }

    #[test]
    fn garbage_pem_is_invalid() {
        let (crt, key) = self_signed();
        let broken = "-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n";
        let truncated = "-----BEGIN CERTIFICATE-----\nMIIB\n";
        let junk_crt = "-----BEGIN CERTIFICATE-----\n\
                        AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n\
                        -----END CERTIFICATE-----\n";
        let no_cert = "tls.crt holds no certificate";
        let bad_crt = "tls.crt is not valid PEM";
        let one_key = "tls.key must hold exactly one private key";
        for (crt, key, why) in [
            ("not a certificate", key.as_str(), no_cert),
            (broken, &key, bad_crt),
            (truncated, &key, bad_crt),
            // A key where the certificate belongs.
            (&key, &key, no_cert),
            (&crt, "not a key", one_key),
            (&crt, &crt, one_key),
            // Well-formed PEM around something that is no certificate.
            (junk_crt, &key, "certificate 1 in tls.crt cannot be read"),
        ] {
            let r = refusal(
                https("public", &["site-tls"]),
                vec![tls_secret(NS, "site-tls", crt, key)],
            );
            invalid(&r);
            assert_eq!(r.message, format!("secret gw/site-tls: {why}"));
        }
        for field in ["tls.crt", "tls.key"] {
            let mut value = if field == "tls.crt" { &crt } else { &key }
                .clone()
                .into_bytes();
            value.push(0xff);
            let secret = with_data(tls_secret(NS, "site-tls", &crt, &key), field, Some(&value));
            let r = refusal(https("public", &["site-tls"]), vec![secret]);
            invalid(&r);
            assert_eq!(
                r.message,
                format!("secret gw/site-tls: {field} is not UTF-8")
            );
        }
    }

    #[test]
    fn chain_element_that_is_not_a_certificate_is_invalid() {
        let (leaf, key) = self_signed();
        let (second, _) = self_signed_with(&rcgen::PKCS_ECDSA_P384_SHA384);
        let junk: Vec<u8> = std::iter::repeat_with(|| fastrand::u8(..))
            .take(300)
            .collect();
        let junk = block("CERTIFICATE", &junk);
        for (crt, n) in [
            (format!("{leaf}{junk}"), 2),
            (format!("{leaf}{second}{junk}"), 3),
            (format!("{leaf}{junk}{second}"), 2),
            (format!("{junk}{leaf}"), 1),
        ] {
            let r = refusal(
                https("public", &["site-tls"]),
                vec![tls_secret(NS, "site-tls", &crt, &key)],
            );
            invalid(&r);
            assert_eq!(
                r.message,
                format!("secret gw/site-tls: certificate {n} in tls.crt cannot be read")
            );
        }
        // A good chain of three still passes.
        let c = resolved(&format!("{leaf}{second}{leaf}"), &key).expect("accepted");
        assert_eq!(c.pem.matches("-----BEGIN CERTIFICATE-----").count(), 3);
    }

    #[test]
    fn two_private_keys_are_invalid() {
        let (crt, key) = self_signed();
        let (_, other_key) = self_signed();
        for (crt, key, why) in [
            (
                crt.clone(),
                format!("{key}{other_key}"),
                "tls.key must hold exactly one private key",
            ),
            (
                crt.clone(),
                format!("{key}{key}"),
                "tls.key must hold exactly one private key",
            ),
            // A private key in tls.crt makes two in the file HAProxy reads.
            (
                format!("{crt}{key}"),
                key.clone(),
                "tls.crt holds a private key",
            ),
        ] {
            let secret = tls_secret(NS, "site-tls", &crt, &key);
            let r = refusal(https("public", &["site-tls"]), vec![secret]);
            invalid(&r);
            assert_eq!(r.message, format!("secret gw/site-tls: {why}"));
        }
    }

    #[test]
    fn unsupported_key_type_is_invalid() {
        let (crt, key) = self_signed();
        // A well-formed PEM section whose content is no key ring can use.
        let junk = "-----BEGIN PRIVATE KEY-----\nAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n-----END PRIVATE KEY-----\n";
        // A real key, cut short.
        let lines: Vec<&str> = key.lines().collect();
        let cut = [&lines[..2], &lines[lines.len() - 1..]].concat().join("\n");
        for key in [junk.to_owned(), cut] {
            let r = refusal(
                https("public", &["site-tls"]),
                vec![tls_secret(NS, "site-tls", &crt, &key)],
            );
            invalid(&r);
            assert_eq!(
                r.message,
                "secret gw/site-tls: unsupported private key type"
            );
        }
    }

    #[test]
    fn mismatched_key_refuses_only_that_listener() {
        let (crt, key) = self_signed();
        let (_, other_key) = self_signed();
        let public = gateway(NS, "public")
            .listener("a", 443, "HTTPS")
            .hostname("a.example.com")
            .certificate("good")
            .listener("b", 443, "HTTPS")
            .hostname("b.example.com")
            .certificate("bad");
        let m = model_of(
            vec![public, https("second", &["good"])],
            vec![
                tls_secret(NS, "good", &crt, &key),
                tls_secret(NS, "bad", &crt, &other_key),
            ],
        );
        let b = listener(&m, "public", "b");
        assert!(b.certificates.is_empty());
        let r = b.resolved_refs.as_ref().unwrap_err();
        invalid(r);
        assert_eq!(
            r.message,
            "secret gw/bad: the private key does not match the certificate"
        );
        assert_eq!(b.accepted, Ok(()));
        for (gw, name) in [("public", "a"), ("second", "tls")] {
            let l = listener(&m, gw, name);
            assert_eq!(l.resolved_refs, Ok(()), "{gw}/{name}");
            assert_eq!(l.certificates.len(), 1, "{gw}/{name}");
        }
        for g in &m.gateways {
            assert_eq!(g.accepted, Ok(()));
        }
    }

    #[test]
    fn one_bad_ref_among_two_refuses_the_listener() {
        let (crt, key) = self_signed();
        for names in [["good", "missing"], ["missing", "good"]] {
            let r = refusal(
                https("public", &names),
                vec![tls_secret(NS, "good", &crt, &key)],
            );
            invalid(&r);
            assert_eq!(r.message, "secret gw/missing not found");
        }
    }

    #[test]
    fn two_valid_refs_give_two_certificates_in_ref_order() {
        let (crt1, key1) = self_signed();
        let (crt2, key2) = self_signed_with(&rcgen::PKCS_ED25519);
        let m = model_of(
            vec![https("public", &["z-tls", "a-tls"])],
            vec![
                tls_secret(NS, "a-tls", &crt2, &key2),
                tls_secret(NS, "z-tls", &crt1, &key1),
            ],
        );
        let l = only(&m);
        let names: Vec<_> = l
            .certificates
            .iter()
            .map(|c| c.secret.name.as_str())
            .collect();
        assert_eq!(names, ["z-tls", "a-tls"]);
        assert!(l.certificates[0].pem.starts_with(crt1.trim_end()));
        assert!(l.certificates[1].pem.starts_with(crt2.trim_end()));
    }

    #[test]
    fn ecdsa_p256_p384_and_ed25519_keys_are_accepted() {
        for alg in [
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P384_SHA384,
            &rcgen::PKCS_ED25519,
        ] {
            let (crt, key) = self_signed_with(alg);
            let m = model_of(
                vec![https("public", &["site-tls"])],
                vec![tls_secret(NS, "site-tls", &crt, &key)],
            );
            assert_eq!(only(&m).resolved_refs, Ok(()), "{alg:?}");
            assert_eq!(only(&m).certificates.len(), 1, "{alg:?}");
        }
    }

    #[test]
    fn certificate_problem_replaces_invalid_route_kinds() {
        let kinds = [
            ("gateway.networking.k8s.io", "HTTPRoute"),
            ("gateway.networking.k8s.io", "TCPRoute"),
        ];
        let r = refusal(https("public", &["site-tls"]).allowed_kinds(&kinds), vec![]);
        invalid(&r);
        assert_eq!(r.message, "secret gw/site-tls not found");

        // With a usable certificate the kinds problem stays.
        let (crt, key) = self_signed();
        let m = model_of(
            vec![https("public", &["site-tls"]).allowed_kinds(&kinds)],
            vec![tls_secret(NS, "site-tls", &crt, &key)],
        );
        let l = only(&m);
        assert_eq!(
            l.resolved_refs.as_ref().unwrap_err().reason,
            "InvalidRouteKinds"
        );
        assert_eq!(l.certificates.len(), 1);
        assert_eq!(l.supported_kinds, ["HTTPRoute"]);
    }

    #[test]
    fn reject_messages_never_contain_key_material() {
        let (crt, key) = self_signed();
        let (_, other_key) = self_signed();
        let lines: Vec<&str> = key.lines().collect();
        let cut_key = [&lines[..2], &lines[lines.len() - 1..]].concat().join("\n");
        let mut not_utf8 = key.clone().into_bytes();
        not_utf8.push(0xff);
        let good = || tls_secret(NS, "site-tls", &crt, &key);
        let in_other_ns = tls_secret("other", "site-tls", &crt, &key);
        let mut opaque = good();
        opaque.type_ = Some("Opaque".into());

        let site = || https("public", &["site-tls"]);
        let cases: Vec<(&str, Gateway, Vec<Secret>)> = vec![
            ("no refs", https("public", &[]), vec![good()]),
            (
                "other namespace",
                https_with(refs(vec![cert_ref(None, None, Some("other"), "site-tls")])),
                vec![in_other_ns],
            ),
            (
                "other kind",
                https_with(refs(vec![cert_ref(
                    None,
                    Some("ConfigMap"),
                    None,
                    "site-tls",
                )])),
                vec![good()],
            ),
            ("missing", https("public", &["missing"]), vec![good()]),
            ("wrong type", site(), vec![opaque]),
            (
                "missing tls.crt",
                site(),
                vec![with_data(good(), "tls.crt", None)],
            ),
            (
                "key in place of the certificate",
                site(),
                vec![tls_secret(NS, "site-tls", &key, &key)],
            ),
            (
                "garbage tls.crt",
                site(),
                vec![tls_secret(NS, "site-tls", "garbage", &key)],
            ),
            (
                "key not UTF-8",
                site(),
                vec![with_data(good(), "tls.key", Some(&not_utf8))],
            ),
            (
                "two keys",
                site(),
                vec![tls_secret(
                    NS,
                    "site-tls",
                    &crt,
                    &format!("{key}{other_key}"),
                )],
            ),
            (
                "key in tls.crt",
                site(),
                vec![tls_secret(NS, "site-tls", &format!("{crt}{key}"), &key)],
            ),
            (
                "cut key",
                site(),
                vec![tls_secret(NS, "site-tls", &crt, &cut_key)],
            ),
            (
                "mismatched key",
                site(),
                vec![tls_secret(NS, "site-tls", &crt, &other_key)],
            ),
        ];
        let secret_lines: Vec<&str> = key_lines(&key)
            .into_iter()
            .chain(key_lines(&other_key))
            .collect();
        assert!(secret_lines.len() >= 4);
        for (label, gw, secrets) in cases {
            let r = refusal(gw, secrets);
            assert!(!r.message.contains("PRIVATE KEY"), "{label}: {r:?}");
            assert!(!r.message.contains("-----"), "{label}: {r:?}");
            for line in &secret_lines {
                assert!(!r.message.contains(line), "{label}: {r:?}");
                // Nor a good part of one.
                assert!(
                    !r.message.contains(&line[..line.len().min(24)]),
                    "{label}: {r:?}"
                );
            }
        }
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let (crt, key) = self_signed();
        let m = model_of(
            vec![https("public", &["site-tls"])],
            vec![tls_secret(NS, "site-tls", &crt, &key)],
        );
        let c = &only(&m).certificates[0];
        assert!(c.pem.contains("PRIVATE KEY"));
        for out in [format!("{m:?}"), format!("{m:#?}"), format!("{c:?}")] {
            assert!(out.contains(&c.file_name), "{out}");
            assert!(out.contains("site-tls"), "{out}");
            assert!(!out.contains("PRIVATE KEY"), "{out}");
            for line in key_lines(&key) {
                assert!(!out.contains(line), "{out}");
            }
        }
    }

    #[test]
    fn https_listener_with_certificates_serves_once_a_route_is_attached() {
        let (crt, key) = self_signed();
        let gw = gateway(NS, "public")
            .listener("good", 443, "HTTPS")
            .hostname("a.example.com")
            .certificate("site-tls")
            .listener("bare", 443, "HTTPS")
            .hostname("b.example.com")
            .certificate("missing");
        let mut m = model_of(vec![gw], vec![tls_secret(NS, "site-tls", &crt, &key)]);
        let listeners = &mut m.gateways[0].listeners;
        assert_eq!(listeners[0].certificates.len(), 1);
        assert!(listeners[1].certificates.is_empty());
        for l in listeners.iter_mut() {
            assert!(!l.serving(), "{}", l.name);
            l.attached_routes = 1;
        }
        assert!(listeners[0].serving());
        // Without certificates it does not serve, whatever is attached.
        assert!(!listeners[1].serving());
        listeners[0].conflicted = Some(Reject::new("HostnameConflict", "x"));
        assert!(!listeners[0].serving());
    }
    /// The certificate of a model of one HTTPS Gateway and a Secret `site-tls` with `crt` and
    /// `key`, or what refused it.
    fn resolved(crt: &str, key: &str) -> Result<super::Certificate, Reject> {
        let m = model_of(
            vec![https("public", &["site-tls"])],
            vec![tls_secret(NS, "site-tls", crt, key)],
        );
        let l = only(&m);
        l.resolved_refs.clone()?;
        assert_eq!(l.certificates.len(), 1);
        Ok(l.certificates[0].clone())
    }

    #[test]
    fn pem_is_re_encoded_from_what_was_checked() {
        let (leaf, key) = self_signed();
        let (second, _) = self_signed_with(&rcgen::PKCS_ED25519);
        let messy_crt = crlf(&format!(
            "Bag Attributes\n    friendlyName: site\n{leaf}# a comment between blocks\n\n{second}trailing text\n"
        ));
        let messy_key = crlf(&format!(
            "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n{key}"
        ));
        let c = resolved(&messy_crt, &messy_key).expect("accepted");
        let want = canonical(&format!("{leaf}{second}"), &key);
        assert_eq!(c.pem, want);
        assert_eq!(c.pem, format!("{leaf}{second}{key}"));
        assert_eq!(c.pem.matches("-----BEGIN CERTIFICATE-----").count(), 2);
        assert_eq!(c.pem.matches("-----BEGIN ").count(), 3);
        assert_eq!(c.pem.matches("PRIVATE KEY-----").count(), 2);
        for extra in [
            "Bag",
            "friendlyName",
            "comment",
            "trailing",
            "PARAMETERS",
            "\r",
            "\n\n",
        ] {
            assert!(!c.pem.contains(extra), "{extra:?} in {}", c.file_name);
        }
        assert_eq!(c.file_name, format!("gw.site-tls.{}.pem", sha16(&want)));
    }

    #[test]
    fn sections_rustls_skips_never_reach_the_file() {
        let (crt, key) = self_signed();
        let trusted = relabel(&crt, "TRUSTED CERTIFICATE");
        let dsa = relabel(&key, "DSA PRIVATE KEY");
        let encrypted = relabel(&key, "ENCRYPTED PRIVATE KEY");
        let cases = [
            (
                "TRUSTED CERTIFICATE",
                format!("{trusted}{crt}"),
                key.clone(),
            ),
            ("DSA PRIVATE KEY", format!("{dsa}{crt}"), key.clone()),
            (
                "ENCRYPTED PRIVATE KEY",
                crt.clone(),
                format!("{encrypted}{key}"),
            ),
        ];
        for (label, crt_field, key_field) in cases {
            // Either refused or accepted; when accepted, the file holds only what was checked.
            if let Ok(c) = resolved(&crt_field, &key_field) {
                assert!(!c.pem.contains(label), "{label}");
                assert!(!c.pem.contains("TRUSTED CERTIFICATE"), "{label}");
                assert!(!c.pem.contains("DSA PRIVATE KEY"), "{label}");
                assert!(!c.pem.contains("ENCRYPTED PRIVATE KEY"), "{label}");
                assert_eq!(c.pem, canonical(&crt, &key), "{label}");
            }
        }
    }

    #[test]
    fn equal_certificates_give_equal_files_whatever_the_whitespace() {
        let (crt, key) = self_signed();
        let lf = resolved(&crt, &key).expect("accepted");
        let crlf = resolved(&crlf(&crt), &crlf(&key)).expect("accepted");
        let trimmed = resolved(crt.trim_end(), key.trim_end()).expect("accepted");
        for other in [&crlf, &trimmed] {
            assert_eq!(other.pem, lf.pem);
            assert_eq!(other.file_name, lf.file_name);
        }
    }

    #[test]
    fn re_encoded_pem_parses_back_to_the_same_der() {
        let (leaf, key) = self_signed();
        let (second, _) = self_signed_with(&rcgen::PKCS_ECDSA_P384_SHA384);
        let crt = crlf(&format!("{leaf}{second}"));
        let c = resolved(&crt, &crlf(&key)).expect("accepted");

        let original: Vec<CertificateDer<'_>> = CertificateDer::pem_slice_iter(crt.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
        let again: Vec<CertificateDer<'_>> = CertificateDer::pem_slice_iter(c.pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(original.len(), 2);
        assert_eq!(again, original);

        let original = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
        let keys: Vec<PrivateKeyDer<'_>> = PrivateKeyDer::pem_slice_iter(c.pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].secret_der(), original.secret_der());
    }

    #[test]
    fn key_blocks_carry_the_label_of_their_form() {
        // Not keys: only the framing is under test here.
        let der: Vec<u8> = (0..=99).collect();
        for (key, label) in [
            (PrivateKeyDer::Pkcs8(der.clone().into()), "PRIVATE KEY"),
            (PrivateKeyDer::Pkcs1(der.clone().into()), "RSA PRIVATE KEY"),
            (PrivateKeyDer::Sec1(der.clone().into()), "EC PRIVATE KEY"),
        ] {
            let mut out = String::new();
            super::push_block(&mut out, label, key.secret_der());
            assert_eq!(out, block(label, &der));
            let lines: Vec<&str> = out.lines().collect();
            // 100 bytes: 136 base64 characters in lines of 64, 64 and 8.
            assert_eq!(lines.len(), 5);
            assert_eq!(lines[0], format!("-----BEGIN {label}-----"));
            assert_eq!(
                (lines[1].len(), lines[2].len(), lines[3].len()),
                (64, 64, 8)
            );
            assert_eq!(lines[4], format!("-----END {label}-----"));
            assert!(out.ends_with("-----\n") && !out.contains("\n\n"));
            let back = PrivateKeyDer::from_pem_slice(out.as_bytes()).unwrap();
            assert_eq!(back.secret_der(), der.as_slice());
        }
    }

    /// One DER element at the start of `der`: its tag, its content, and what follows it.
    fn tlv(der: &[u8]) -> (u8, &[u8], &[u8]) {
        let (len, at) = match der[1] {
            n if n < 0x80 => (usize::from(n), 2),
            0x81 => (usize::from(der[2]), 3),
            0x82 => (usize::from(der[2]) << 8 | usize::from(der[3]), 4),
            n => panic!("length form {n:#x}"),
        };
        (der[0], &der[at..at + len], &der[at + len..])
    }

    /// `content` as a DER element with `tag`.
    fn wrap(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            n if n < 0x80 => out.push(n as u8),
            n if n < 0x100 => out.extend([0x81, n as u8]),
            n => out.extend([0x82, (n >> 8) as u8, n as u8]),
        }
        out.extend_from_slice(content);
        out
    }

    /// The SEC1 `ECPrivateKey` inside a PKCS#8 EC key, and the curve OID of its algorithm.
    fn sec1_of(pkcs8: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (tag, info, rest) = tlv(pkcs8);
        assert_eq!((tag, rest.len()), (0x30, 0));
        let (_, _version, rest) = tlv(info);
        let (_, alg, rest) = tlv(rest);
        let (_, _ec_public_key, curve) = tlv(alg);
        let (tag, sec1, _) = tlv(rest);
        assert_eq!(tag, 0x04);
        (sec1.to_vec(), curve.to_vec())
    }

    /// `sec1` with the `[0]` curve parameters `curve` (a full OID element) after the private key.
    fn with_parameters(sec1: &[u8], curve: &[u8]) -> Vec<u8> {
        let (tag, content, _) = tlv(sec1);
        assert_eq!(tag, 0x30);
        let (_, _, after_version) = tlv(content);
        let (_, _, after_key) = tlv(after_version);
        assert_eq!(after_key[0], 0xa1, "ring writes no parameters");
        let head = &content[..content.len() - after_key.len()];
        let mut inner = head.to_vec();
        inner.extend(wrap(0xa0, curve));
        inner.extend_from_slice(after_key);
        wrap(0x30, &inner)
    }

    #[test]
    fn sec1_key_is_written_as_pkcs8() {
        use rustls::crypto::ring::sign::any_supported_type;
        use rustls::sign::CertifiedKey;

        for alg in [
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P384_SHA384,
        ] {
            let (crt, key) = self_signed_with(alg);
            let pkcs8 = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
            let (bare, curve) = sec1_of(pkcs8.secret_der());
            let full = with_parameters(&bare, &curve);
            assert_ne!(bare, full);
            let crt_der = CertificateDer::from_pem_slice(crt.as_bytes()).unwrap();
            for sec1 in [&bare, &full] {
                let sec1_pem = block("EC PRIVATE KEY", sec1);
                // rustls itself reads the SEC1 form.
                assert!(matches!(
                    PrivateKeyDer::from_pem_slice(sec1_pem.as_bytes()).unwrap(),
                    PrivateKeyDer::Sec1(_)
                ));
                let c = resolved(&crt, &sec1_pem).expect("accepted");
                assert!(!c.pem.contains("EC PRIVATE KEY"), "{alg:?}");
                let (cert_block, key_block) = c
                    .pem
                    .split_at(c.pem.find("-----BEGIN PRIVATE KEY").unwrap());
                assert_eq!(cert_block, block("CERTIFICATE", &crt_der));

                // The key parses back as PKCS#8 holding exactly the SEC1 structure given, under
                // the algorithm of the certificate's curve.
                let written = PrivateKeyDer::from_pem_slice(key_block.as_bytes()).unwrap();
                assert!(matches!(written, PrivateKeyDer::Pkcs8(_)), "{alg:?}");
                assert_eq!(sec1_of(written.secret_der()), (sec1.clone(), curve.clone()));
                if sec1 == &bare {
                    // Without parameters it is the PKCS#8 key rcgen made.
                    assert_eq!(written.secret_der(), pkcs8.secret_der());
                }
                let signing = any_supported_type(&written).expect("a key rustls can use");
                CertifiedKey::new(vec![crt_der.clone()], signing)
                    .keys_match()
                    .expect("matches the certificate");
            }
        }
    }

    #[test]
    fn sec1_key_of_another_curve_than_its_certificate_is_refused() {
        let (crt, _) = self_signed();
        let (_, p384) = self_signed_with(&rcgen::PKCS_ECDSA_P384_SHA384);
        let pkcs8 = PrivateKeyDer::from_pem_slice(p384.as_bytes()).unwrap();
        let (sec1, _) = sec1_of(pkcs8.secret_der());
        let r = resolved(&crt, &block("EC PRIVATE KEY", &sec1)).expect_err("refused");
        invalid(&r);
        assert_eq!(
            r.message,
            "secret gw/site-tls: the private key does not match the certificate"
        );
    }
}
