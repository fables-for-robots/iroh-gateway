//! Certificates of HTTPS listeners, from Secrets of type `kubernetes.io/tls`.

use std::collections::BTreeMap;
use std::fmt;

use gateway_api::gateways::v1::{GatewayListenersTls, GatewayListenersTlsCertificateRefs};
use k8s_openapi::api::core::v1::Secret;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};

use super::{ObjRef, Reject};

/// A certificate chain with its private key, as HAProxy reads it.
#[derive(Clone, PartialEq, Eq)]
pub struct Certificate {
    pub secret: ObjRef,
    /// See `file_name`.
    pub file_name: String,
    /// `tls.crt`, then `tls.key`, each ending in exactly one newline. Key material.
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
    let mut keys = PrivateKeyDer::pem_slice_iter(tls_key.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| refuse("tls.key is not valid PEM"))?;
    if keys.len() != 1 {
        return Err(refuse("tls.key must hold exactly one private key"));
    }
    let der = keys.remove(0);
    let signing_key =
        any_supported_type(&der).map_err(|_| refuse("unsupported private key type"))?;
    match CertifiedKey::new(chain, signing_key).keys_match() {
        Ok(()) => {}
        Err(rustls::Error::InconsistentKeys(_)) => {
            return Err(refuse("the private key does not match the certificate"));
        }
        Err(_) => return Err(refuse("the first certificate in tls.crt cannot be read")),
    }

    let pem = format!("{}\n{}\n", crt.trim_end(), tls_key.trim_end());
    Ok(Certificate {
        file_name: file_name(&key, &pem),
        secret: key,
        pem,
    })
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
        let pem = format!("{}\n{}\n", crt.trim_end(), key.trim_end());
        assert_eq!(c.pem, pem);
        assert_eq!(c.file_name, format!("gw.site-tls.{}.pem", sha16(&pem)));

        // Each part ends in exactly one newline, whatever the Secret has.
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
            (
                junk_crt,
                &key,
                "the first certificate in tls.crt cannot be read",
            ),
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
}
