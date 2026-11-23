//! The operator's iroh key, kept in a Secret so that it survives restarts and rescheduling.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use iroh::SecretKey;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::PostParams;
use kube::{Api, Client};
use tracing::info;

use super::STATUS_REQUEST_TIMEOUT;

/// The Secret's one key; its value is the secret key as 64 lowercase hex characters.
pub const SECRET_KEY: &str = "secret-key";

/// How long one call for the Secret may take, as for a status request.
const REQUEST_TIMEOUT: Duration = STATUS_REQUEST_TIMEOUT;

/// `request` with `limit`; running out of time is an error.
async fn bounded<T>(
    limit: Duration,
    request: impl Future<Output = kube::Result<T>>,
) -> anyhow::Result<kube::Result<T>> {
    tokio::time::timeout(limit, request)
        .await
        .map_err(|_| anyhow!("no answer from the API server within {limit:?}"))
}

/// Reads key `secret-key` (64 hex characters) from the Secret; creates the Secret with a fresh key
/// if it does not exist. A malformed value is an error and is never overwritten. Each call to the
/// API server that takes longer than 10 s is an error.
pub async fn load_or_create(
    client: &Client,
    namespace: &str,
    name: &str,
) -> anyhow::Result<SecretKey> {
    load_or_create_within(client, namespace, name, REQUEST_TIMEOUT).await
}

/// [`load_or_create`] with `limit` for each call to the API server.
async fn load_or_create_within(
    client: &Client,
    namespace: &str,
    name: &str,
    limit: Duration,
) -> anyhow::Result<SecretKey> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let what = || format!("Secret {namespace}/{name}");
    if let Some(secret) = bounded(limit, api.get_opt(name))
        .await
        .with_context(what)?
        .with_context(what)?
    {
        return parse(&secret).with_context(what);
    }
    let key = SecretKey::generate();
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(name.to_owned()),
            namespace: Some(namespace.to_owned()),
            ..ObjectMeta::default()
        },
        type_: Some("Opaque".to_owned()),
        data: Some(BTreeMap::from([(
            SECRET_KEY.to_owned(),
            ByteString(hex::encode(key.to_bytes()).into_bytes()),
        )])),
        ..Secret::default()
    };
    let created = bounded(limit, api.create(&PostParams::default(), &secret))
        .await
        .with_context(|| format!("creating {}", what()))?;
    match created {
        Ok(_) => {
            info!(secret = %what(), "created the operator's identity");
            Ok(key)
        }
        // Someone else created it first: theirs counts.
        Err(kube::Error::Api(status)) if status.code == 409 => {
            let secret = bounded(limit, api.get(name))
                .await
                .with_context(what)?
                .with_context(what)?;
            parse(&secret).with_context(what)
        }
        Err(e) => Err(e).with_context(|| format!("creating {}", what())),
    }
}

/// The key in `secret`; the error never contains the value.
fn parse(secret: &Secret) -> anyhow::Result<SecretKey> {
    let value = secret
        .data
        .as_ref()
        .and_then(|d| d.get(SECRET_KEY))
        .ok_or_else(|| anyhow!("has no key {SECRET_KEY:?}"))?;
    let text =
        std::str::from_utf8(&value.0).map_err(|_| anyhow!("key {SECRET_KEY:?} is not text"))?;
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(
            "key {SECRET_KEY:?} is not 64 hex characters (found {} bytes)",
            text.len()
        );
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(text, &mut bytes).map_err(|_| anyhow!("key {SECRET_KEY:?} is not hex"))?;
    Ok(SecretKey::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(data: Option<&[u8]>) -> Secret {
        Secret {
            data: data.map(|d| BTreeMap::from([(SECRET_KEY.to_owned(), ByteString(d.to_vec()))])),
            ..Secret::default()
        }
    }

    #[tokio::test]
    async fn a_call_without_an_answer_is_an_error_after_the_limit() {
        // The kernel completes the handshake; nothing ever reads the request.
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", silent.local_addr().unwrap())
            .parse()
            .unwrap();
        let client = Client::try_from(kube::Config::new(url)).unwrap();
        let limit = std::time::Duration::from_millis(300);
        let started = tokio::time::Instant::now();
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            load_or_create_within(&client, "ns", "id", limit),
        )
        .await
        .expect("the call did not end")
        .unwrap_err();
        assert!(started.elapsed() >= limit);
        let text = format!("{error:#}");
        assert!(text.contains("no answer from the API server"), "{text}");
        assert!(text.contains("Secret ns/id"), "{text}");
        assert_eq!(REQUEST_TIMEOUT, std::time::Duration::from_secs(10));
        drop(silent);
    }

    #[test]
    fn parses_64_hex_characters() {
        let key = SecretKey::from_bytes(&[3; 32]);
        let text = hex::encode(key.to_bytes());
        let parsed = parse(&secret(Some(text.as_bytes()))).unwrap();
        assert_eq!(parsed.public(), key.public());
    }

    #[test]
    fn malformed_values_are_errors_that_do_not_show_the_value() {
        let not_hex = "zz".repeat(32);
        let too_long = "ab".repeat(33);
        for value in ["abcd", not_hex.as_str(), too_long.as_str()] {
            let error = parse(&secret(Some(value.as_bytes()))).unwrap_err();
            assert!(!format!("{error:#}").contains(value), "{error:#}");
        }
        assert!(parse(&secret(None)).is_err());
        assert!(parse(&secret(Some(&[0xff; 64]))).is_err());
    }
}
