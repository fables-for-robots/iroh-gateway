//! Length-prefixed CBOR framing: a 4-byte big-endian length, then that many bytes of CBOR.

use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME_LEN: usize = 65_536;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame of {0} bytes exceeds the maximum")]
    TooLarge(usize),
    #[error("decode: {0}")]
    Decode(String),
    #[error("encode: {0}")]
    Encode(String),
}

pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut body = Vec::new();
    ciborium::into_writer(msg, &mut body).map_err(|e| FrameError::Encode(e.to_string()))?;
    if body.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(body.len()));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    w.write_all(&out).await?;
    Ok(())
}

/// Ok(None) on clean EOF before the first length byte.
pub async fn read_frame<R, T>(r: &mut R) -> Result<Option<T>, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    let mut filled = 0;
    while filled < len_buf.len() {
        let n = r.read(&mut len_buf[filled..]).await?;
        if n == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        filled += n;
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    ciborium::from_reader(&body[..])
        .map(Some)
        .map_err(|e| FrameError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::*;

    #[tokio::test]
    async fn config_roundtrips() {
        let cfg = Config {
            generation: 7,
            listeners: vec![Listener {
                id: 3,
                protocol: Protocol::Tcp,
                port: 443,
            }],
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &cfg).await.unwrap();
        assert_eq!(&buf[..4], &((buf.len() - 4) as u32).to_be_bytes());
        let got: Option<Config> = read_frame(&mut &buf[..]).await.unwrap();
        assert_eq!(got, Some(cfg));
    }

    #[tokio::test]
    async fn status_and_header_roundtrip() {
        let status = Status {
            generation: 2,
            listeners: vec![
                ListenerStatus {
                    id: 1,
                    state: BindState::Bound,
                },
                ListenerStatus {
                    id: 2,
                    state: BindState::Error("address in use".into()),
                },
            ],
            version: "0.1.0".into(),
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &status).await.unwrap();
        let got: Option<Status> = read_frame(&mut &buf[..]).await.unwrap();
        assert_eq!(got, Some(status));

        let header = StreamHeader {
            listener_id: 1,
            visitor: "198.51.100.9:50000".parse().unwrap(),
            local: "[2001:db8::1]:443".parse().unwrap(),
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &header).await.unwrap();
        let got: Option<StreamHeader> = read_frame(&mut &buf[..]).await.unwrap();
        assert_eq!(got, Some(header));
    }

    #[tokio::test]
    async fn read_frame_returns_none_on_clean_eof() {
        let got: Option<Config> = read_frame(&mut &[][..]).await.unwrap();
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn read_frame_errors_on_truncated_body() {
        let bytes = [0, 0, 0, 10, 1, 2];
        let err = read_frame::<_, Config>(&mut &bytes[..]).await.unwrap_err();
        assert!(matches!(err, FrameError::Io(_)));
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_length() {
        let bytes = (MAX_FRAME_LEN as u32 + 1).to_be_bytes();
        let err = read_frame::<_, Config>(&mut &bytes[..]).await.unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(n) if n == MAX_FRAME_LEN + 1));
    }

    #[tokio::test]
    async fn read_frame_rejects_garbage_cbor() {
        let bytes = [0, 0, 0, 3, 0xff, 0xff, 0xff];
        assert!(matches!(
            read_frame::<_, Config>(&mut &bytes[..]).await,
            Err(FrameError::Decode(_))
        ));
    }

    #[tokio::test]
    async fn unknown_fields_are_ignored() {
        use ciborium::Value;
        let map = Value::Map(vec![
            (Value::Text("generation".into()), Value::Integer(1.into())),
            (Value::Text("listeners".into()), Value::Array(vec![])),
            (Value::Text("future_field".into()), Value::Bool(true)),
        ]);
        let mut buf = Vec::new();
        write_frame(&mut buf, &map).await.unwrap();
        let got: Config = read_frame(&mut &buf[..]).await.unwrap().unwrap();
        assert_eq!(got.generation, 1);
    }
}
