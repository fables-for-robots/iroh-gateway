//! `splice` between a loopback TCP socket and one QUIC stream between two loopback endpoints.

use std::{future::Future, io::ErrorKind, time::Duration};

use iroh::{
    Endpoint, EndpointAddr, SecretKey,
    endpoint::{Connection, ReadError, RecvStream, SendStream, VarInt},
};
use iroh_gateway_proto::{
    ALPN, RESET_ABORTED,
    splice::{SpliceEnd, SpliceStats, splice},
    transport::{Relay, Role, endpoint_builder},
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

const TIMEOUT: Duration = Duration::from_secs(30);

async fn within<F: Future>(fut: F) -> F::Output {
    tokio::time::timeout(TIMEOUT, fut).await.expect("timed out")
}

/// Both ends of one connection. The endpoints are kept because dropping one kills its connections.
struct QuicPair {
    near: Connection,
    far: Connection,
    _endpoints: (Endpoint, Endpoint),
}

async fn quic_pair() -> QuicPair {
    let far_ep = endpoint_builder(SecretKey::generate(), 4, &Relay::Disabled, Role::Edge)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap();
    let near_ep = endpoint_builder(SecretKey::generate(), 4, &Relay::Disabled, Role::Operator)
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap();
    let addr = EndpointAddr::new(far_ep.id()).with_ip_addr(far_ep.bound_sockets()[0]);
    let accept = async { far_ep.accept().await.unwrap().await.unwrap() };
    let (near, far) = within(async { tokio::join!(near_ep.connect(addr, ALPN), accept) }).await;
    QuicPair {
        near: near.unwrap(),
        far,
        _endpoints: (near_ep, far_ep),
    }
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (a, b) = tokio::join!(TcpStream::connect(addr), listener.accept());
    (a.unwrap(), b.unwrap().0)
}

/// `tcp_b` spliced with the near ends of one stream; the test drives `tcp_a` and the far ends.
struct Rig {
    tcp_a: TcpStream,
    far_send: SendStream,
    far_recv: RecvStream,
    quic: QuicPair,
    splice: JoinHandle<SpliceStats>,
}

async fn rig() -> Rig {
    let quic = quic_pair().await;
    let (tcp_a, tcp_b) = tcp_pair().await;
    // A stream reaches the peer only once it carries something, so the near side sends a
    // one-byte stand-in for a stream header before splicing.
    let (mut send, recv) = within(quic.near.open_bi()).await.unwrap();
    send.write_all(b"h").await.unwrap();
    let (far_send, mut far_recv) = within(quic.far.accept_bi()).await.unwrap();
    let mut header = [0; 1];
    within(far_recv.read_exact(&mut header)).await.unwrap();
    assert_eq!(&header, b"h");
    let splice = tokio::spawn(splice(tcp_b, send, recv));
    Rig {
        tcp_a,
        far_send,
        far_recv,
        quic,
        splice,
    }
}

fn aborted() -> VarInt {
    VarInt::from_u32(RESET_ABORTED)
}

#[tokio::test]
async fn copies_both_directions() {
    let mut r = rig().await;
    let mut buf = [0; 4];

    r.tcp_a.write_all(b"ping").await.unwrap();
    within(r.far_recv.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"ping");

    r.far_send.write_all(b"pong").await.unwrap();
    within(r.tcp_a.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"pong");

    r.tcp_a.shutdown().await.unwrap();
    r.far_send.finish().unwrap();
    assert_eq!(within(r.far_recv.read_to_end(16)).await.unwrap(), b"");
    assert_eq!(within(r.tcp_a.read(&mut buf)).await.unwrap(), 0);
    let stats = within(r.splice).await.unwrap();
    assert_eq!(stats.end, SpliceEnd::Clean);
    assert_eq!((stats.to_remote, stats.to_local), (4, 4));
}

#[tokio::test]
async fn local_eof_finishes_stream_and_keeps_reading() {
    let mut r = rig().await;

    r.tcp_a.shutdown().await.unwrap();
    assert_eq!(within(r.far_recv.read_to_end(16)).await.unwrap(), b"");

    r.far_send.write_all(b"late").await.unwrap();
    r.far_send.finish().unwrap();
    let mut got = Vec::new();
    within(r.tcp_a.read_to_end(&mut got)).await.unwrap();
    assert_eq!(got, b"late");

    let stats = within(r.splice).await.unwrap();
    assert_eq!(stats.end, SpliceEnd::Clean);
    assert_eq!((stats.to_remote, stats.to_local), (0, 4));
}

#[tokio::test]
async fn remote_finish_shuts_local_write_and_keeps_reading() {
    let mut r = rig().await;
    let mut buf = [0; 8];

    r.far_send.finish().unwrap();
    assert_eq!(within(r.tcp_a.read(&mut buf)).await.unwrap(), 0);

    r.tcp_a.write_all(b"still").await.unwrap();
    r.tcp_a.shutdown().await.unwrap();
    assert_eq!(within(r.far_recv.read_to_end(16)).await.unwrap(), b"still");

    let stats = within(r.splice).await.unwrap();
    assert_eq!(stats.end, SpliceEnd::Clean);
    assert_eq!((stats.to_remote, stats.to_local), (5, 0));
}

#[tokio::test]
async fn local_abort_resets_stream() {
    let mut r = rig().await;
    let mut buf = [0; 8];

    r.tcp_a.set_zero_linger().unwrap();
    drop(r.tcp_a);

    let err = within(r.far_recv.read(&mut buf)).await.unwrap_err();
    assert_eq!(err, ReadError::Reset(aborted()));
    assert_eq!(within(r.far_send.stopped()).await.unwrap(), Some(aborted()));
    assert_eq!(within(r.splice).await.unwrap().end, SpliceEnd::LocalAborted);
}

#[tokio::test]
async fn remote_reset_aborts_local() {
    let mut r = rig().await;
    let mut buf = [0; 8];

    r.far_send.reset(VarInt::from_u32(9)).unwrap();

    let err = within(r.tcp_a.read(&mut buf)).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ConnectionReset);
    // The near send must be reset too: dropping it would have finished it cleanly.
    let err = within(r.far_recv.read(&mut buf)).await.unwrap_err();
    assert_eq!(err, ReadError::Reset(aborted()));
    assert_eq!(within(r.splice).await.unwrap().end, SpliceEnd::RemoteReset);
}

#[tokio::test]
async fn remote_stop_aborts_local() {
    let mut r = rig().await;
    let mut buf = [0; 8];

    r.far_recv.stop(VarInt::from_u32(9)).unwrap();

    let err = within(r.tcp_a.read(&mut buf)).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ConnectionReset);
    assert_eq!(within(r.far_send.stopped()).await.unwrap(), Some(aborted()));
    assert_eq!(within(r.splice).await.unwrap().end, SpliceEnd::RemoteReset);
}

#[tokio::test]
async fn connection_loss_aborts_local() {
    let mut r = rig().await;
    let mut buf = [0; 8];

    r.quic.far.close(0u32.into(), b"bye");

    let err = within(r.tcp_a.read(&mut buf)).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ConnectionReset);
    assert_eq!(
        within(r.splice).await.unwrap().end,
        SpliceEnd::ConnectionLost
    );
}

#[tokio::test]
async fn large_transfer_is_intact() {
    const LEN: usize = 8 << 20;
    let data: Vec<u8> = (0..(LEN / 4) as u32).flat_map(u32::to_le_bytes).collect();
    let expected = Sha256::digest(&data);

    let Rig {
        tcp_a,
        mut far_send,
        mut far_recv,
        quic: _quic,
        splice,
    } = rig().await;

    let echo = tokio::spawn(async move {
        let mut buf = vec![0; 64 << 10];
        while let Some(n) = far_recv.read(&mut buf).await.unwrap() {
            far_send.write_all(&buf[..n]).await.unwrap();
        }
        far_send.finish().unwrap();
    });
    let (mut rd, mut wr) = tcp_a.into_split();
    let writer = tokio::spawn(async move {
        wr.write_all(&data).await.unwrap();
        wr.shutdown().await.unwrap();
    });

    let mut got = Vec::with_capacity(LEN);
    within(rd.read_to_end(&mut got)).await.unwrap();
    within(writer).await.unwrap();
    within(echo).await.unwrap();
    assert_eq!(got.len(), LEN);
    assert_eq!(Sha256::digest(&got), expected);

    let stats = within(splice).await.unwrap();
    assert_eq!(stats.end, SpliceEnd::Clean);
    assert_eq!((stats.to_remote, stats.to_local), (LEN as u64, LEN as u64));
}
