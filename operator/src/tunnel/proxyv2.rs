//! PROXY protocol v2 header encoding.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// Version 2, command PROXY.
const VERSION_PROXY: u8 = 0x21;
const TCP4: u8 = 0x11;
const TCP6: u8 = 0x21;

/// PROXY protocol v2, command PROXY, protocol STREAM. Source is the visitor, destination is `local`.
/// Both IPv4 → family TCP4 (28 bytes). Otherwise both are written as IPv6, an IPv4 address as
/// IPv4-mapped → family TCP6 (52 bytes).
pub fn header(visitor: SocketAddr, local: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(52);
    out.extend_from_slice(&SIGNATURE);
    out.push(VERSION_PROXY);
    match (visitor.ip(), local.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            out.push(TCP4);
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&src.octets());
            out.extend_from_slice(&dst.octets());
        }
        (src, dst) => {
            out.push(TCP6);
            out.extend_from_slice(&36u16.to_be_bytes());
            out.extend_from_slice(&to_v6(src).octets());
            out.extend_from_slice(&to_v6(dst).octets());
        }
    }
    out.extend_from_slice(&visitor.port().to_be_bytes());
    out.extend_from_slice(&local.port().to_be_bytes());
    out
}

fn to_v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_header_bytes() {
        let h = header(
            "198.51.100.9:50000".parse().unwrap(),
            "203.0.113.7:443".parse().unwrap(),
        );
        let mut want = b"\r\n\r\n\x00\r\nQUIT\n".to_vec();
        want.extend([0x21, 0x11, 0x00, 0x0c]);
        want.extend([198, 51, 100, 9, 203, 0, 113, 7]);
        want.extend(50000u16.to_be_bytes());
        want.extend(443u16.to_be_bytes());
        assert_eq!(h, want);
        assert_eq!(h.len(), 28);
    }

    #[test]
    fn v6_header_bytes() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let h = header(
            "[2001:db8::1]:1234".parse().unwrap(),
            "[2001:db8::2]:443".parse().unwrap(),
        );
        let mut want = b"\r\n\r\n\x00\r\nQUIT\n".to_vec();
        want.extend([0x21, 0x21, 0x00, 0x24]);
        want.extend(src.octets());
        want.extend(dst.octets());
        want.extend(1234u16.to_be_bytes());
        want.extend(443u16.to_be_bytes());
        assert_eq!(h.len(), 52);
        assert_eq!(h[13], 0x21);
        assert_eq!(h, want);
    }

    #[test]
    fn mixed_families_become_v6() {
        let h = header(
            "192.0.2.1:1".parse().unwrap(),
            "[2001:db8::2]:443".parse().unwrap(),
        );
        assert_eq!(h.len(), 52);
        assert_eq!(h[13], 0x21);
        let mapped: Ipv6Addr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(&h[16..32], &mapped.octets());
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert_eq!(&h[32..48], &dst.octets());
        assert_eq!(&h[48..50], &1u16.to_be_bytes());
        assert_eq!(&h[50..52], &443u16.to_be_bytes());
    }
}
