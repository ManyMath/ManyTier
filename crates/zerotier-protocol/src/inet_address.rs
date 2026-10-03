/// InetAddress: IPv4/IPv6/Null address with ZeroTier wire format serialization.
///
/// - Null: `[0x00]` (1 byte)
/// - IPv4: `[0x04][ip:4][port:2]` (7 bytes, port big-endian)
/// - IPv6: `[0x06][ip:16][port:2]` (19 bytes, port big-endian)
use crate::error::ProtocolError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InetAddress {
    Null,
    V4 { ip: [u8; 4], port: u16 },
    V6 { ip: [u8; 16], port: u16 },
}

impl InetAddress {
    /// Serialize this address into `buf`. Returns the number of bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        match self {
            InetAddress::Null => {
                buf[0] = 0x00;
                1
            }
            InetAddress::V4 { ip, port } => {
                buf[0] = 0x04;
                buf[1..5].copy_from_slice(ip);
                buf[5..7].copy_from_slice(&port.to_be_bytes());
                7
            }
            InetAddress::V6 { ip, port } => {
                buf[0] = 0x06;
                buf[1..17].copy_from_slice(ip);
                buf[17..19].copy_from_slice(&port.to_be_bytes());
                19
            }
        }
    }

    /// Deserialize an address from `data`. Returns the address and bytes consumed.
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), ProtocolError> {
        if data.is_empty() {
            return Err(ProtocolError::TooShort { need: 1, got: 0 });
        }
        match data[0] {
            0x00 => Ok((InetAddress::Null, 1)),
            0x04 => {
                if data.len() < 7 {
                    return Err(ProtocolError::TooShort {
                        need: 7,
                        got: data.len(),
                    });
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&data[1..5]);
                let port = u16::from_be_bytes([data[5], data[6]]);
                Ok((InetAddress::V4 { ip, port }, 7))
            }
            0x06 => {
                if data.len() < 19 {
                    return Err(ProtocolError::TooShort {
                        need: 19,
                        got: data.len(),
                    });
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&data[1..17]);
                let port = u16::from_be_bytes([data[17], data[18]]);
                Ok((InetAddress::V6 { ip, port }, 19))
            }
            // Types ZeroTier One reserves for future use and accepts by
            // skipping them (InetAddress::deserialize): 0x01/0x02 are seven
            // bytes, 0x03 carries its own u16 length.
            0x01 | 0x02 if data.len() >= 7 => Ok((InetAddress::Null, 7)),
            0x03 if data.len() >= 3 => {
                let used = 3 + u16::from_be_bytes([data[1], data[2]]) as usize;
                if data.len() < used {
                    return Err(ProtocolError::TooShort {
                        need: used,
                        got: data.len(),
                    });
                }
                Ok((InetAddress::Null, used))
            }
            _ => Err(ProtocolError::InvalidPacket),
        }
    }

    /// Convert to a `core::net::SocketAddr`, if not null.
    pub fn to_socket_addr(&self) -> Option<core::net::SocketAddr> {
        match self {
            InetAddress::Null => None,
            InetAddress::V4 { ip, port } => Some(core::net::SocketAddr::V4(
                core::net::SocketAddrV4::new(core::net::Ipv4Addr::from(*ip), *port),
            )),
            InetAddress::V6 { ip, port } => Some(core::net::SocketAddr::V6(
                core::net::SocketAddrV6::new(core::net::Ipv6Addr::from(*ip), *port, 0, 0),
            )),
        }
    }

    /// Create from a `core::net::SocketAddr`.
    pub fn from_socket_addr(addr: core::net::SocketAddr) -> Self {
        match addr {
            core::net::SocketAddr::V4(v4) => InetAddress::V4 {
                ip: v4.ip().octets(),
                port: v4.port(),
            },
            core::net::SocketAddr::V6(v6) => InetAddress::V6 {
                ip: v6.ip().octets(),
                port: v6.port(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn null_roundtrip() {
        let mut buf = [0u8; 32];
        let n = InetAddress::Null.serialize(&mut buf);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x00);
        let (addr, consumed) = InetAddress::deserialize(&buf[..n]).unwrap();
        assert_eq!(addr, InetAddress::Null);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn v4_roundtrip() {
        let addr = InetAddress::V4 {
            ip: [192, 168, 1, 1],
            port: 9993,
        };
        let mut buf = [0u8; 32];
        let n = addr.serialize(&mut buf);
        assert_eq!(n, 7);
        assert_eq!(buf[0], 0x04);
        let (parsed, consumed) = InetAddress::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, addr);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn v6_roundtrip() {
        let addr = InetAddress::V6 {
            ip: [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ],
            port: 443,
        };
        let mut buf = [0u8; 32];
        let n = addr.serialize(&mut buf);
        assert_eq!(n, 19);
        assert_eq!(buf[0], 0x06);
        let (parsed, consumed) = InetAddress::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, addr);
        assert_eq!(consumed, 19);
    }

    #[test]
    fn deserialize_too_short_v4() {
        let data = [0x04, 0x01, 0x02]; // only 3 bytes after type
        assert!(InetAddress::deserialize(&data).is_err());
    }

    #[test]
    fn deserialize_too_short_v6() {
        let data = [0x06; 10]; // only 10 bytes total, need 19
        assert!(InetAddress::deserialize(&data).is_err());
    }

    #[test]
    fn deserialize_empty() {
        assert!(InetAddress::deserialize(&[]).is_err());
    }

    #[test]
    fn to_socket_addr_v4() {
        let addr = InetAddress::V4 {
            ip: [127, 0, 0, 1],
            port: 8080,
        };
        let sa = addr.to_socket_addr().unwrap();
        assert_eq!(sa.to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn to_socket_addr_v6() {
        let addr = InetAddress::V6 {
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: 443,
        };
        let sa = addr.to_socket_addr().unwrap();
        assert_eq!(sa.to_string(), "[::1]:443");
    }

    #[test]
    fn to_socket_addr_null() {
        assert!(InetAddress::Null.to_socket_addr().is_none());
    }

    #[test]
    fn from_socket_addr_v4() {
        let sa: core::net::SocketAddr = "10.0.0.1:9993".parse().unwrap();
        let addr = InetAddress::from_socket_addr(sa);
        assert_eq!(
            addr,
            InetAddress::V4 {
                ip: [10, 0, 0, 1],
                port: 9993,
            }
        );
    }

    #[test]
    fn from_socket_addr_v6() {
        let sa: core::net::SocketAddr = "[::1]:443".parse().unwrap();
        let addr = InetAddress::from_socket_addr(sa);
        assert!(matches!(addr, InetAddress::V6 { port: 443, .. }));
    }

    #[test]
    fn port_big_endian_encoding() {
        let addr = InetAddress::V4 {
            ip: [0; 4],
            port: 0x1234,
        };
        let mut buf = [0u8; 7];
        addr.serialize(&mut buf);
        assert_eq!(buf[5], 0x12);
        assert_eq!(buf[6], 0x34);
    }

    /// Reserved address types are skipped, not rejected, so a peer sending
    /// a newer type does not break the whole message.
    #[test]
    fn reserved_address_types_are_skipped() {
        assert_eq!(
            InetAddress::deserialize(&[0x01, 1, 2, 3, 4, 5, 6, 0xaa]).unwrap(),
            (InetAddress::Null, 7)
        );
        assert_eq!(
            InetAddress::deserialize(&[0x03, 0, 2, 9, 9, 0xaa]).unwrap(),
            (InetAddress::Null, 5)
        );
        assert!(InetAddress::deserialize(&[0x03, 0, 9, 1]).is_err());
        assert!(InetAddress::deserialize(&[0x05]).is_err());
    }
}
