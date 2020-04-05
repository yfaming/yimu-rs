use crate::error::Socks5Error;
use bytes::{BufMut, BytesMut};
use std::convert::TryFrom;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str;
use tokio::codec::{Decoder, Encoder};

pub const SOCKSV5: u8 = 5;

pub const S5AUTH_NO_AUTHENTICATION_REQUIRED: u8 = 0;
pub const S5AUTH_GSSAPI: u8 = 1;
pub const S5AUTH_USERNAME_PASSWORD: u8 = 2;
pub const S5AUTH_NO_ACCEPTABLE_METHODS: u8 = 255;

#[derive(Debug, Clone, PartialEq)]
pub struct AuthNegoRequest {
    pub version: u8,
    pub nmethods: u8,
    pub methods: Vec<u8>,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct AuthNegoReply {
    pub version: u8,
    pub method: u8,
}
impl AuthNegoReply {
    pub fn new(method: u8) -> AuthNegoReply {
        AuthNegoReply {
            version: SOCKSV5,
            method,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NegotiateCodec;

impl Decoder for NegotiateCodec {
    type Item = AuthNegoRequest;
    type Error = Socks5Error;

    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<AuthNegoRequest>, Socks5Error> {
        if src.len() >= 2 && src.len() >= src[1] as usize + 2 {
            let nmethods = src[1];
            let req = AuthNegoRequest {
                version: src[0],
                nmethods: nmethods,
                methods: Vec::from(&src[2..2 + nmethods as usize]),
            };
            src.advance(2 + nmethods as usize);
            return Ok(Some(req));
        }
        Ok(None)
    }
}

impl Encoder for NegotiateCodec {
    type Item = AuthNegoReply;
    type Error = Socks5Error;

    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+
    fn encode(&mut self, item: AuthNegoReply, dst: &mut BytesMut) -> Result<(), Socks5Error> {
        dst.reserve(2);
        dst.put_u8(item.version);
        dst.put_u8(item.method);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Cmd {
    Connect = 1,
    Bind = 2,
    UdpAssociate = 3,
}

impl TryFrom<u8> for Cmd {
    type Error = Socks5Error;

    fn try_from(value: u8) -> Result<Cmd, Socks5Error> {
        match value {
            1 => Ok(Cmd::Connect),
            2 => Ok(Cmd::Bind),
            3 => Ok(Cmd::UdpAssociate),
            _ => Err(Socks5Error::InvalidCmd(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AddrType {
    V4 = 1,
    Domain = 3,
    V6 = 4,
}

impl TryFrom<u8> for AddrType {
    type Error = Socks5Error;
    fn try_from(value: u8) -> Result<AddrType, Socks5Error> {
        match value {
            1 => Ok(AddrType::V4),
            3 => Ok(AddrType::Domain),
            4 => Ok(AddrType::V6),
            _ => Err(Socks5Error::InvalidAddrType(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Addr {
    Ip(IpAddr),
    Domain(String),
}

impl Addr {
    pub fn addr_type(&self) -> AddrType {
        use Addr::*;
        match self {
            Ip(IpAddr::V4(_)) => AddrType::V4,
            Ip(IpAddr::V6(_)) => AddrType::V6,
            Domain(_) => AddrType::Domain,
        }
    }

    pub fn wire_len(&self) -> usize {
        use Addr::*;
        match self {
            Ip(IpAddr::V4(_)) => 4,
            Ip(IpAddr::V6(_)) => 16,
            Domain(domain) => domain.len() + 1,
        }
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            Addr::Ip(ipaddr) => ipaddr.fmt(f),
            Addr::Domain(domain) => domain.fmt(f),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub version: u8,
    pub cmd: Cmd,
    pub rsv: u8,
    pub dest_addr: Addr,
    pub dest_port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub version: u8,
    pub reply_code: u8,
    pub rsv: u8,
    pub bind_addr: Addr,
    pub bind_port: u16,
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self.cmd {
            Cmd::Connect => write!(f, "CONNECT {}:{}", self.dest_addr, self.dest_port),
            Cmd::Bind => write!(f, "BIND"),
            Cmd::UdpAssociate => write!(f, "UDP ASSOCIATE"),
        }
    }
}

// reply code
pub const REP_SUCCEEDED: u8 = 0;
pub const REP_GENERAL_FAILURE: u8 = 1;
pub const REP_CONNECTION_NOT_ALLOWED: u8 = 2;
pub const REP_NETWORK_UNREACHABLE: u8 = 3;
pub const REP_HOST_UNREACHABLE: u8 = 4;
pub const REP_CONNECTION_REFUSED: u8 = 5;
pub const REP_TTL_EXPIRED: u8 = 6;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 7;
pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 8;
// 9 - 255 not assigned

pub fn socks5_error_to_reply_code(e: &Socks5Error) -> u8 {
    use Socks5Error::*;
    match e {
        InvalidCmd(_) => REP_COMMAND_NOT_SUPPORTED,
        InvalidAddrType(_) => REP_ADDRESS_TYPE_NOT_SUPPORTED,
        _ => REP_GENERAL_FAILURE,
    }
}

impl Reply {
    pub fn new(code: u8, sockaddr: SocketAddr) -> Reply {
        Reply {
            version: SOCKSV5,
            reply_code: code,
            rsv: 0,
            bind_addr: Addr::Ip(sockaddr.ip()),
            bind_port: sockaddr.port(),
        }
    }
}

impl From<Socks5Error> for Reply {
    fn from(e: Socks5Error) -> Reply {
        let code = socks5_error_to_reply_code(&e);
        let sockaddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        Reply::new(code, sockaddr)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Socks5Codec;

impl Decoder for Socks5Codec {
    type Item = Request;
    type Error = Socks5Error;

    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Request>, Socks5Error> {
        // ver(1) + cmd(1) + rsv(1) + atyp(1) = 4
        // If atyp=3(domain name), we have to inspect extra byte to get domain name length.
        if src.len() <= 5 {
            return Ok(None);
        }

        let addr_type = AddrType::try_from(src[3])?;
        // req_len: ver(1) + cmd(1) + rsv(1) + atyp(1) + len_of_addr + dst.port(2)
        // for AddrType::Domain, the 1st byte of DST.ADDR is length of domain
        let (addr_start, addr_len, req_len): (usize, usize, usize) = match addr_type {
            AddrType::V4 => (4, 4, 10),
            AddrType::V6 => (4, 16, 22),
            AddrType::Domain => (5, src[4] as usize, 6 + src[4] as usize + 1),
        };
        if src.len() < req_len {
            return Ok(None);
        }

        let addr_raw: &[u8] = &src[addr_start..addr_start + addr_len];
        let addr = match addr_type {
            AddrType::V4 => {
                let octets = <[u8; 4]>::try_from(addr_raw).expect("unreachable");
                Addr::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
            }
            AddrType::V6 => {
                let octets = <[u8; 16]>::try_from(addr_raw).expect("unreachable");
                Addr::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            AddrType::Domain => {
                let domain = str::from_utf8(addr_raw)
                    .map_err(|_| Socks5Error::invalid_data())?
                    .to_string();
                Addr::Domain(domain)
            }
        };

        let port_start = addr_start + addr_len;
        let port_raw: [u8; 2] = [src[port_start], src[port_start + 1]];
        let port: u16 = u16::from_be_bytes(port_raw);

        let req = Request {
            version: src[0],
            cmd: Cmd::try_from(src[1])?,
            rsv: src[2],
            dest_addr: addr,
            dest_port: port,
        };
        src.advance(req_len);

        Ok(Some(req))
    }
}

impl Encoder for Socks5Codec {
    type Item = Reply;
    type Error = Socks5Error;

    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    fn encode(&mut self, item: Reply, dst: &mut BytesMut) -> Result<(), Socks5Error> {
        // ver(1) + rep(1) + rsv(1) + atyp(1) + BIND.ADDR.wire_len + port(2)
        dst.reserve(6 + item.bind_addr.wire_len());
        dst.put_u8(item.version);
        dst.put_u8(item.reply_code);
        dst.put_u8(item.rsv);
        dst.put_u8(item.bind_addr.addr_type() as u8);

        match item.bind_addr {
            Addr::Ip(IpAddr::V4(ipv4)) => dst.put_slice(&ipv4.octets()),
            Addr::Ip(IpAddr::V6(ipv6)) => dst.put_slice(&ipv6.octets()),
            Addr::Domain(domain) => {
                if domain.len() > u8::max_value() as usize {
                    return Err(Socks5Error::InvalidDomainName);
                }
                // extra 1 byte to indicate domain length
                dst.put_u8(domain.len() as u8);
                dst.put_slice(domain.as_bytes());
            }
        }
        dst.put_u16_be(item.bind_port);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_auth_negotiation_request() -> Result<(), Socks5Error> {
        let raw: &[u8] = b"\x05\x01\x00";
        let mut buf = BytesMut::from(raw);
        let req = NegotiateCodec.decode(&mut buf)?;
        assert_eq!(
            req,
            Some(AuthNegoRequest {
                version: 5,
                nmethods: 1,
                methods: vec![S5AUTH_NO_AUTHENTICATION_REQUIRED],
            })
        );
        assert!(buf.is_empty());
        Ok(())
    }

    #[test]
    fn test_encode_auth_negotiation_reply() -> Result<(), Socks5Error> {
        let reply = AuthNegoReply {
            version: 5,
            method: S5AUTH_NO_AUTHENTICATION_REQUIRED,
        };
        let mut buf = BytesMut::new();
        NegotiateCodec.encode(reply, &mut buf)?;
        assert_eq!(buf.as_ref(), b"\x05\x00");
        Ok(())
    }

    #[test]
    fn test_decode_request() -> Result<(), Socks5Error> {
        let raw: &[u8] = b"\x05\x01\x00\x03\x07\x61\x62\x63\x2e\x63\x6f\x6d\x04\x00";
        let mut buf = BytesMut::from(raw);
        let req = Socks5Codec.decode(&mut buf)?;
        assert_eq!(
            req,
            Some(Request {
                version: 5,
                cmd: Cmd::Connect,
                rsv: 0,
                dest_addr: Addr::Domain("abc.com".to_string()),
                dest_port: 1024,
            })
        );
        assert!(buf.is_empty());
        Ok(())
    }

    #[test]
    fn test_encode_reply() -> Result<(), Socks5Error> {
        let reply = Reply {
            version: 5,
            reply_code: REP_SUCCEEDED,
            rsv: 0,
            bind_addr: Addr::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 8))),
            bind_port: 3306,
        };
        let mut buf = BytesMut::new();
        Socks5Codec.encode(reply, &mut buf)?;
        assert_eq!(buf.as_ref(), b"\x05\x00\x00\x01\xc0\xa8\x00\x08\x0c\xea");
        Ok(())
    }
}
