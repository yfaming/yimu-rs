use crate::error::{Socks5Error, YimuError};
use crate::framed_ext::FramedExt;
use crate::socks5;
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use dyn_clone::DynClone;
use std::str;
use tokio::codec::{Decoder, Encoder, Framed};
use tokio::net::TcpStream;

#[async_trait]
pub trait Authenticate: DynClone + Sync + Send {
    fn method(&self) -> u8;

    /// authenticate the stream.
    async fn auth(&self, stream: TcpStream) -> Result<TcpStream, YimuError>;
}

#[derive(Debug, Clone, Copy)]
pub struct NoAuth;

#[async_trait]
impl Authenticate for NoAuth {
    fn method(&self) -> u8 {
        socks5::S5AUTH_NO_AUTHENTICATION_REQUIRED
    }

    async fn auth(&self, stream: TcpStream) -> Result<TcpStream, YimuError> {
        Ok(stream)
    }
}

/// [RFC1929: Username/Password Authentication for SOCKS V5](https://tools.ietf.org/html/rfc1929)
#[derive(Clone)]
pub struct UsernamePasswordAuth {
    username: String,
    password: String,
}

impl UsernamePasswordAuth {
    pub fn new(username: String, password: String) -> UsernamePasswordAuth {
        UsernamePasswordAuth { username, password }
    }
}

#[async_trait]
impl Authenticate for UsernamePasswordAuth {
    fn method(&self) -> u8 {
        socks5::S5AUTH_USERNAME_PASSWORD
    }

    async fn auth(&self, stream: TcpStream) -> Result<TcpStream, YimuError> {
        let mut transport = Framed::new(stream, UsernamePasswordAuthCodec);
        let req = transport.framed_read().await?;

        if req.username == self.username && req.password == self.password {
            let res = UsernamePasswordAuthResponse::success();
            transport.framed_write(res).await?;
            Ok(transport.into_inner())
        } else {
            let res = UsernamePasswordAuthResponse::fail();
            transport.framed_write(res).await?;
            Err(Socks5Error::AuthFailed.into())
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UsernamePasswordAuthRequest {
    pub username: String,
    pub password: String,
}

impl UsernamePasswordAuthRequest {
    pub fn new(username: &str, password: &str) -> UsernamePasswordAuthRequest {
        UsernamePasswordAuthRequest {
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UsernamePasswordAuthResponse {
    pub version: u8,
    pub status: u8,
}

impl UsernamePasswordAuthResponse {
    const STATUS_SUCCESS: u8 = 0;
    const STATUS_FAIL: u8 = 1;

    pub fn success() -> UsernamePasswordAuthResponse {
        UsernamePasswordAuthResponse {
            version: socks5::SOCKSV5,
            status: Self::STATUS_SUCCESS,
        }
    }
    pub fn fail() -> UsernamePasswordAuthResponse {
        UsernamePasswordAuthResponse {
            version: socks5::SOCKSV5,
            status: Self::STATUS_FAIL,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UsernamePasswordAuthCodec;

impl Decoder for UsernamePasswordAuthCodec {
    type Item = UsernamePasswordAuthRequest;
    type Error = Socks5Error;

    // +----+------+----------+------+----------+
    // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    // +----+------+----------+------+----------+
    // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    // +----+------+----------+------+----------+
    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<UsernamePasswordAuthRequest>, Socks5Error> {
        // VER + ULEN
        if src.len() <= 2 {
            return Ok(None);
        }

        let ulen = src[1] as usize;
        // VER + ULEN + UNAME + PLEN
        if src.len() < 3 + ulen {
            return Ok(None);
        }

        let plen = src[2 + ulen] as usize;
        // VER + ULEN + UNAME + PLEN + PASSWD
        if src.len() < 3 + ulen + plen {
            return Ok(None);
        }

        let uname = str::from_utf8(&src[2..2 + ulen]).map_err(|_| Socks5Error::invalid_data())?;
        let passwd_start = 3 + ulen;
        let passwd = str::from_utf8(&src[passwd_start..passwd_start + plen])
            .map_err(|_| Socks5Error::invalid_data())?;
        Ok(Some(UsernamePasswordAuthRequest::new(uname, passwd)))
    }
}

impl Encoder for UsernamePasswordAuthCodec {
    type Item = UsernamePasswordAuthResponse;
    type Error = Socks5Error;

    fn encode(
        &mut self,
        item: UsernamePasswordAuthResponse,
        dst: &mut BytesMut,
    ) -> Result<(), Socks5Error> {
        dst.reserve(2);
        dst.put_u8(item.version);
        dst.put_u8(item.status);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_username_password_auth_request() -> Result<(), Socks5Error> {
        let raw: &[u8] = b"\x05\x08username\x08password";
        let mut buf = BytesMut::from(raw);
        let req = UsernamePasswordAuthCodec.decode(&mut buf)?;
        assert_eq!(
            req,
            Some(UsernamePasswordAuthRequest::new("username", "password"))
        );
        Ok(())
    }

    #[test]
    fn test_encode_username_password_auth_response() -> Result<(), Socks5Error> {
        let reply = UsernamePasswordAuthResponse::success();
        let mut buf = BytesMut::new();
        UsernamePasswordAuthCodec.encode(reply, &mut buf)?;
        assert_eq!(buf.as_ref(), b"\x05\x00");
        Ok(())
    }
}
