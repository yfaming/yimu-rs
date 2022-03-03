use std::io;
use thiserror::Error;
use trust_dns_resolver::error::ResolveError;

pub type YimuError = anyhow::Error;

#[derive(Debug, Error)]
pub enum Socks5Error {
    #[error("auth failed")]
    AuthFailed,
    #[error("invalid cmd: {0}")]
    InvalidCmd(u8),
    #[error("invalid address type: {0}")]
    InvalidAddrType(u8),
    #[error("invalid domain name")]
    InvalidDomainName,
    #[error("resolve error: {0}")]
    ResolveError(#[from] ResolveError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

impl Socks5Error {
    pub fn invalid_data() -> Socks5Error {
        Socks5Error::Io(io::Error::from(io::ErrorKind::InvalidData))
    }
}
