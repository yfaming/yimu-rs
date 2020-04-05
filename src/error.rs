use std::fmt;
use std::io;
use trust_dns_resolver::error::ResolveError;

pub type YimuError = failure::Error;

#[derive(Debug)]
pub enum Socks5Error {
    AuthFailed,
    InvalidCmd(u8),
    InvalidAddrType(u8),
    InvalidDomainName,
    ResolveError(ResolveError),
    Io(io::Error),
}

impl Socks5Error {
    pub fn invalid_data() -> Socks5Error {
        Socks5Error::Io(io::Error::from(io::ErrorKind::InvalidData))
    }
}

impl fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Socks5Error {}

impl From<io::Error> for Socks5Error {
    fn from(e: io::Error) -> Socks5Error {
        Socks5Error::Io(e)
    }
}

impl From<ResolveError> for Socks5Error {
    fn from(e: ResolveError) -> Socks5Error {
        Socks5Error::ResolveError(e)
    }
}
