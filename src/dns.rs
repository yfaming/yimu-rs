use crate::error::YimuError;
use crate::socks5::Addr;
use async_trait::async_trait;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::TokioAsyncResolver;

#[async_trait]
pub trait AsyncResolverExt {
    async fn dns_resolve(&self, addr: &Addr) -> Result<Vec<IpAddr>, ResolveError>;
}

#[async_trait]
impl AsyncResolverExt for TokioAsyncResolver {
    async fn dns_resolve(&self, addr: &Addr) -> Result<Vec<IpAddr>, ResolveError> {
        match addr {
            Addr::Ip(ip) => Ok(vec![*ip]),
            Addr::Domain(domain) => Ok(self
                .lookup_ip(domain.as_str())
                .await?
                .iter()
                .collect::<Vec<IpAddr>>()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Dns {
    System,
    Google,
    Cloudflare,
    Quad9,
    NameServer(SocketAddr),
}

impl Dns {
    pub fn new() -> Dns {
        Dns::System
    }

    pub async fn create_resolver(&self) -> Result<TokioAsyncResolver, YimuError> {
        let opts = ResolverOpts::default();
        let resolver = match self {
            Dns::System => TokioAsyncResolver::tokio_from_system_conf().await?,
            Dns::Google => TokioAsyncResolver::tokio(ResolverConfig::google(), opts).await?,
            Dns::Cloudflare => {
                TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts).await?
            }
            Dns::Quad9 => TokioAsyncResolver::tokio(ResolverConfig::quad9(), opts).await?,
            Dns::NameServer(socket_addr) => {
                let mut config = ResolverConfig::new();
                config.add_name_server(NameServerConfig {
                    socket_addr: *socket_addr,
                    protocol: Protocol::Udp,
                    tls_dns_name: None,
                });
                TokioAsyncResolver::tokio(config, opts).await?
            }
        };
        Ok(resolver)
    }
}

#[derive(Debug)]
pub struct ParseDnsError;

impl FromStr for Dns {
    type Err = ParseDnsError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "system" => {
                return Ok(Dns::System);
            }
            "google" => {
                return Ok(Dns::Google);
            }
            "cloudflare" => {
                return Ok(Dns::Cloudflare);
            }
            "quad9" => {
                return Ok(Dns::Quad9);
            }
            _ => {}
        }

        if let Ok(socket_addr) = SocketAddr::from_str(s) {
            return Ok(Dns::NameServer(socket_addr));
        }
        if let Ok(ip) = IpAddr::from_str(s) {
            let socket_addr = SocketAddr::from((ip, 53));
            return Ok(Dns::NameServer(socket_addr));
        }
        return Err(ParseDnsError);
    }
}

impl Display for ParseDnsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "parse dns error")
    }
}

impl Error for ParseDnsError {}
