use async_trait::async_trait;
use std::net::IpAddr;
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::AsyncResolver;

use crate::socks5::Addr;

#[async_trait]
pub trait AsyncResolverExt {
    async fn dns_resolve(&self, addr: &Addr) -> Result<Vec<IpAddr>, ResolveError>;
}

#[async_trait]
impl AsyncResolverExt for AsyncResolver {
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
