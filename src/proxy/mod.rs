use std::io;
use std::marker::Unpin;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::Socks5Error;

pub mod dummy_proxy;

pub use self::dummy_proxy::DummyProxy;

pub trait Proxy: AsyncRead + AsyncWrite + Unpin + Send {
    fn local_addr(&self) -> Result<SocketAddr, io::Error>;
}

pub struct ProxyManager;

impl ProxyManager {
    pub async fn chose_proxy(
        &self,
        target_addr: &SocketAddr,
    ) -> Result<Box<dyn Proxy>, Socks5Error> {
        let proxy = DummyProxy::create(target_addr).await?;
        // rustc is not smart enought yet. see: https://github.com/rust-lang/rust/pull/64999
        // It will reject the code if we write `Ok(Box::new(proxy))`
        let proxy: Box<dyn Proxy> = Box::new(proxy);
        Ok(proxy)
    }
}
