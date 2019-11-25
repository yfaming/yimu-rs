use crate::error::YimuError;
use log::info;
use std::io;
use std::marker::Unpin;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod demux_proxy;
pub mod dummy_proxy;

use crate::proxy::demux_proxy::MuxManager;
use crate::proxy::dummy_proxy::DummyProxy;

pub trait Proxy: AsyncRead + AsyncWrite + Unpin + Send {
    // Maybe remove this method...
    fn local_addr(&self) -> Result<SocketAddr, io::Error>;
}

#[derive(Debug)]
pub struct ProxyManager {
    mux_manager: MuxManager,
}

impl ProxyManager {
    pub async fn create() -> Result<ProxyManager, YimuError> {
        // let demux_remote_addr = "45.76.232.203:4350".parse::<SocketAddr>()?;
        let demux_remote_addr = "127.0.0.1:4350".parse::<SocketAddr>()?;
        let mux_manager = MuxManager::create(demux_remote_addr).await?;
        Ok(ProxyManager { mux_manager })
    }

    pub async fn choose_proxy(
        &mut self,
        target_addr: SocketAddr,
    ) -> Result<Box<dyn Proxy>, YimuError> {
        self.create_demux_proxy(target_addr).await
    }

    pub async fn create_dummy_proxy(
        &mut self,
        target_addr: SocketAddr,
    ) -> Result<Box<dyn Proxy>, YimuError> {
        let proxy = DummyProxy::create(target_addr).await?;
        // rustc is not smart enought yet. see: https://github.com/rust-lang/rust/pull/64999
        // It will reject the code if we write `Ok(Box::new(proxy))`
        let proxy: Box<dyn Proxy> = Box::new(proxy);
        Ok(proxy)
    }

    async fn create_demux_proxy(
        &mut self,
        target_addr: SocketAddr,
    ) -> Result<Box<dyn Proxy>, YimuError> {
        info!("enter create_demu_proxy");
        let proxy = self.mux_manager.create_proxy(target_addr).await?;
        let proxy: Box<dyn Proxy> = Box::new(proxy);
        Ok(proxy)
    }
}
