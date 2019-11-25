use crate::error::Socks5Error;
use crate::proxy::Proxy;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// A dummy proxy, which does nothing proxying.
pub struct DummyProxy {
    stream: TcpStream,
}

impl DummyProxy {
    pub async fn create(target_addr: SocketAddr) -> Result<DummyProxy, Socks5Error> {
        let stream = TcpStream::connect(target_addr).await?;
        Ok(DummyProxy { stream })
    }
}

impl AsyncRead for DummyProxy {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // rustc will complain if we use `self.stream.poll_read(cx, buf)` directly
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for DummyProxy {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

impl Proxy for DummyProxy {
    fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.stream.local_addr()
    }
}
