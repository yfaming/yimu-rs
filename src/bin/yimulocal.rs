use futures::future::try_join;
use futures_util::future::FutureExt;
use log::{error, info};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::codec::Framed;
use tokio::io::{split, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Builder;
use tokio::sync::Mutex;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::AsyncResolver;
use yimu::dns::AsyncResolverExt;
use yimu::error::{Socks5Error, YimuError};
use yimu::framed_ext::{FramedExt, FramedExt2};
use yimu::proxy::{Proxy, ProxyManager};
use yimu::socks5::{AuthNegotiationReply, NegotiateCodec, REP_SUCCEEDED};
use yimu::socks5::{Cmd, Reply, Request, Socks5Codec, S5AUTH_NO_AUTHENTICATION_REQUIRED, SOCKSV5};

fn main() -> Result<(), YimuError> {
    env_logger::init();
    let rt = Builder::new().core_threads(1).build()?;

    rt.block_on(run())?;

    Ok(())
}

async fn run() -> Result<(), YimuError> {
    let addr = "0.0.0.0:9011";
    let mut listener = TcpListener::bind(addr).await?;
    info!("listening on: {}", addr);

    let (resolver, fut) = AsyncResolver::new(ResolverConfig::google(), ResolverOpts::default());
    tokio::spawn(fut);

    let proxy_manager = ProxyManager::create().await?;
    let proxy_manager = Arc::new(Mutex::new(proxy_manager));

    loop {
        let (stream, _sockaddr) = listener.accept().await?;

        let resolver = resolver.clone();
        let proxy_manager = proxy_manager.clone();
        tokio::spawn(handle(stream, resolver, proxy_manager).map(|result| {
            if let Err(e) = result {
                error!("{}", e);
            }
        }));
    }
}

async fn handle_socks5_request(
    req: &Request,
    resolver: &AsyncResolver,
    proxy_manager: Arc<Mutex<ProxyManager>>,
) -> Result<Box<dyn Proxy>, Socks5Error> {
    if req.cmd != Cmd::Connect {
        return Err(Socks5Error::InvalidCmd(req.cmd as u8));
    }

    let remote_ips = resolver.dns_resolve(&req.dest_addr).await?;
    if remote_ips.is_empty() {
        return Err(Socks5Error::from(ResolveError::from(
            "no DNS records found",
        )));
    }
    let remote_sockaddr = SocketAddr::new(remote_ips[0], req.dest_port);

    let mut proxy_manager = proxy_manager.lock().await;
    let proxy = proxy_manager
        .choose_proxy(remote_sockaddr)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "choose_proxy failure"))?;
    Ok(proxy)
}

async fn handle(
    stream: TcpStream,
    resolver: AsyncResolver,
    proxy_manager: Arc<Mutex<ProxyManager>>,
) -> Result<(), YimuError> {
    // negotiation
    let mut transport = Framed::new(stream, NegotiateCodec);
    let _auth_nego_req = transport.framed_read().await?;
    let auth_nego_res = AuthNegotiationReply {
        version: SOCKSV5,
        method: S5AUTH_NO_AUTHENTICATION_REQUIRED,
    };
    transport.framed_write(auth_nego_res).await?;

    // request process
    let mut transport = transport.replace_codec(Socks5Codec);
    let req = transport.framed_read().await?;
    info!("{:?}", req);
    let proxy = match handle_socks5_request(&req, &resolver, proxy_manager).await {
        Ok(proxy) => {
            let unspecified_sockaddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            let local_addr = proxy.local_addr().unwrap_or(unspecified_sockaddr);
            let reply = Reply::new(REP_SUCCEEDED, local_addr);
            info!("{:?}", reply);
            transport.framed_write(reply).await?;
            proxy
        }
        Err(e) => {
            let reply = Reply::from(&e);
            info!("{:?}", reply);
            transport.framed_write(reply).await?;
            return Ok(());
        }
    };

    // now do proxy
    let mut stream = transport.into_inner();
    let (mut ri, mut wi) = stream.split();
    let (mut ro, mut wo) = split(proxy);

    let client_to_server = ri.copy(&mut wo);
    let server_to_client = ro.copy(&mut wi);

    try_join(client_to_server, server_to_client).await?;
    Ok(())
}
