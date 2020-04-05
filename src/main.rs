use dyn_clone::clone_box;
use futures::future::try_join;
use futures_util::future::FutureExt;
use log::{error, info};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::codec::Framed;
use tokio::io::{split, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::AsyncResolver;
use yimu::auth::{Authenticate, NoAuth, UsernamePasswordAuth};
use yimu::dns::AsyncResolverExt;
use yimu::error::{Socks5Error, YimuError};
use yimu::framed_ext::FramedExt;
use yimu::socks5::{AuthNegoReply, AuthNegoRequest, NegotiateCodec, REP_SUCCEEDED};
use yimu::socks5::{Cmd, Reply, Request, Socks5Codec, S5AUTH_NO_ACCEPTABLE_METHODS};

#[tokio::main(multi_thread)]
async fn main() -> Result<(), YimuError> {
    env_logger::init();

    let server = Server::new(State::new());
    server.run().await?;
    Ok(())
}

pub struct State {
    resolver: AsyncResolver,
    listen_addr: SocketAddr,
    authenticators: Vec<Box<dyn Authenticate + Send + Sync + 'static>>,
}

impl State {
    pub fn new() -> State {
        // TODO: 如何处理 fut???
        let (resolver, fut) = AsyncResolver::new(ResolverConfig::google(), ResolverOpts::default());
        tokio::spawn(fut);
        let sock_addr = "0.0.0.0:9011".parse::<SocketAddr>().unwrap();
        let authenticators: Vec<Box<dyn Authenticate + Send + Sync + 'static>> = vec![
            Box::new(NoAuth),
            Box::new(UsernamePasswordAuth::new(
                "yfaming".to_string(),
                "yfaming".to_string(),
            )),
        ];
        State {
            resolver,
            listen_addr: sock_addr,
            authenticators,
        }
    }

    pub fn resolver(&self) -> AsyncResolver {
        self.resolver.clone()
    }

    pub fn add_authenticator<T: Authenticate + 'static>(&mut self, authenticator: T)
    where
        T: Authenticate + Send + Sync + 'static,
    {
        self.authenticators.push(Box::new(authenticator));
    }

    pub fn authenticator(&self, auth_nego_req: &AuthNegoRequest) -> Option<Box<dyn Authenticate>> {
        for auth in &self.authenticators {
            for method in &auth_nego_req.methods {
                if auth.method() == *method {
                    return Some(clone_box(auth.as_ref()));
                }
            }
        }
        None
    }
}

pub struct Server {
    state: Arc<State>,
}

impl Server {
    pub fn new(state: State) -> Server {
        Server {
            state: Arc::new(state),
        }
    }

    pub async fn run(&self) -> Result<(), io::Error> {
        let listen_addr = self.state.listen_addr;
        let mut listener = TcpListener::bind(listen_addr).await?;
        info!("listening on: {}", listen_addr);

        loop {
            if let Ok((stream, client_addr)) = listener.accept().await {
                info!("new client: {}", client_addr);
                tokio::spawn(handle(stream, client_addr, self.state.clone()).map(|_| {}));
            }
        }
    }
}

async fn handle(
    stream: TcpStream,
    client_addr: SocketAddr,
    state: Arc<State>,
) -> Result<(), YimuError> {
    // negotiation and authentication
    let mut transport = Framed::new(stream, NegotiateCodec);
    let auth_nego_req = transport.framed_read().await?;
    let stream = match state.authenticator(&auth_nego_req) {
        Some(authenticator) => {
            let auth_nego_res = AuthNegoReply::new(authenticator.method());
            transport.framed_write(auth_nego_res).await?;
            authenticator.auth(transport.into_inner()).await?
        }
        None => {
            info!("no acceptable auth method for client {}", client_addr);
            let auth_nego_res = AuthNegoReply::new(S5AUTH_NO_ACCEPTABLE_METHODS);
            transport.framed_write(auth_nego_res).await?;
            return Ok(());
        }
    };

    // request process
    let mut transport = Framed::new(stream, Socks5Codec);
    let req = transport.framed_read().await?;
    info!("client {}, request: {}", client_addr, req);
    let (remote_stream, reply) = match handle_request(client_addr, &req, &state.resolver()).await {
        Ok((remote_stream, reply)) => (remote_stream, reply),
        Err(e) => {
            transport.framed_write(Reply::from(e)).await?;
            return Ok(());
        }
    };
    transport.framed_write(reply).await?;

    // now do proxy
    let mut stream = transport.into_inner();
    let (mut ri, mut wi) = stream.split();
    let (mut ro, mut wo) = split(remote_stream);

    let client_to_server = ri.copy(&mut wo);
    let server_to_client = ro.copy(&mut wi);

    try_join(client_to_server, server_to_client).await?;
    Ok(())
}

pub async fn handle_request(
    client_addr: SocketAddr,
    req: &Request,
    resolver: &AsyncResolver,
) -> Result<(TcpStream, Reply), Socks5Error> {
    if req.cmd != Cmd::Connect {
        // only cmd CONNECT is supported for now.
        error!("client {}, request not supported: {}", client_addr, req);
        return Err(Socks5Error::InvalidCmd(req.cmd as u8));
    }

    let target_ips = resolver.dns_resolve(&req.dest_addr).await?;
    if target_ips.is_empty() {
        error!(
            "client {}, no DNS records found for: {}",
            client_addr, req.dest_addr
        );
        return Err(ResolveError::from("no DNS records found").into());
    }

    let target_sockaddr = SocketAddr::new(target_ips[0], req.dest_port);
    info!("client {}, connecting to: {}", client_addr, target_sockaddr);
    let remote_stream = TcpStream::connect(target_sockaddr)
        .await
        .map_err(move |err| {
            error!(
                "client {}, connecting to {} failed, error: {}",
                client_addr, target_sockaddr, err
            );
            err
        })?;
    let reply = Reply::new(REP_SUCCEEDED, remote_stream.local_addr()?);
    Ok((remote_stream, reply))
}
