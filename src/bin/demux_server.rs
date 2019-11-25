#![recursion_limit = "256"]
use futures::future::try_join;
use futures::select;
use futures_util::stream::StreamExt;
use futures_util::SinkExt;
use log::{debug, error, info};
use std::collections::hash_map::{Entry, HashMap};
use std::convert::TryFrom;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use tokio::codec::{FramedRead, FramedWrite};
use tokio::io::{split, AsyncReadExt};
use tokio::net::tcp::split::WriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Mutex;
use yimu::error::YimuError;
use yimu::proxy::demux_proxy::{DemuxProxy, Packet, PacketCodec, Session};

#[tokio::main(multi_thread)]
async fn main() -> Result<(), YimuError> {
    env_logger::init();
    let addr = "0.0.0.0:4350";
    let mut listener = TcpListener::bind(addr).await?;
    info!("demux server on: {}", addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        tokio::spawn(demux(stream, peer_addr));
    }
}

//                          (MuxManager)
//
// client---socks5server---DemuxProxy---                         ---DemuxProxy---remote
//                                      \                       /
// client---socks5server---DemuxProxy-------MuxWorker---demux-------DemuxProxy---remote
//                                      /                       \
// client---socks5server---DemuxProxy---                         ---DemuxProxy---remote
pub async fn demux(mut stream: TcpStream, peer_addr: SocketAddr) {
    debug!("enter demux()");
    let (read_half, write_half) = stream.split();
    let framed_read = FramedRead::new(read_half, PacketCodec);
    let mut framed_write = FramedWrite::new(write_half, PacketCodec);

    let (worker_tx, worker_rx) = channel::<Packet>(1024);
    let sessions: Arc<Mutex<HashMap<u16, Session>>> = Arc::new(Mutex::new(HashMap::new()));

    let mut fut_chan = worker_rx.fuse();
    let mut fut_stream = framed_read.fuse();
    loop {
        debug!("demux() another iteration");
        select! {
            packet = fut_chan.next() => {
                debug!("fut_chan.next(): {:?}", packet);
                let packet = match packet {
                    Some(packet) => packet,
                    None => unreachable!(), // all senders of worker_tx closed, impossible.
                };
                process_channel_packet(packet, sessions.clone(), &mut framed_write).await;
            }
            packet = fut_stream.next() => {
                debug!("fut_stream.next(): {:?}", packet);
                let packet = match packet {
                    Some(Ok(packet)) => packet,
                    Some(Err(e)) => {
                        error!("demux() error: {}", e);
                        return;
                    }
                    None => {
                        info!("demux() peer {} closed connection", peer_addr);
                        let sessions = sessions.clone();
                        let mut sessions = sessions.lock().await;
                        sessions.clear();
                        return;
                    }
                };
                process_stream_packet(packet, sessions.clone(), worker_tx.clone()).await;
            }
        }
    }
}

pub async fn process_channel_packet(
    packet: Packet,
    sessions: Arc<Mutex<HashMap<u16, Session>>>,
    framed_write: &mut FramedWrite<WriteHalf<'_>, PacketCodec>,
) {
    debug!("enter process_channel_packet()");
    {
        let session_closed: bool;
        let mut sessions = sessions.lock().await;
        if let Some(session) = sessions.get_mut(&packet.conn_id) {
            if packet.data.is_empty() {
                session.local_eof = true;
            }
            session_closed = session.local_eof && session.remote_eof;
        } else {
            error!("conn#{} session not found", packet.conn_id);
            return; // TODO: wtf
        }

        if session_closed {
            sessions.remove(&packet.conn_id);
        }
    }

    debug!("process_channel_packet() before framed_stream.send()");
    if let Err(e) = framed_write.send(packet).await {
        error!("process_channel_packet(): framed_write.send() error: {}", e)
    }
}

pub async fn process_stream_packet(
    packet: Packet,
    sessions: Arc<Mutex<HashMap<u16, Session>>>,
    worker_tx: Sender<Packet>,
) {
    debug!("enter process_stream_packet()");
    let conn_id = packet.conn_id;

    let mut session_tx: Option<Sender<Packet>> = None;
    let mut session_closed = false;
    {
        match sessions.lock().await.entry(conn_id) {
            Entry::Occupied(mut entry) => {
                let session = entry.get_mut();
                session_tx = Some(session.tx.clone());
                if packet.data.is_empty() {
                    session.remote_eof = true;
                }
                session_closed = session.local_eof && session.remote_eof;
            }
            Entry::Vacant(vacant) => {
                if let Ok(sockaddr) = parse_sockadddr_from_first_packet(&packet) {
                    let (tx, rx) = channel::<Packet>(32);
                    let session = Session::new(conn_id, tx);
                    vacant.insert(session);
                    debug!("process_stream_packet() before enter new_conn()");
                    tokio::spawn(new_conn(sockaddr, conn_id, worker_tx.clone(), rx));
                } else {
                    error!(
                        "conn#{}: parse_sockadddr_from_first_packet() failed",
                        conn_id
                    );
                }
            }
        }
    }

    if let Some(mut session_tx) = session_tx {
        // 这样处理，似有严重逻辑之错误
        debug!("process_stream_packet() before session_tx.send()");
        if session_tx.send(packet).await.is_err() {
            error!("send to channel with conn_id={} failed", conn_id);
            session_closed = true;
        }
    }

    if session_closed {
        let mut sessions = sessions.lock().await;
        sessions.remove(&conn_id);
    }
}

async fn new_conn(sockaddr: SocketAddr, conn_id: u16, tx: Sender<Packet>, rx: Receiver<Packet>) {
    if let Err(e) = new_conn_inner(sockaddr, conn_id, tx, rx).await {
        error!("conn#{} new_conn() error: {}", conn_id, e);
    }
}

async fn new_conn_inner(
    sockaddr: SocketAddr,
    conn_id: u16,
    mut tx: Sender<Packet>,
    rx: Receiver<Packet>,
) -> Result<(), YimuError> {
    let mut stream = match TcpStream::connect(sockaddr).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("conn#{} connect to {} error: {}", conn_id, sockaddr, e);
            tx.send(Packet::empty(conn_id)).await?;
            return Err(e)?;
        }
    };
    info!("conn#{} new connection to {} success", conn_id, sockaddr);

    let fake_sockaddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let proxy = DemuxProxy::new(conn_id, fake_sockaddr, tx, rx);

    let (mut local_r, mut local_w) = split(proxy);
    let (mut remote_r, mut remote_w) = stream.split();
    let remote_to_local = remote_r.copy(&mut local_w);
    let local_to_remote = local_r.copy(&mut remote_w);
    try_join(remote_to_local, local_to_remote).await?;
    Ok(())
}

fn parse_sockadddr_from_first_packet(packet: &Packet) -> io::Result<SocketAddr> {
    let data: &[u8] = &packet.data;
    if data.len() == 4 + 2 {
        let octets = <[u8; 4]>::try_from(&data[0..4]).expect("unreachable");
        let ip = Ipv4Addr::from(octets);
        let port = u16::from_be_bytes([data[4], data[5]]);
        return Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)));
    }
    if data.len() == 16 + 2 {
        let octets = <[u8; 16]>::try_from(&data[0..16]).expect("unreachable");
        let ip = Ipv6Addr::from(octets);
        let port = u16::from_be_bytes([data[16], data[17]]);
        return Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "parse_sockadddr_from_first_packet: invalid ip/port",
    ))
}
