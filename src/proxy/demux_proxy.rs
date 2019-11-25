use crate::error::YimuError;
use crate::proxy::Proxy;
use bytes::{BufMut, BytesMut};
use futures::ready;
use futures_sink::Sink;
use log::{error, info};
use std::cmp::min;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::codec::{Decoder, Encoder, Framed};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::stream::Stream;
use tokio::sync::mpsc::error::{SendError, TrySendError};
use tokio::sync::mpsc::{channel, Receiver, Sender};

// A proxy inspired by https://blog.codingnow.com/2011/05/xtunnel.html

#[derive(Debug)]
pub enum DemuxError {
    ConnectionOverflow,
    ChannelError,
    Io(io::Error),
}

impl DemuxError {
    pub fn unexpected_eof() -> DemuxError {
        let e = io::Error::from(io::ErrorKind::UnexpectedEof);
        DemuxError::Io(e)
    }
}

impl fmt::Display for DemuxError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for DemuxError {}

impl From<io::Error> for DemuxError {
    fn from(e: io::Error) -> DemuxError {
        DemuxError::Io(e)
    }
}

impl<T> From<TrySendError<T>> for DemuxError {
    fn from(_: TrySendError<T>) -> DemuxError {
        DemuxError::ChannelError
    }
}

impl From<SendError> for DemuxError {
    fn from(_: SendError) -> DemuxError {
        DemuxError::ChannelError
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub conn_id: u16,
    pub data: BytesMut, // data.len()=0 means close.
}

impl Packet {
    pub fn max_data_size() -> usize {
        u16::max_value() as usize
    }

    pub fn new(conn_id: u16, data: &[u8]) -> Packet {
        assert!(data.len() <= Packet::max_data_size());
        let mut buf = BytesMut::with_capacity(data.len());
        buf.extend_from_slice(data);
        Packet { conn_id, data: buf }
    }

    pub fn empty(conn_id: u16) -> Packet {
        Packet::new(conn_id, &[])
    }

    pub fn from_slice(conn_id: u16, data: &[u8]) -> Vec<Packet> {
        let mut packets = vec![];
        for chunk in data.chunks(Packet::max_data_size()) {
            packets.push(Packet::new(conn_id, chunk));
        }
        packets
    }
}

// each packet has 4-byte header: DATA_LEN(2) and CONN_ID(2).
// DATA_LEN indacates length of data, excluding header's length。
// +----------+---------+----------+
// | DATA_LEN | CONN_ID |   DATA   |
// +----------+---------+----------+
// |    2     |    2    | Variable |
// +----------+---------+----------+
#[derive(Debug, Clone)]
pub struct PacketCodec;

impl Decoder for PacketCodec {
    type Item = Packet;
    type Error = DemuxError;
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Packet>, DemuxError> {
        if buf.len() < 4 {
            return Ok(None);
        }

        let data_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if buf.len() < data_len + 4 {
            return Ok(None);
        }

        let conn_id = u16::from_be_bytes([buf[2], buf[3]]);
        let mut data = buf.split_to(data_len + 4);
        data.advance(4); // header
        Ok(Some(Packet { conn_id, data }))
    }
}

impl Encoder for PacketCodec {
    type Item = Packet;
    type Error = DemuxError;
    fn encode(&mut self, packet: Packet, buf: &mut BytesMut) -> Result<(), DemuxError> {
        assert!(packet.data.len() <= Packet::max_data_size());
        let data_len = packet.data.len();
        buf.reserve(4 + data_len);
        buf.put_u16_be(data_len as u16);
        buf.put_u16_be(packet.conn_id);
        buf.put_slice(&packet.data);
        Ok(())
    }
}

#[derive(Debug)]
pub struct DemuxProxy {
    conn_id: u16,
    local_addr: SocketAddr,
    tx: Sender<Packet>,
    rx: Receiver<Packet>,

    read_buf: BytesMut,
    eof: bool,

    closed: bool,
}

impl DemuxProxy {
    pub fn new(
        conn_id: u16,
        local_addr: SocketAddr,
        tx: Sender<Packet>,
        rx: Receiver<Packet>,
    ) -> DemuxProxy {
        DemuxProxy {
            conn_id,
            local_addr,
            tx,
            rx,
            read_buf: BytesMut::new(),
            eof: false,
            closed: false,
        }
    }

    pub async fn connect(&mut self, target_addr: SocketAddr) -> Result<(), DemuxError> {
        info!("enter DemuxProxy::connect()");
        let mut buf = BytesMut::new();
        match target_addr.ip() {
            IpAddr::V4(ipv4) => {
                buf.reserve(4);
                buf.put_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                buf.reserve(16);
                buf.put_slice(&ipv6.octets());
            }
        }
        buf.reserve(2);
        buf.put_u16_be(target_addr.port());

        let packet = Packet::new(self.conn_id, &buf);
        info!(
            "before DemuxProxy::connect() INIT packet send: {:?}",
            packet
        );
        self.tx.send(packet).await?;
        info!("DemuxProxy::connect() INIT packet sent success");
        Ok(())
    }
}

impl AsyncRead for DemuxProxy {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        info!(
            "conn#{} enter <DemuProxy as AsyncRead>::poll_read()",
            self.conn_id
        );
        assert!(buf.len() > 0);

        let pinned = Pin::get_mut(self);
        if !pinned.eof {
            let rx = Pin::new(&mut pinned.rx);
            match rx.poll_next(cx) {
                Poll::Ready(Some(packet)) => {
                    if packet.data.is_empty() {
                        pinned.eof = true;
                    } else {
                        pinned.read_buf.reserve(packet.data.len());
                        pinned.read_buf.put_slice(&packet.data);
                    }
                }
                Poll::Ready(None) => {
                    pinned.eof = true;
                }
                Poll::Pending => {}
            }
        }

        let read_buf = &mut pinned.read_buf;
        if read_buf.is_empty() {
            info!(
                "conn#{} <DemuProxy as AsyncRead>::poll_read() read_buf is empty",
                pinned.conn_id
            );
            if pinned.eof {
                info!(
                    "conn#{} <DemuProxy as AsyncRead>::poll_read() returns Poll::Ready(Ok(0))",
                    pinned.conn_id
                );
                return Poll::Ready(Ok(0));
            } else {
                info!(
                    "conn#{} <DemuProxy as AsyncRead>::poll_read() returns Poll::Pending",
                    pinned.conn_id
                );
                return Poll::Pending;
            }
        } else {
            let len = min(read_buf.len(), buf.len());
            let buf = &mut buf[0..len];
            buf.copy_from_slice(&read_buf[0..len]);
            read_buf.advance(len);
            info!(
                "conn#{} <DemuProxy as AsyncRead>::poll_read() returns Poll::Ready(Ok({}))",
                pinned.conn_id, len
            );
            return Poll::Ready(Ok(len));
        }
    }
}

impl AsyncWrite for DemuxProxy {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        info!(
            "conn#{} enter <DemuProxy as AsyncWrite>::poll_write()",
            self.conn_id
        );
        assert!(buf.len() > 0);
        let pinned = Pin::get_mut(self);
        let mut bytes_written = 0usize;

        loop {
            let tx = Pin::new(&mut pinned.tx);
            match tx
                .poll_ready(cx)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "send to channel failed"))
            {
                Poll::Pending => {
                    break;
                }
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => {
                    error!("conn#{} send to channel failed: {}", pinned.conn_id, e);
                    return Poll::Ready(Err(e));
                }
            }

            let len = min(Packet::max_data_size(), buf.len() - bytes_written);
            let packet = Packet::new(pinned.conn_id, &buf[bytes_written..bytes_written + len]);
            info!(
                "conn#{} <DemuProxy as AsyncWrite>::poll_write(). packet: {:?}",
                pinned.conn_id, packet
            );
            let tx = Pin::new(&mut pinned.tx);
            tx.start_send(packet)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "send to channel failed"))?;
            bytes_written += len;

            if bytes_written >= buf.len() {
                info!("conn#{} all written!!!", pinned.conn_id);
                break;
            }
        }

        let tx = Pin::new(&mut pinned.tx);
        if let Poll::Ready(Err(e)) = tx
            .poll_flush(cx)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "send to channel failed"))
        {
            return Poll::Ready(Err(e));
        }

        if bytes_written > 0 {
            info!(
                "conn#{} <DemuProxy as AsyncWrite>::poll_write() {} bytes written",
                pinned.conn_id, bytes_written
            );
            return Poll::Ready(Ok(bytes_written));
        } else {
            return Poll::Pending;
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        info!(
            "conn#{} enter <DemuProxy as AsyncWrite>::poll_flush()",
            self.conn_id
        );
        let pinned = Pin::get_mut(self);
        let tx = Pin::new(&mut pinned.tx);
        tx.poll_flush(cx)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "send to channel failed"))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        info!(
            "conn#{} enter <DemuProxy as AsyncWrite>::poll_shutdown()",
            self.conn_id
        );
        let pinned = Pin::get_mut(self);

        if !pinned.closed {
            let tx = Pin::new(&mut pinned.tx);
            ready!(tx.poll_ready(cx))
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "send to channel failed"))?;

            let data: [u8; 0] = [];
            let empty_packet = Packet::new(pinned.conn_id, &data);

            let tx = Pin::new(&mut pinned.tx);
            tx.start_send(empty_packet)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "send to channel failed"))?;
            pinned.closed = true;
        }

        let tx = Pin::new(&mut pinned.tx);
        tx.poll_flush(cx)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "send to channel failed"))
    }
}

impl Proxy for DemuxProxy {
    fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        Ok(self.local_addr)
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub conn_id: u16,
    pub tx: Sender<Packet>,
    pub local_eof: bool,
    pub remote_eof: bool,
}

impl Session {
    pub fn new(conn_id: u16, tx: Sender<Packet>) -> Session {
        Session {
            conn_id: conn_id,
            tx: tx,
            local_eof: false,
            remote_eof: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MuxManager {
    next_conn_id: u16,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    tx: Sender<Packet>,
    sessions: Arc<Mutex<HashMap<u16, Session>>>,
}

pub fn circular_incr(n: u16) -> u16 {
    if n == u16::max_value() {
        return 0;
    } else {
        return n + 1;
    }
}

impl MuxManager {
    pub async fn create(remote_addr: SocketAddr) -> Result<MuxManager, YimuError> {
        let stream = TcpStream::connect(remote_addr).await?;
        let local_addr = stream.local_addr()?;
        let (tx, rx) = channel::<Packet>(1024);
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let worker = MuxWorker::new(stream, rx, sessions.clone());
        tokio::spawn(worker);

        let next_conn_id = 0;
        let manager = MuxManager {
            next_conn_id,
            local_addr,
            remote_addr,
            tx,
            sessions,
        };
        Ok(manager)
    }

    pub fn gen_conn_id(&mut self) -> Result<u16, DemuxError> {
        let sessions = self.sessions.lock().unwrap();
        // try only 100 times
        for _ in 0..100 {
            let conn_id = self.next_conn_id;
            self.next_conn_id = circular_incr(self.next_conn_id);
            if !sessions.contains_key(&conn_id) {
                return Ok(conn_id);
            }
        }
        Err(DemuxError::ConnectionOverflow)
    }

    pub async fn create_proxy(
        &mut self,
        target_addr: SocketAddr,
    ) -> Result<DemuxProxy, DemuxError> {
        info!("enter MuxManager::create_proxy");
        let conn_id = self.gen_conn_id()?;
        let (session_tx, session_rx) = channel::<Packet>(32);
        let session = Session::new(conn_id, session_tx);
        {
            // If these 2 lines are not in separate scope, we will get comile errors like:
            // `std::sync::MutexGuard<'_, std::collections::HashMap<u16, yimu::proxy::demux_proxy::Session>>`
            // cannot be sent between threads safely
            let mut sessions = self.sessions.lock().unwrap();
            sessions.insert(conn_id, session);
        }

        let mut proxy = DemuxProxy::new(conn_id, self.local_addr, self.tx.clone(), session_rx);
        proxy.connect(target_addr).await?;
        Ok(proxy)
    }
}

#[derive(Debug)]
pub struct MuxWorker {
    framed_stream: Framed<TcpStream, PacketCodec>,
    stream_buf: Option<Packet>,
    rx: Receiver<Packet>,
    rx_buf: Option<Packet>,
    sessions: Arc<Mutex<HashMap<u16, Session>>>,
}

impl MuxWorker {
    pub fn new(
        stream: TcpStream,
        rx: Receiver<Packet>,
        sessions: Arc<Mutex<HashMap<u16, Session>>>,
    ) -> MuxWorker {
        let framed_stream = Framed::new(stream, PacketCodec);
        MuxWorker {
            framed_stream,
            stream_buf: None,
            rx,
            rx_buf: None,
            sessions,
        }
    }

    pub fn poll_stream(&mut self, cx: &mut Context) -> Poll<DemuxError> {
        loop {
            if self.stream_buf.is_none() {
                let framed = Pin::new(&mut self.framed_stream);
                match ready!(framed.poll_next(cx)).unwrap_or(Err(DemuxError::unexpected_eof())) {
                    Ok(packet) => {
                        self.stream_buf = Some(packet);
                    }
                    Err(e) => {
                        return Poll::Ready(e);
                    }
                }
            }

            let packet = self.stream_buf.take().unwrap();
            let conn_id = packet.conn_id;

            let mut session_tx: Sender<Packet>;
            {
                let session_closed: bool;
                let mut sessions = self.sessions.lock().unwrap();
                if let Some(session) = sessions.get_mut(&conn_id) {
                    session_tx = session.tx.clone();
                    if packet.data.is_empty() {
                        session.remote_eof = true;
                    }
                    session_closed = session.local_eof && session.remote_eof;
                } else {
                    error!("session with conn_id={} not found", conn_id);
                    return Poll::Pending;
                }

                if session_closed {
                    sessions.remove(&conn_id);
                }
            }

            self.stream_buf = Some(packet);
            let tx_pinned = Pin::new(&mut session_tx);
            if let Err(e) = ready!(tx_pinned.poll_ready(cx)) {
                return Poll::Ready(DemuxError::from(e));
            }

            let tx_pinned = Pin::new(&mut session_tx);
            if let Err(e) = tx_pinned.start_send(self.stream_buf.take().unwrap()) {
                return Poll::Ready(DemuxError::from(e));
            }

            let tx_pinned = Pin::new(&mut session_tx);
            if let Err(e) = ready!(tx_pinned.poll_flush(cx)) {
                return Poll::Ready(DemuxError::from(e));
            }
        }
    }

    pub fn poll_channel(&mut self, cx: &mut Context) -> Poll<DemuxError> {
        loop {
            info!("enter MuxWorker::poll_channel()");
            let rx = Pin::new(&mut self.rx);
            if self.rx_buf.is_none() {
                match ready!(rx.poll_next(cx)) {
                    Some(packet) => self.rx_buf = Some(packet),
                    None => {
                        return Poll::Ready(DemuxError::unexpected_eof());
                    }
                };
            }

            info!("in MuxWorker::poll_channel(), {:?}", self.rx_buf);

            if self.rx_buf.is_none() {
                return Poll::Pending;
            }

            let framed = Pin::new(&mut self.framed_stream);
            info!("in MuxWorker::poll_channel(), before framed.poll_ready()");
            if let Err(e) = ready!(framed.poll_ready(cx)) {
                return Poll::Ready(e);
            }
            info!("MuxWorker::poll_channel(), after framed.poll_ready()");

            let packet = self.rx_buf.take().unwrap();
            {
                let mut sessions = self.sessions.lock().unwrap();
                let mut should_remove = false;
                if let Some(session) = sessions.get_mut(&packet.conn_id) {
                    if packet.data.is_empty() {
                        session.local_eof = true;
                        if session.remote_eof {
                            should_remove = true;
                        }
                    }
                } else {
                    error!("session with conn_id={} not found", packet.conn_id);
                    return Poll::Pending;
                }

                if should_remove {
                    info!(
                        "MuxWorker::poll_channel(), before remove session. conn#{}",
                        packet.conn_id
                    );
                    sessions.remove(&packet.conn_id);
                }
            }

            let framed = Pin::new(&mut self.framed_stream);
            info!(
                "MuxWorker::poll_channel(), before framed.start_send() {:?}",
                packet
            );
            if let Err(e) = framed.start_send(packet) {
                return Poll::Ready(e);
            }

            let framed = Pin::new(&mut self.framed_stream);
            info!("MuxWorker::poll_channel(), before framed.poll_flush()");
            if let Err(e) = ready!(framed.poll_flush(cx)) {
                return Poll::Ready(e);
            }
        }
    }

    fn remove_all_sessions(&mut self) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.clear();
    }
}

impl Future for MuxWorker {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        info!("enter <MuxWorker as Future>::poll()");
        let pinned = Pin::get_mut(self);

        info!("in <MuxWorker as Future>::poll() before poll_channel()");
        match pinned.poll_channel(cx) {
            Poll::Pending => {
                info!("<MuxWorker as Future>::poll_channel() returns Poll::Pending");
            }
            Poll::Ready(e) => {
                error!("MuxWorker.poll_channel error: {}", e);
                pinned.remove_all_sessions();
                return Poll::Ready(()); // Future resolved
            }
        };

        info!("in <MuxWorker as Future>::poll() before poll_stream()");
        match pinned.poll_stream(cx) {
            Poll::Pending => {
                info!("MuxWorker.poll_stream() returns Poll::Pending");
            }
            Poll::Ready(e) => {
                error!("MuxWorker.poll_stream error: {}", e);
                pinned.remove_all_sessions();
                return Poll::Ready(()); // Future resolved
            }
        }

        info!("in <MuxWorker as Future>::poll() before return Poll::Pending");
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_packet_encode_decode_roundtrip() -> Result<(), DemuxError> {
        let packet = Packet::new(1, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut buf = BytesMut::new();

        PacketCodec.encode(packet.clone(), &mut buf)?;
        let res = PacketCodec.decode(&mut buf)?;

        assert!(buf.is_empty());
        assert!(res.is_some());
        let packet_back = res.unwrap();
        assert_eq!(packet_back.conn_id, packet.conn_id);
        assert_eq!(&packet_back.data, &packet.data);

        Ok(())
    }
}
