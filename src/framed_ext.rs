use async_trait::async_trait;
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use std::convert::From;
use std::io;
use tokio::codec::{Decoder, Encoder};
use tokio::codec::{Framed, FramedParts};
use tokio::io::{AsyncRead, AsyncWrite};

fn unexpected_eof() -> io::Error {
    From::from(io::ErrorKind::UnexpectedEof)
}

/// Framed impls Stream/Sink, so it's suitably used in a loop.
/// FramedExt provides easy to use methods for us to read/write a single item.
#[async_trait]
pub trait FramedExt {
    type Decoder: Decoder;
    type Encoder: Encoder;

    async fn framed_read(
        &mut self,
    ) -> Result<<Self::Decoder as Decoder>::Item, <Self::Decoder as Decoder>::Error>;

    async fn framed_write(
        &mut self,
        item: <Self::Encoder as Encoder>::Item,
    ) -> Result<(), <Self::Encoder as Encoder>::Error>;
}

#[async_trait]
impl<T, U> FramedExt for Framed<T, U>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
    U: Decoder + Encoder + Unpin + Send,
    <U as Encoder>::Item: Send,
{
    type Decoder = U;
    type Encoder = U;

    async fn framed_read(&mut self) -> Result<<U as Decoder>::Item, <U as Decoder>::Error> {
        self.next()
            .await
            .unwrap_or(Err(From::from(unexpected_eof())))
    }

    async fn framed_write(
        &mut self,
        item: <U as Encoder>::Item,
    ) -> Result<(), <U as Encoder>::Error> {
        self.send(item).await
    }
}

/// FramedExt2 let us replace codec with a new one.
pub trait FramedExt2<T, U> {
    fn replace_codec<V>(self, new_codec: V) -> Framed<T, V>;
}

impl<T, U> FramedExt2<T, U> for Framed<T, U> {
    fn replace_codec<V>(self, new_codec: V) -> Framed<T, V> {
        let parts = self.into_parts();
        let mut new_parts = FramedParts::new(parts.io, new_codec);
        new_parts.read_buf = parts.read_buf;
        new_parts.write_buf = parts.write_buf;
        Framed::from_parts(new_parts)
    }
}
