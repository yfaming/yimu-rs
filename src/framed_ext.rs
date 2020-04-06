use async_trait::async_trait;
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use std::convert::From;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder, Framed, FramedParts};

fn unexpected_eof() -> io::Error {
    io::Error::from(io::ErrorKind::UnexpectedEof)
}

/// Framed impls Stream/Sink, so it's suitably used in a loop.
/// FramedExt provides easy to use methods for us to read/write a single item.
#[async_trait]
pub trait FramedExt<Item> {
    type Decoder: Decoder;
    type Encoder: Encoder<Item>;

    async fn framed_read(
        &mut self,
    ) -> Result<<Self::Decoder as Decoder>::Item, <Self::Decoder as Decoder>::Error>;

    async fn framed_write(
        &mut self,
        item: Item,
    ) -> Result<(), <Self::Encoder as Encoder<Item>>::Error>;
}

#[async_trait]
impl<T, U, I> FramedExt<I> for Framed<T, U>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
    U: Decoder + Encoder<I> + Unpin + Send,
    I: Send + 'static,
{
    type Decoder = U;
    type Encoder = U;

    async fn framed_read(&mut self) -> Result<<U as Decoder>::Item, <U as Decoder>::Error> {
        self.next()
            .await
            .unwrap_or(Err(From::from(unexpected_eof())))
    }

    async fn framed_write(&mut self, item: I) -> Result<(), <U as Encoder<I>>::Error> {
        self.send(item).await
    }
}

/// FramedExt2 let us replace codec with a new one.
pub trait FramedExt2<T, U> {
    fn replace_codec<V, I>(self, new_codec: V) -> Framed<T, V>
    where
        V: Encoder<I>;
}

impl<T, U> FramedExt2<T, U> for Framed<T, U> {
    fn replace_codec<V, I>(self, new_codec: V) -> Framed<T, V>
    where
        V: Encoder<I>,
    {
        let parts = self.into_parts();
        let mut new_parts = FramedParts::new(parts.io, new_codec);
        new_parts.read_buf = parts.read_buf;
        new_parts.write_buf = parts.write_buf;
        Framed::from_parts(new_parts)
    }
}
