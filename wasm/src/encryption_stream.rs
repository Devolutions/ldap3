use std::{pin::Pin, future::Pending, task::ready};

use serde::de;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::authentication::SecurityProvider;

pub struct EncryptionStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    security_provider: Box<dyn SecurityProvider>,
    stream: T,
}

impl<T> EncryptionStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(security_provider: Box<dyn SecurityProvider>, stream: T) -> Self {
        Self {
            security_provider,
            stream,
        }
    }
}

impl<T> AsyncRead for EncryptionStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut buffer = [0u8; 8096];
        let mut undecrypted = tokio::io::ReadBuf::new(&mut buffer[..]);
        let res = Pin::new(&mut self.stream).poll_read(cx, &mut undecrypted);

        match res {
            std::task::Poll::Ready(a) => a,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }?;

        let decrypted = self
            .security_provider
            .decrypt(undecrypted.filled().to_vec())
            .map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, format!("decrypt error: {}", e))
            })?;

        buf.put_slice(decrypted.as_slice());
        std::task::Poll::Ready(Ok(()))
    }
}

impl<T> AsyncWrite for EncryptionStream<T>
where
    T: AsyncWrite + AsyncRead + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let vec = self.security_provider.encrypt(buf.to_vec()).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("encrypt error: {}", e))
        })?;
        Pin::new(&mut self.stream).poll_write(cx, vec.as_slice())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
