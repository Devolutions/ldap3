use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::ReadBuf;

use crate::authentication::SecurityProvider;

pub struct DummyEncryptionProvider;
impl SecurityProvider for DummyEncryptionProvider {
    fn step<'a>(
        &'a mut self,
        _input: &'a [u8],
    ) -> futures_util::future::LocalBoxFuture<'a, crate::authentication::StepResult> {
        unreachable!()
    }

    fn encrypt(&mut self, input: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(input)
    }

    fn decrypt(&mut self, input: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(input)
    }
}

pub struct EncryptionStream<T> {
    inner: T,
    encryption: Box<dyn SecurityProvider>,
}

impl<T> EncryptionStream<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            encryption: Box::new(DummyEncryptionProvider),
        }
    }

    pub fn set_encryption(&mut self, encryption: Box<dyn SecurityProvider>) {
        self.encryption = encryption;
    }
}

impl<T> tokio::io::AsyncRead for EncryptionStream<T>
where
    T: tokio::io::AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        tracing::debug!("poll read");
        let mut inner_read_buf = [0u8; 8096];
        let mut inner_read_buf = ReadBuf::new(&mut inner_read_buf);
        match Pin::new(&mut self.inner).poll_read(cx, &mut inner_read_buf) {
            Poll::Ready(res) => {
                if let Err(e) = res {
                    return Poll::Ready(Err(e));
                }
            }
            Poll::Pending => return Poll::Pending,
        };
        let decrypted_payload = match self.encryption.decrypt(inner_read_buf.filled().to_vec()) {
            Ok(payload) => payload,
            Err(e) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                )))
            }
        };

        buf.put_slice(&decrypted_payload[..]);
        tracing::debug!("decrypted poll read payload");
        Poll::Ready(Ok(()))
    }
}

impl<T> tokio::io::AsyncWrite for EncryptionStream<T>
where
    T: tokio::io::AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let encrypted_payload = match self.encryption.encrypt(buf.to_vec()) {
            Ok(payload) => payload,
            Err(e) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                )))
            }
        };

        tracing::debug!(
            "encrypted poll write payload,size = {:?},original size = {:?}",
            encrypted_payload.len(),
            buf.len()
        );
        match Pin::new(&mut self.inner).poll_write(cx, &encrypted_payload[..]) {
            Poll::Ready(res) => {
                if let Err(e) = res {
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tracing::debug!("poll flush");
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tracing::debug!("poll shutdown");
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
