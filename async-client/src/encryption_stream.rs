use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::ReadBuf;

use crate::authentication::{DummySecurityProvider, SecurityProvider, SecurityProviderError};

pub struct EncryptionStream<T> {
    inner: T,
    encryption: Box<dyn SecurityProvider>,
    inner_read_buf: Vec<u8>,
    decryption_buf: Vec<u8>,
}

impl<T> EncryptionStream<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            encryption: Box::new(DummySecurityProvider),
            inner_read_buf: Vec::new(),
            decryption_buf: Vec::new(),
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
        if !self.decryption_buf.is_empty() {
            tracing::trace!("The decryption buffer is not empty, reading from it. buf.remaining = {}, decryption buffer = {}", buf.remaining(), self.decryption_buf.len());
            let data_to_read = std::cmp::min(self.decryption_buf.len(), buf.remaining());
            buf.put_slice(&self.decryption_buf[..data_to_read]);
            self.decryption_buf.drain(..data_to_read);
            return Poll::Ready(Ok(()));
        }

        // read from inner stream
        let mut inner_read_buf = [0u8; 1024];
        let mut local_read_buf = ReadBuf::new(&mut inner_read_buf);
        match Pin::new(&mut self.inner).poll_read(cx, &mut local_read_buf) {
            Poll::Ready(res) => {
                if let Err(e) = res {
                    return Poll::Ready(Err(e));
                }
            }
            Poll::Pending => return Poll::Pending,
        };

        if local_read_buf.filled().is_empty() {
            return Poll::Ready(Ok(())); // EOF
        }

        // decrypt
        self.inner_read_buf
            .extend_from_slice(local_read_buf.filled());
        let to_decrypt = &self.inner_read_buf.clone();
        let decrypted_payload = match self.encryption.decrypt(to_decrypt) {
            Ok(payload) => {
                self.inner_read_buf.clear();
                payload
            }
            Err(e) => {
                return Poll::Ready(match e {
                    SecurityProviderError::BufferNotLargeEnough(_) => {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    SecurityProviderError::IoError(e) => Err(e),

                    SecurityProviderError::SspiError(e) => {
                        Err(std::io::Error::new(std::io::ErrorKind::Other, e))
                    }
                    _ => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                })
            }
        };

        // if decrypted payload is larger than buf, return buf
        if decrypted_payload.len() > buf.remaining() {
            tracing::debug!("Decrypted payload is larger than buf, return buf and save the rest to decryption buf");

            let space_in_buf = buf.remaining();
            buf.put_slice(&decrypted_payload[..space_in_buf]);
            let left_over = decrypted_payload[space_in_buf..].to_vec();
            self.decryption_buf.clear();
            self.decryption_buf.extend_from_slice(&left_over);
        } else {
            tracing::trace!(
                "Decrypted payload is smaller than or equal to buf, return decrypted payload"
            );
            buf.put_slice(&decrypted_payload);
        }

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
        let encrypted_payload = match self.encryption.encrypt(buf) {
            Ok(payload) => payload,
            Err(e) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                )))
            }
        };

        tracing::trace!(
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
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
