use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::ReadBuf;

use crate::authentication::{SecurityProvider, SecurityProviderError};

pub struct DummyEncryptionProvider;
impl SecurityProvider for DummyEncryptionProvider {
    fn step<'a>(
        &'a mut self,
        _input: &'a [u8],
    ) -> futures_util::future::LocalBoxFuture<'a, crate::authentication::StepResult> {
        unreachable!()
    }

    fn encrypt(&mut self, input: Vec<u8>) -> Result<Vec<u8>, SecurityProviderError> {
        Ok(input)
    }

    fn decrypt(&mut self, input: Vec<u8>) -> Result<Vec<u8>, SecurityProviderError> {
        Ok(input)
    }
}

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
            encryption: Box::new(DummyEncryptionProvider),
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

        if self.decryption_buf.len() > 0 {
            tracing::info!(
                "decryption buf has data len = {} , return it first",
                self.decryption_buf.len()
            );
            if self.decryption_buf.len() <= buf.remaining() {
                tracing::info!(
                    "decryption buf is smaller than buf, return decryption buf, buf len = {}",
                    buf.remaining()
                );
                buf.put_slice(&self.decryption_buf[..]);
                self.decryption_buf.clear();
            } else {
                tracing::info!("decryption buf is larger than buf, return buf and save the rest to decryption buf, buf len = {}", buf.remaining());
                let left = self.decryption_buf[buf.remaining()..].to_vec();
                buf.put_slice(&self.decryption_buf[..buf.remaining()]);
                self.decryption_buf.clear();
                self.decryption_buf.extend_from_slice(&left);
            }
            tracing::debug!(
                "read into buf, buf len = {}, there is {} left in the decryption buf",
                buf.filled().len(),
                self.decryption_buf.len()
            );
            return Poll::Ready(Ok(()));
        }

        // read from inner stream
        let mut inner_read_buf = [0u8; 8096];
        let mut local_read_buf = ReadBuf::new(&mut inner_read_buf);
        match Pin::new(&mut self.inner).poll_read(cx, &mut local_read_buf) {
            Poll::Ready(res) => {
                if let Err(e) = res {
                    return Poll::Ready(Err(e));
                }
            }
            Poll::Pending => return Poll::Pending,
        };

        tracing::debug!(
            "read from inner stream, size = {}",
            local_read_buf.filled().len()
        );

        if local_read_buf.filled().len() == 0 {
            return Poll::Ready(Ok(()));
        }
        // decrypt
        self.inner_read_buf
            .extend_from_slice(&local_read_buf.filled());
        let to_decrypt = self.inner_read_buf.clone();
        let decrypted_payload = match self.encryption.decrypt(to_decrypt) {
            Ok(payload) => {
                self.inner_read_buf.clear();
                payload
            }
            Err(e) => {
                return Poll::Ready(match e {
                    SecurityProviderError::SspiError(e) => Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )),
                    SecurityProviderError::IoError(e) => Err(e),
                    SecurityProviderError::BufferNotLargeEnough(size) => {
                        tracing::debug!("buffer not large enough, size = {}, read again", size);
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
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
        
            tracing::debug!("Read into buf, buf len = {}, there is {} left in the decryption buf and decrypted_payload.len() = {}", 
                            buf.filled().len(), 
                            self.decryption_buf.len(),
                            decrypted_payload.len());
        } else {
            tracing::debug!("Decrypted payload is smaller than or equal to buf, return decrypted payload");
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
