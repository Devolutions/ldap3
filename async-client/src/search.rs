use std::sync::Arc;

use futures_util::Stream;
use futures_util::{FutureExt, StreamExt};
use ldap3_proto::LdapMsg;

use tokio::sync::Mutex;

use crate::ldap_session::LdapFrame;

pub struct LdapSearchResultStream<T> {
    frame: Arc<Mutex<LdapFrame<T>>>,
}

impl<T> LdapSearchResultStream<T> {}

impl<T> LdapSearchResultStream<T> {
    pub fn new(frame: Arc<Mutex<LdapFrame<T>>>) -> Self {
        Self { frame }
    }
}

impl<T> Stream for LdapSearchResultStream<T>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    type Item = std::io::Result<LdapMsg>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let lock_future = self.frame.lock();

        let mut frame = match lock_future.boxed_local().poll_unpin(cx) {
            std::task::Poll::Ready(a) => a,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        };

        match frame.next().poll_unpin(cx) {
            std::task::Poll::Ready(item) => std::task::Poll::Ready(item),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
