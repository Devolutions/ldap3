use std::sync::Arc;

use anyhow::Context;
use futures_util::future::{BoxFuture, LocalBoxFuture};

use sspi::{generator::NetworkRequest};
use tokio::net;

pub mod kerberos;
pub mod negotiate;
pub mod ntlm;

/*
We are not seeking to implement GSSAPI encryption/decryption, at this time.
We will use LDAP over TLS, instead.
*/
pub type StepResult = Result<Vec<u8>, Box<dyn std::error::Error>>;
pub trait SecurityProvider {
    // we are using wasm, so we dont need Send on the future, LocalBoxFuture is fine
    fn step<'a>(&'a mut self, input: &'a [u8]) -> LocalBoxFuture<'a, StepResult>;

    fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecurityProviderError>;

    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecurityProviderError>;

    fn status(&self) -> Option<sspi::SecurityStatus>;
}

#[derive(Debug, Default)]
pub struct DummySecurityProvider;

impl SecurityProvider for DummySecurityProvider {
    fn step<'a>(&'a mut self, _input: &'a [u8]) -> LocalBoxFuture<'a, StepResult> {
        unreachable!()
    }

    fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecurityProviderError> {
        Ok(input.to_vec())
    }

    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecurityProviderError> {
        Ok(input.to_vec())
    }

    fn status(&self) -> Option<sspi::SecurityStatus> {
        unreachable!()
    }
}

pub trait AsyncNetworkClient {
    fn send<'a>(&'a self, network_request: NetworkRequest) -> BoxFuture<'a, anyhow::Result<Vec<u8>>>;
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone)]
pub struct SspiDefaultNetworkClient(
    sspi::network_client::reqwest_network_client::ReqwestNetworkClient,
);

#[cfg(not(target_arch = "wasm32"))]
impl SspiDefaultNetworkClient {
    pub fn new() -> Self {
        Self(sspi::network_client::reqwest_network_client::ReqwestNetworkClient::default())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl AsyncNetworkClient for SspiDefaultNetworkClient {
    fn send<'a>(&'a self, network_request: NetworkRequest) -> BoxFuture<'a, anyhow::Result<Vec<u8>>> {
        let self_clone = self.clone();
        Box::pin(async move {
            tracing::debug!("Sending network request: {:?}", network_request);
            let res = tokio::task::spawn_blocking(move || {
                sspi::network_client::NetworkClient::send(&self_clone.0, &network_request)
            })
            .await
            .with_context(|| "tokio::task::spawn_blocking failed")?
            .with_context(|| "sspi::network_client::NetworkClient::send failed")?;
            Ok(res)
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecurityProviderError {
    #[error("SSPI Error")]
    SspiError(sspi::Error),
    #[error("IO Error")]
    IoError(std::io::Error),
    #[error("Buffer not large enough,expected {0}")]
    BufferNotLargeEnough(u32),
}

impl From<sspi::Error> for SecurityProviderError {
    fn from(value: sspi::Error) -> Self {
        SecurityProviderError::SspiError(value)
    }
}

impl From<std::io::Error> for SecurityProviderError {
    fn from(value: std::io::Error) -> Self {
        SecurityProviderError::IoError(value)
    }
}
