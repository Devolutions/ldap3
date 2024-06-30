use anyhow::Context;
use futures_util::future::LocalBoxFuture;

use sspi::generator::NetworkRequest;

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
    fn send(&self, network_request: NetworkRequest) -> LocalBoxFuture<'_, anyhow::Result<Vec<u8>>>;
}

#[derive(Debug)]
pub(crate) struct WasmNetworkClient;

impl AsyncNetworkClient for WasmNetworkClient {
    fn send(&self, network_request: NetworkRequest) -> LocalBoxFuture<'_, anyhow::Result<Vec<u8>>> {
        Box::pin(async move {
            match &network_request.protocol {
                sspi::network_client::NetworkProtocol::Http
                | sspi::network_client::NetworkProtocol::Https => {
                    let body = js_sys::Uint8Array::from(&network_request.data[..]);

                    gloo_net::http::Request::post(network_request.url.as_str())
                        .header("keep-alive", "true")
                        .body(body)
                        .unwrap()
                        .send()
                        .await
                        .unwrap()
                        .binary()
                        .await
                        .context("gloo_net::http::Request::post failed")
                }
                _ => panic!("unsupported protocol for KDC proxy"),
            }
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
    #[error("Should never happen error {0}")]
    Unreachable(String),
    #[error("unexpected error {0}")]
    Other(String),
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
