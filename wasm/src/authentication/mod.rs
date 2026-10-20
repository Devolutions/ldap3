use anyhow::Context;
use futures_util::future::LocalBoxFuture;

use sspi::generator::NetworkRequest;

pub mod kerberos;
pub mod negotiate;
pub mod ntlm;

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct TestNetworkClient {
    pub requests: std::rc::Rc<std::cell::RefCell<Vec<NetworkRequest>>>,
}

#[cfg(test)]
impl AsyncNetworkClient for TestNetworkClient {
    fn send(&self, request: NetworkRequest) -> LocalBoxFuture<'_, anyhow::Result<Vec<u8>>> {
        self.requests.borrow_mut().push(request);
        Box::pin(async { anyhow::bail!("KDC blocked by regression test") })
    }
}

/*
We are not seeking to implement GSSAPI encryption/decryption, at this time.
We will use LDAP over TLS, instead.
*/
pub type StepResult = Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync + 'static>>;

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

                    // Avoid exposing the token-bearing proxy URL in transport errors.
                    let response = gloo_net::http::Request::post(network_request.url.as_str())
                        .header("keep-alive", "true")
                        .body(body)
                        .map_err(|_| anyhow::anyhow!("unable to build KDC proxy request"))?
                        .send()
                        .await
                        .map_err(|_| anyhow::anyhow!("unable to send KDC proxy request"))?;
                    if !response.ok() {
                        anyhow::bail!("KDC proxy returned HTTP {}", response.status());
                    }
                    response
                        .binary()
                        .await
                        .context("unable to read KDC proxy response")
                }
                _ => anyhow::bail!("KDC proxy requires HTTP or HTTPS"),
            }
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecurityProviderError {
    #[error("SSPI error")]
    Sspi(#[from] sspi::Error),
    #[error("IO error")]
    Io(#[from] std::io::Error),
    #[error("buffer not large enough, expected at least {0} bytes")]
    BufferNotLargeEnough(u32),
    #[error("{0}")]
    Other(String),
}
