

use futures_util::future::LocalBoxFuture;
use serde::{Serialize, Deserialize};
use sspi::{generator::NetworkRequest, network_client::NetworkProtocol};
use tracing::debug;
use tsify::Tsify;

pub mod ntlm;
pub mod kerberos;
pub mod negotiate;

/*
We are not seeking to implement GSSAPI encryption/decryption, at this time.
We will use LDAP over TLS, instead.
*/
pub type StepResult = Result<Vec<u8>, Box<dyn std::error::Error>>;
pub trait SecurityProvider { 
    // we are using wasm, so we dont need Send on the future, LocalBoxFuture is fine
    fn step<'a>(&'a mut self, input: &'a [u8]) -> LocalBoxFuture<'a,StepResult>;  
}

#[derive(Debug)]
pub(crate) struct WasmNetworkClient;

impl WasmNetworkClient {
    async fn send(&self, network_request: &NetworkRequest) -> Vec<u8> {
        debug!(?network_request.protocol, ?network_request.url);
        match &network_request.protocol {
            NetworkProtocol::Http | NetworkProtocol::Https => {
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
                    .unwrap()
            }
            _  => panic!("unsupported protocol for KDC proxy")
        }
    }
}
