use futures_util::future::{BoxFuture, LocalBoxFuture};

use sspi::{generator::NetworkRequest, network_client::NetworkProtocol};

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

    fn encrypt(&mut self, input: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>>;

    fn decrypt(&mut self, input: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>>;

    fn status(&self) -> Option<sspi::SecurityStatus>;
}

#[derive(Debug,Default)]
pub struct PlaceHolderSecurityProvider;

impl SecurityProvider for PlaceHolderSecurityProvider {
    fn step<'a>(&'a mut self, input: &'a [u8]) -> LocalBoxFuture<'a, StepResult> {
        todo!()
    }

    fn encrypt(&mut self, input: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(input)
    }

    fn decrypt(&mut self, input: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(input)
    }

    fn status(&self) -> Option<sspi::SecurityStatus> {
        todo!()
    }
}

pub trait NetworkClient {
    fn send<'a>(&self, network_request: &NetworkRequest) -> BoxFuture<'a, Vec<u8>>;
}