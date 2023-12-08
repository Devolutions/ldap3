use sspi::{
    builders::EmptyInitializeSecurityContext, generator::NetworkRequest,
    network_client::NetworkProtocol, AuthIdentity, ClientRequestFlags, CredentialUse,
    DataRepresentation, Kerberos, KerberosConfig, Ntlm, SecurityBuffer, SecurityBufferType,
    SecurityStatus, Sspi, SspiImpl, Username,
};
use tracing::debug;

pub mod ntlm;
pub mod kerberos;

pub trait SecurityProvider {
    fn step(&mut self, input: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}