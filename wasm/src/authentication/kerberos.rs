use anyhow::Context;
use futures_util::future::LocalBoxFuture;
use sspi::{
    builders::EmptyInitializeSecurityContext, detect_kdc_url, AuthIdentity, BufferType,
    ClientRequestFlags, CredentialUse, DataRepresentation, EncryptionFlags, KerberosConfig,
    Negotiate, NegotiateConfig, SecurityBuffer, SecurityBufferRef, SecurityStatus, Sspi, SspiImpl,
    Username,
};
use tracing::debug;

use super::{AsyncNetworkClient, SecurityProvider, SecurityProviderError, StepResult};

// FIXME: typo in Kerberos

pub struct KerberoAuthProvier {
    // Negotiate (SPNEGO) restricted to Kerberos: Windows LDAP expects a standard SPNEGO token, not a raw Kerberos one
    kerbero: Negotiate, // FIXME: typo
    credentials_handle: <Negotiate as SspiImpl>::CredentialsHandle,
    server_computer_name: String,
    sign: Option<bool>,
    seal: Option<bool>,
    client: Box<dyn AsyncNetworkClient>,
    context_status: Option<SecurityStatus>,
}

#[derive(typed_builder::TypedBuilder)]
pub struct KerberoInitParams<'a> {
    pub ldap_username: &'a str,
    pub ldap_password: &'a str,
    pub domain: Option<&'a str>,
    pub kdc_proxy_url: Option<&'a str>,
    pub client_computer_name: &'a str,
    pub server_computer_name: &'a str,
    pub sign: Option<bool>,
    pub seal: Option<bool>,
    pub client: Option<Box<dyn AsyncNetworkClient>>,
}

impl<'a> TryFrom<KerberoInitParams<'a>> for KerberoAuthProvier {
    type Error = anyhow::Error;
    fn try_from(value: KerberoInitParams) -> Result<KerberoAuthProvier, anyhow::Error> {
        KerberoAuthProvier::new(value)
    }
}

impl KerberoAuthProvier {
    pub(crate) fn new(params: KerberoInitParams) -> anyhow::Result<Self> {
        let KerberoInitParams {
            ldap_username,
            ldap_password,
            domain,
            kdc_proxy_url,
            client_computer_name,
            server_computer_name,
            sign,
            seal,
            client,
        } = params;

        let username = match Username::parse(ldap_username) {
            Ok(username) if username.domain_name().is_some() => username,
            _ => Username::new(ldap_username, domain)
                .with_context(|| format!("Failed to parse username: {}", ldap_username))?,
        };

        let clone = username.clone();
        let domain = match domain {
            Some(d) => d,
            None => clone
                .domain_name()
                .with_context(|| format!("Failed to parse domain: {}", ldap_username))?,
        };

        let identity = AuthIdentity {
            username,
            password: ldap_password.to_string().into(),
        };

        let url = match kdc_proxy_url {
            Some(k) => k.to_string(),
            None => {
                let url = detect_kdc_url(domain).ok_or(anyhow::anyhow!(
                    "Failed to detect KDC URL for domain: {}",
                    domain
                ))?;
                url.to_string()
            }
        };
        let kerb_config = KerberosConfig::new(&url, client_computer_name.to_string());
        if kerb_config.kdc_url.is_none() {
            anyhow::bail!("invalid KDC proxy URL");
        }

        let negotiate_config = NegotiateConfig::new(
            Box::new(kerb_config),
            Some("kerberos,!ntlm,!pku2u".to_string()),
            client_computer_name.to_string(),
        );
        let mut kerbero = Negotiate::new_client(negotiate_config)?;

        let acq_cred_result = kerbero
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity.into())
            .execute(&mut kerbero)?;

        let client = client.unwrap();

        let res = Self {
            kerbero,
            credentials_handle: acq_cred_result.credentials_handle,
            server_computer_name: server_computer_name.to_string(),
            sign,
            seal,
            client,
            context_status: None,
        };

        Ok(res)
    }
}

impl SecurityProvider for KerberoAuthProvier {
    fn step<'a>(&'a mut self, input: &'a [u8]) -> LocalBoxFuture<'a, StepResult> {
        Box::pin(async move {
            let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];

            let mut input_buffer = vec![SecurityBuffer::new(
                input.to_vec().clone(),
                BufferType::Token,
            )];
            let target_name = format!("LDAP/{}", self.server_computer_name);

            let mut flag = ClientRequestFlags::ALLOCATE_MEMORY | ClientRequestFlags::MUTUAL_AUTH;

            if self.sign.unwrap_or(false) {
                flag |= ClientRequestFlags::INTEGRITY;
            }

            if self.seal.unwrap_or(false) {
                flag |= ClientRequestFlags::CONFIDENTIALITY;
            }

            let mut builder = EmptyInitializeSecurityContext::<
                <Negotiate as SspiImpl>::CredentialsHandle,
            >::default()
            .with_credentials_handle(&mut self.credentials_handle)
            .with_context_requirements(flag)
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(&target_name)
            .with_input(&mut input_buffer)
            .with_output(&mut output_buffer);

            let result = {
                let mut generator = self
                    .kerbero
                    .initialize_security_context_impl(&mut builder)?;
                let mut state = generator.start();

                loop {
                    match state {
                        sspi::generator::GeneratorState::Suspended(req) => {
                            let res = self.client.send(req).await?;
                            state = generator.resume(Ok(res));
                        }
                        sspi::generator::GeneratorState::Completed(v) => break v,
                    }
                }
            }?;

            if [
                SecurityStatus::CompleteAndContinue,
                SecurityStatus::CompleteNeeded,
            ]
            .contains(&result.status)
            {
                debug!("Completing the token...");
                self.kerbero.complete_auth_token(&mut output_buffer)?;
            }

            self.context_status = Some(result.status);
            Ok(output_buffer[0].buffer.clone())
        })
    }

    fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, super::SecurityProviderError> {
        let mut input = input.to_vec();

        let security_trailer_len = self.kerbero.query_context_sizes()?.security_trailer as usize;
        let mut token = vec![0; security_trailer_len];

        let mut msg_buffer = vec![
            SecurityBufferRef::token_buf(&mut token),
            SecurityBufferRef::data_buf(&mut input),
        ];
        self.kerbero
            .encrypt_message(EncryptionFlags::empty(), &mut msg_buffer)?;

        let mut output = Vec::new();
        let length = msg_buffer[0].buf_len() as u32 + msg_buffer[1].buf_len() as u32;
        let length_bytes = length.to_be_bytes();
        output.extend_from_slice(&length_bytes);
        output.extend_from_slice(msg_buffer[0].data());
        output.extend_from_slice(msg_buffer[1].data());

        Ok(output)
    }

    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, super::SecurityProviderError> {
        if (input.len() as u32) < 4 {
            return Err(SecurityProviderError::BufferNotLargeEnough(4));
        }
        let length = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);

        if length != input.len() as u32 - 4 {
            return Err(SecurityProviderError::BufferNotLargeEnough(length + 4));
        }

        let security_trailer_len = self.kerbero.query_context_sizes()?.security_trailer as usize;

        let rest = &input[4..];
        let mut token_buf = rest[..security_trailer_len].to_vec();
        let mut data_buf = rest[security_trailer_len..].to_vec();

        let mut msg_buffer = vec![
            SecurityBufferRef::token_buf(&mut token_buf),
            SecurityBufferRef::data_buf(&mut data_buf),
        ];

        self.kerbero.decrypt_message(&mut msg_buffer)?;

        Ok(data_buf)
    }

    fn status(&self) -> Option<sspi::SecurityStatus> {
        self.context_status
    }
}

#[cfg(test)]
mod tests {
    use super::{KerberoAuthProvier, KerberoInitParams};
    use crate::authentication::{SecurityProvider, TestNetworkClient};
    use futures_util::FutureExt;
    use sspi::{AuthIdentity, CredentialsBuffers};

    #[test]
    fn provided_domain_is_preserved() {
        for (username, domain, expected_domain) in [
            ("alice", Some("ad.example.test"), "ad.example.test"),
            ("OTHER\\alice", Some("ad.example.test"), "OTHER"),
            (
                "alice@other.example.test",
                Some("ad.example.test"),
                "other.example.test",
            ),
            ("alice@other.example.test", None, "other.example.test"),
        ] {
            let params = KerberoInitParams::builder()
                .ldap_username(username)
                .ldap_password("not-a-real-password")
                .domain(domain)
                .kdc_proxy_url(Some("https://gateway.example.test/jet/KdcProxy/test"))
                .client_computer_name("test-client")
                .server_computer_name("dc.ad.example.test")
                .sign(Some(true))
                .seal(Some(true))
                .client(Some(Box::new(TestNetworkClient::default())))
                .build();
            let provider = KerberoAuthProvier::new(params).expect("provider");
            let identity = match provider.credentials_handle.as_ref() {
                Some(CredentialsBuffers::AuthIdentity(identity)) => {
                    AuthIdentity::try_from(identity).expect("identity")
                }
                _ => panic!("expected password credentials"),
            };

            assert_eq!(identity.username.account_name(), "alice");
            assert_eq!(identity.username.domain_name(), Some(expected_domain));
        }
    }

    #[test]
    fn kerberos_requires_kdc_before_a_bind() {
        let network = TestNetworkClient::default();
        let url = "https://gateway.example.test/jet/KdcProxy/test";
        let params = KerberoInitParams::builder()
            .ldap_username("alice")
            .ldap_password("not-a-real-password")
            .domain(Some("ad.example.test"))
            .kdc_proxy_url(Some(url))
            .client_computer_name("test-client")
            .server_computer_name("dc.ad.example.test")
            .sign(Some(true))
            .seal(Some(true))
            .client(Some(Box::new(network.clone())))
            .build();
        let mut provider = KerberoAuthProvier::new(params).expect("provider");
        let error = provider
            .step(&[])
            .now_or_never()
            .expect("synchronous test network")
            .expect_err("KDC failure must not emit an LDAP token");

        assert!(error.to_string().contains("KDC blocked by regression test"));
        assert_eq!(provider.status(), None);
        let requests = network.requests.borrow();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url.as_str(), url);
        assert!(requests[0]
            .data
            .windows(b"AD.EXAMPLE.TEST".len())
            .any(|value| value == b"AD.EXAMPLE.TEST"));
    }
}
