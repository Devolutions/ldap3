use anyhow::Context;
use futures_util::future::LocalBoxFuture;
use sspi::{
    builders::EmptyInitializeSecurityContext, ntlm::NtlmConfig, AuthIdentity, BufferType,
    ClientRequestFlags, CredentialUse, DataRepresentation, EncryptionFlags, KerberosConfig,
    Negotiate, NegotiateConfig, SecurityBuffer, SecurityBufferRef, SecurityStatus, Sspi, SspiImpl,
    Username,
};
use tracing::debug;

use super::{
    kerberos::KerberoInitParams, AsyncNetworkClient, SecurityProvider, SecurityProviderError,
    StepResult,
};
pub struct NegotiateAuthProvier {
    negotiate: Negotiate,
    credentials_handle: <Negotiate as SspiImpl>::CredentialsHandle,
    server_computer_name: String,
    sign: Option<bool>,
    seal: Option<bool>,
    client: Box<dyn AsyncNetworkClient>,
    context_status: Option<SecurityStatus>,
}

impl TryFrom<KerberoInitParams<'_>> for NegotiateAuthProvier {
    type Error = anyhow::Error;

    fn try_from(value: KerberoInitParams) -> Result<Self, Self::Error> {
        NegotiateAuthProvier::new(value)
    }
}

impl NegotiateAuthProvier {
    pub(crate) fn new(param: KerberoInitParams) -> anyhow::Result<Self> {
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
        } = param;

        let kdc_proxy_url = kdc_proxy_url.filter(|url| !url.trim().is_empty());
        // Preserve NTLM's existing challenge-domain behavior when no KDC proxy is configured.
        let username = match Username::parse(ldap_username) {
            Ok(username) if username.domain_name().is_some() || kdc_proxy_url.is_none() => username,
            _ => Username::new(ldap_username, domain).context("failed to parse username")?,
        };

        let identity = AuthIdentity {
            username,
            password: ldap_password.to_string().into(),
        };

        let negotiate_config = match kdc_proxy_url {
            Some(url) => {
                let kerb_config = KerberosConfig::new(url, client_computer_name.to_string());
                if kerb_config.kdc_url.is_none() {
                    anyhow::bail!("invalid KDC proxy URL");
                }
                NegotiateConfig::new(
                    Box::new(kerb_config),
                    Some("kerberos,!ntlm,!pku2u".to_string()),
                    client_computer_name.to_string(),
                )
            }
            None => {
                let ntlm_config = NtlmConfig::new(client_computer_name.to_string());
                NegotiateConfig::new(
                    Box::new(ntlm_config),
                    Some("ntlm,!kerberos,!pku2u".to_string()),
                    client_computer_name.to_string(),
                )
            }
        };

        let mut negotiate = Negotiate::new_client(negotiate_config)?;

        let acq_cred_result = negotiate
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity.into())
            .execute(&mut negotiate)?;

        let client = client.unwrap();

        let res = Self {
            negotiate,
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

impl SecurityProvider for NegotiateAuthProvier {
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
                    .negotiate
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
                self.negotiate.complete_auth_token(&mut output_buffer)?;
            }

            self.context_status = Some(result.status);
            Ok(output_buffer[0].buffer.clone())
        })
    }

    fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, super::SecurityProviderError> {
        let mut input = input.to_vec();

        let security_trailer_len = self.negotiate.query_context_sizes()?.security_trailer as usize;
        let mut token = vec![0; security_trailer_len];

        let mut msg_buffer = vec![
            SecurityBufferRef::token_buf(&mut token),
            SecurityBufferRef::data_buf(&mut input),
        ];
        self.negotiate
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
        let token_size = match self.negotiate.query_context_negotiation_package()?.name {
            sspi::SecurityPackageType::Ntlm => 16,
            sspi::SecurityPackageType::Kerberos => 60,
            _ => {
                return Err(SecurityProviderError::Other(
                    "unsupported negotiation package".to_string(),
                ))
            }
        };

        let rest = &input[4..];
        let mut token_buf = rest[..token_size].to_vec();
        let mut data_buf = rest[token_size..].to_vec();

        let mut msg_buffer = vec![
            SecurityBufferRef::token_buf(&mut token_buf),
            SecurityBufferRef::data_buf(&mut data_buf),
        ];

        self.negotiate.decrypt_message(&mut msg_buffer)?;

        Ok(data_buf)
    }

    fn status(&self) -> Option<sspi::SecurityStatus> {
        self.context_status
    }
}

#[cfg(test)]
mod tests {
    use super::{KerberoInitParams, NegotiateAuthProvier};
    use crate::authentication::{SecurityProvider, TestNetworkClient};
    use futures_util::FutureExt;
    use picky_krb::gss_api::{ApplicationTag0, GssApiNegInit};
    use sspi::{AuthIdentity, CredentialsBuffers};

    fn provider(
        username: &str,
        domain: Option<&str>,
        kdc_proxy_url: Option<&str>,
        protected: bool,
    ) -> anyhow::Result<(NegotiateAuthProvier, TestNetworkClient)> {
        let network = TestNetworkClient::default();
        let params = KerberoInitParams::builder()
            .ldap_username(username)
            .ldap_password("not-a-real-password")
            .domain(domain)
            .kdc_proxy_url(kdc_proxy_url)
            .client_computer_name("test-client")
            .server_computer_name("dc.ad.example.test")
            .sign(Some(protected))
            .seal(Some(protected))
            .client(Some(Box::new(network.clone())))
            .build();
        Ok((NegotiateAuthProvier::new(params)?, network))
    }

    fn identity(provider: &NegotiateAuthProvier) -> AuthIdentity {
        match provider.credentials_handle.as_ref() {
            Some(CredentialsBuffers::AuthIdentity(identity)) => {
                AuthIdentity::try_from(identity).expect("identity")
            }
            _ => panic!("expected password credentials"),
        }
    }

    #[test]
    fn provided_domain_is_preserved() {
        for (username, domain, expected_domain) in [
            ("alice", Some("ad.example.test"), Some("ad.example.test")),
            ("OTHER\\alice", Some("ad.example.test"), Some("OTHER")),
            (
                "alice@other.example.test",
                Some("ad.example.test"),
                Some("other.example.test"),
            ),
            ("alice", None, None),
        ] {
            let (provider, _) = provider(
                username,
                domain,
                Some("https://gateway.example.test/jet/KdcProxy/test"),
                true,
            )
            .expect("provider");
            let identity = identity(&provider);

            assert_eq!(identity.username.account_name(), "alice");
            assert_eq!(identity.username.domain_name(), expected_domain);
        }
    }

    #[test]
    fn no_kdc_only_offers_ntlm() {
        for (kdc, protected) in [
            (None, true),
            (None, false),
            (Some(""), true),
            (Some(""), false),
            (Some(" \t "), true),
            (Some(" \t "), false),
        ] {
            let (mut provider, network) =
                provider("alice", Some("ad.example.test"), kdc, protected).expect("provider");
            assert_eq!(identity(&provider).username.domain_name(), None);
            let token = provider
                .step(&[])
                .now_or_never()
                .expect("initial context does not require network access")
                .expect("initial context");

            let initial: ApplicationTag0<GssApiNegInit> =
                picky_asn1_der::from_bytes(&token).expect("valid SPNEGO");
            let oid: String = (&initial.0.oid.0).into();
            assert_eq!(oid, "1.3.6.1.5.5.2");
            let mechanisms = initial.0.neg_token_init.0.mech_types.0.expect("mechanisms");
            let ids: Vec<String> = mechanisms.0 .0
                .iter()
                .map(|mechanism| (&mechanism.0).into())
                .collect();
            assert_eq!(ids, ["1.3.6.1.4.1.311.2.2.10"]);
            let optimistic_token = initial
                .0
                .neg_token_init
                .0
                .mech_token
                .0
                .expect("optimistic NTLM token");
            assert!(optimistic_token.0 .0.starts_with(b"NTLMSSP\0"));
            assert!(network.requests.borrow().is_empty());
        }
    }

    #[test]
    fn rejects_kerberos_selection_without_kdc() {
        let kerberos_selection = [
            0xa1, 0x14, 0x30, 0x12, 0xa0, 0x03, 0x0a, 0x01, 0x01, 0xa1, 0x0b, 0x06, 0x09, 0x2a,
            0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02,
        ];
        let (mut provider, _) =
            provider("alice", Some("ad.example.test"), None, true).expect("provider");
        provider
            .step(&[])
            .now_or_never()
            .expect("initial context does not require network access")
            .expect("initial context");
        let error = provider
            .step(&kerberos_selection)
            .now_or_never()
            .expect("disabled mechanism does not require network access")
            .expect_err("disabled mechanism");

        assert!(error.to_string().contains(
            "Kerberos mechanism was selected by the server but is disabled in package_list"
        ));
    }

    #[test]
    fn kerberos_requires_kdc_before_a_bind_and_does_not_fall_back() {
        let url = "https://gateway.example.test/jet/KdcProxy/test";
        let (mut provider, network) =
            provider("alice", Some("ad.example.test"), Some(url), true).expect("provider");
        let error = provider
            .step(&[])
            .now_or_never()
            .expect("synchronous test network")
            .expect_err("KDC failure must not emit an LDAP or NTLM token");

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

    #[test]
    fn rejects_a_configured_invalid_kdc_proxy() {
        for url in ["https://", "http://"] {
            let error = provider("alice", Some("ad.example.test"), Some(url), true)
                .err()
                .expect("invalid proxy URL");

            assert!(error.to_string().contains("invalid KDC proxy URL"));
        }
    }
}
