use futures_util::future::LocalBoxFuture;
use sspi::{
    builders::EmptyInitializeSecurityContext, ntlm::NtlmConfig, AuthIdentity, ClientRequestFlags,
    CredentialUse, DataRepresentation, KerberosConfig, Negotiate, NegotiateConfig, SecurityBuffer,
    SecurityBufferType, SecurityStatus, Sspi, SspiImpl, Username,
};
use tracing::debug;

use super::{SecurityProvider, StepResult, WasmNetworkClient};
pub struct NegotiateAuthProvier {
    negotiate: Negotiate,
    credentials_handle: <Negotiate as SspiImpl>::CredentialsHandle,
    server_computer_name: String,
}

impl NegotiateAuthProvier {
    pub(crate) fn new(
        ldap_username: &str,
        ldap_password: &str,
        domain: Option<&str>,
        kdc_proxy_url: Option<&str>,
        client_computer_name: &str,
        server_computer_name: &str,
    ) -> Self {
        let identity = AuthIdentity {
            username: Username::new(ldap_username, domain).unwrap(),
            password: ldap_password.to_string().into(),
        };

        let negotiate_config = match kdc_proxy_url {
            Some(url) => {
                let kerb_config = KerberosConfig::new(url, client_computer_name.to_string());
                NegotiateConfig::from_protocol_config(
                    Box::new(kerb_config),
                    client_computer_name.to_string(),
                )
            }
            None => {
                let ntlm_config = NtlmConfig::new(client_computer_name.to_string());
                NegotiateConfig::from_protocol_config(
                    Box::new(ntlm_config),
                    client_computer_name.to_string(),
                )
            }
        };

        let mut negotiate = Negotiate::new(negotiate_config).unwrap();

        let acq_cred_result = negotiate
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity.into())
            .execute()
            .unwrap();

        Self {
            negotiate,
            credentials_handle: acq_cred_result.credentials_handle,
            server_computer_name: server_computer_name.to_string(),
        }
    }
}

impl SecurityProvider for NegotiateAuthProvier {
    fn step<'a>(&'a mut self, input: &'a [u8]) -> LocalBoxFuture<'a, StepResult> {
        Box::pin(async move {
            let mut output_buffer =
                vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];

            let mut input_buffer = vec![SecurityBuffer::new(
                input.to_vec().clone(),
                SecurityBufferType::Token,
            )];
            let target_name = format!("LDAP/{}", self.server_computer_name);
            let mut builder =
                EmptyInitializeSecurityContext::<<Negotiate as SspiImpl>::CredentialsHandle>::new()
                    .with_credentials_handle(&mut self.credentials_handle)
                    .with_context_requirements(
                        ClientRequestFlags::ALLOCATE_MEMORY | ClientRequestFlags::MUTUAL_AUTH,
                    )
                    .with_target_data_representation(DataRepresentation::Native)
                    .with_target_name(&target_name)
                    .with_input(&mut input_buffer)
                    .with_output(&mut output_buffer);

            let result = {
                let clinet = WasmNetworkClient;
                let mut generator = self
                    .negotiate
                    .initialize_security_context_impl(&mut builder);
                let mut state = generator.start();

                loop {
                    match state {
                        sspi::generator::GeneratorState::Suspended(req) => {
                            let res = clinet.send(&req).await;
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

            Ok(output_buffer[0].buffer.clone())
        })
    }
}
