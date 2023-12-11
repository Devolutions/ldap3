use sspi::{
    builders::EmptyInitializeSecurityContext, generator::NetworkRequest,
    network_client::NetworkProtocol, AuthIdentity, ClientRequestFlags, CredentialUse,
    DataRepresentation, Kerberos, KerberosConfig, Ntlm, SecurityBuffer, SecurityBufferType,
    SecurityStatus, Sspi, SspiImpl, Username,
};
use tracing::debug;

pub mod ntlm;

pub(crate) struct AuthProvier {
    ntlm: Ntlm,
    credentials_handle: <Ntlm as SspiImpl>::CredentialsHandle,
}

impl AuthProvier {
    pub(crate) fn new(ldap_username: &str, ldap_password: &str) -> Self {
        let identity = AuthIdentity {
            username: Username::parse(ldap_username).unwrap(),
            password: ldap_password.to_string().into(),
        };

        let mut ntlm = Ntlm::new();

        let acq_cred_result = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute()
            .unwrap();

        Self {
            ntlm,
            credentials_handle: acq_cred_result.credentials_handle,
        }
    }

    pub(crate) fn step(&mut self, input: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];

        let mut input_buffer = vec![SecurityBuffer::new(
            input.to_vec().clone(),
            SecurityBufferType::Token,
        )];
        let mut builder =
            EmptyInitializeSecurityContext::<<Ntlm as SspiImpl>::CredentialsHandle>::new()
                .with_credentials_handle(&mut self.credentials_handle)
                .with_context_requirements(ClientRequestFlags::ALLOCATE_MEMORY)
                .with_target_data_representation(DataRepresentation::Native)
                .with_target_name("ldap/ldapserver.domain.com")
                .with_input(&mut input_buffer)
                .with_output(&mut output_buffer);

        let result = self
            .ntlm
            .initialize_security_context_impl(&mut builder)
            .resolve_to_result()?;

        if [
            SecurityStatus::CompleteAndContinue,
            SecurityStatus::CompleteNeeded,
        ]
        .contains(&result.status)
        {
            println!("Completing the token...");
            self.ntlm.complete_auth_token(&mut output_buffer)?;
        }

        Ok(output_buffer[0].buffer.clone())
    }
}

struct KerberoAuthProvier {
    kerbero: Kerberos,
    credentials_handle: <Kerberos as SspiImpl>::CredentialsHandle,
}

impl KerberoAuthProvier {
    // new func, takes username and password, domian ,kdc_proxy_url and returns Self
    pub(crate) fn new(
        ldap_username: &str,
        ldap_password: &str,
        domain: &str,
        kdc_proxy_url: &str,
        client_computer_name: &str,
    ) -> Self {
        let identity = AuthIdentity {
            username: Username::new(ldap_username, Some(domain)).unwrap(),
            password: ldap_password.to_string().into(),
        };

        let kerb_config = KerberosConfig::new(kdc_proxy_url, client_computer_name.to_string());

        let mut kerbero = Kerberos::new_client_from_config(kerb_config).unwrap();

        let acq_cred_result = kerbero
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity.into())
            .execute()
            .unwrap();

        Self {
            kerbero,
            credentials_handle: acq_cred_result.credentials_handle,
        }
    }

    pub(crate) async fn step(
        &mut self,
        input: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];

        let mut input_buffer = vec![SecurityBuffer::new(
            input.to_vec().clone(),
            SecurityBufferType::Token,
        )];
        let mut builder =
            EmptyInitializeSecurityContext::<<Kerberos as SspiImpl>::CredentialsHandle>::new()
                .with_credentials_handle(&mut self.credentials_handle)
                .with_context_requirements(ClientRequestFlags::ALLOCATE_MEMORY)
                .with_target_data_representation(DataRepresentation::Native)
                .with_target_name("ldap/ldapserver.domain.com")
                .with_input(&mut input_buffer)
                .with_output(&mut output_buffer);
        let mut clinet = WasmNetworkClient;
        let result = {
            let mut generator = self.kerbero.initialize_security_context_impl(&mut builder);
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
            println!("Completing the token...");
            self.kerbero.complete_auth_token(&mut output_buffer)?;
        }

        Ok(output_buffer[0].buffer.clone())
    }
}

#[derive(Debug)]
pub(crate) struct WasmNetworkClient;

impl WasmNetworkClient {
    async fn send<'a>(&mut self, network_request: &NetworkRequest) -> Vec<u8> {
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
            unsupported => panic!("unsupported protocol: {:?}", unsupported),
        }
    }
}
