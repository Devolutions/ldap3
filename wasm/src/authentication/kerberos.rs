use futures_util::future::LocalBoxFuture;
use sspi::{
    builders::EmptyInitializeSecurityContext, AuthIdentity, ClientRequestFlags, CredentialUse,
    DataRepresentation, EncryptionFlags, Kerberos, KerberosConfig, SecurityBuffer,
    SecurityBufferType, SecurityStatus, Sspi, SspiImpl, Username,
};
use tracing::debug;

use super::{SecurityProvider, StepResult, WasmNetworkClient};
pub struct KerberoAuthProvier {
    kerbero: Kerberos,
    credentials_handle: <Kerberos as SspiImpl>::CredentialsHandle,
    server_computer_name: String,
    sign: Option<bool>,
    seal: Option<bool>,
    sequence_number: u32,
}

impl KerberoAuthProvier {
    // new func, takes username and password, domian ,kdc_proxy_url and returns Self
    pub(crate) fn new(
        ldap_username: &str,
        ldap_password: &str,
        domain: &str,
        kdc_proxy_url: &str,
        client_computer_name: &str,
        server_computer_name: &str,
        sign: Option<bool>,
        seal: Option<bool>,
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
            server_computer_name: server_computer_name.to_string(),
            sign,
            seal,
            sequence_number: 0,
        }
    }
    fn next_sequence_number(&mut self) -> u32 {
        let res = self.sequence_number;
        self.sequence_number += 1;
        res
    }
}

impl SecurityProvider for KerberoAuthProvier {
    fn step<'a>(&'a mut self, input: &'a [u8]) -> LocalBoxFuture<'a, StepResult> {
        Box::pin(async move {
            let mut output_buffer =
                vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];

            let mut input_buffer = vec![SecurityBuffer::new(
                input.to_vec().clone(),
                SecurityBufferType::Token,
            )];
            let target_name = format!("LDAP/{}", self.server_computer_name);

            let mut flag = ClientRequestFlags::ALLOCATE_MEMORY | ClientRequestFlags::MUTUAL_AUTH;

            if self.sign.unwrap_or(false) {
                flag |= ClientRequestFlags::INTEGRITY;
            }

            if self.seal.unwrap_or(false) {
                flag |= ClientRequestFlags::CONFIDENTIALITY;
            }

            let mut builder =
                EmptyInitializeSecurityContext::<<Kerberos as SspiImpl>::CredentialsHandle>::new()
                    .with_credentials_handle(&mut self.credentials_handle)
                    .with_context_requirements(flag)
                    .with_target_data_representation(DataRepresentation::Native)
                    .with_target_name(&target_name)
                    .with_input(&mut input_buffer)
                    .with_output(&mut output_buffer);

            let result = {
                let clinet = WasmNetworkClient;
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
                debug!("Completing the token...");
                self.kerbero.complete_auth_token(&mut output_buffer)?;
            }

            Ok(output_buffer[0].buffer.clone())
        })
    }

    fn encrypt(&mut self, input: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut msg_buffer = vec![SecurityBuffer::new(input, SecurityBufferType::Stream)];

        let seq = self.next_sequence_number();
        self.kerbero
            .encrypt_message(EncryptionFlags::empty(), &mut msg_buffer, seq)?;
        Ok(msg_buffer[0].buffer.clone())
    }

    fn decrypt(&mut self, input: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut msg_buffer = vec![SecurityBuffer::new(input, SecurityBufferType::Stream)];
        let seq = self.next_sequence_number();
        self.kerbero.decrypt_message(&mut msg_buffer, seq)?;
        Ok(msg_buffer[0].buffer.clone())
    }
}
