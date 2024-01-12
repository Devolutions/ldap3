use futures_util::future::LocalBoxFuture;
use serde::de;
use sspi::{
    builders::EmptyInitializeSecurityContext, AuthIdentity, ClientRequestFlags, CredentialUse,
    DataRepresentation, EncryptionFlags, Ntlm, SecurityBuffer, SecurityBufferType, SecurityStatus,
    Sspi, SspiImpl, Username,
};

use super::{SecurityProvider, StepResult};
use crate::error::JsErrorValue;
use crate::{to_js_error, JsResult};
pub(crate) struct NtlmAuthProvier {
    ntlm: Ntlm,
    credentials_handle: <Ntlm as SspiImpl>::CredentialsHandle,
    server_computer_name: String,
    sign: Option<bool>,
    seal: Option<bool>,
    sequence_number: u32,
}

impl NtlmAuthProvier {
    pub(crate) fn new(
        ldap_username: &str,
        ldap_password: &str,
        server_computer_name: &str,
        sign: Option<bool>,
        seal: Option<bool>,
    ) -> Self {
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
            server_computer_name: server_computer_name.to_string(),
            sign,
            seal,
            sequence_number: 0,
        }
    }

    fn next_sequence_number(&mut self) -> u32 {
        self.sequence_number += 1;
        self.sequence_number
    }
}
impl SecurityProvider for NtlmAuthProvier {
    fn step<'a>(&'a mut self, input: &'a [u8]) -> LocalBoxFuture<'a, StepResult> {
        Box::pin(async move {
            let mut output_buffer =
                vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];

            let mut input_buffer = vec![SecurityBuffer::new(
                input.to_vec().clone(),
                SecurityBufferType::Token,
            )];
            let target_name = format!("LDAP/{}", self.server_computer_name);

            let mut flag = ClientRequestFlags::ALLOCATE_MEMORY;

            if self.sign.unwrap_or(false) {
                flag |= ClientRequestFlags::INTEGRITY;
            }

            if self.seal.unwrap_or(false) {
                flag |= ClientRequestFlags::CONFIDENTIALITY;
            }

            let mut builder =
                EmptyInitializeSecurityContext::<<Ntlm as SspiImpl>::CredentialsHandle>::new()
                    .with_credentials_handle(&mut self.credentials_handle)
                    .with_context_requirements(flag)
                    .with_target_data_representation(DataRepresentation::Native)
                    .with_target_name(&target_name)
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
                tracing::debug!("Completing the token...");
                self.ntlm.complete_auth_token(&mut output_buffer)?;
            }

            Ok(output_buffer[0].buffer.clone())
        })
    }

    fn encrypt(&mut self, input: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut msg_buffer = vec![
            SecurityBuffer::new(Vec::new(), SecurityBufferType::Token),
            SecurityBuffer::new(input.to_vec(), SecurityBufferType::Data),
            SecurityBuffer::new(Vec::new(), SecurityBufferType::Padding),
        ];
        let seq = self.next_sequence_number();
        self.ntlm
            .encrypt_message(EncryptionFlags::empty(), &mut msg_buffer, seq)?;

        let mut output = Vec::new();
        let length = msg_buffer[0].buffer.len() as u32
            + msg_buffer[1].buffer.len() as u32
            + msg_buffer[2].buffer.len() as u32;
        let length_bytes = length.to_be_bytes();
        output.extend_from_slice(&length_bytes);
        output.extend_from_slice(&msg_buffer[0].buffer);
        output.extend_from_slice(&msg_buffer[1].buffer);
        output.extend_from_slice(&msg_buffer[2].buffer);
        Ok(output)
    }

    fn decrypt(&mut self, input: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut msg_buffer = vec![SecurityBuffer::new(
            input.to_vec(),
            SecurityBufferType::Stream,
        )];
        let seq = self.next_sequence_number();
        self.ntlm.decrypt_message(&mut msg_buffer, seq)?;
        Ok(msg_buffer[0].buffer.clone())
    }
}
