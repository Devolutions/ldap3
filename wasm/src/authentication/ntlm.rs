use futures_util::future::LocalBoxFuture;
use sspi::{
    builders::EmptyInitializeSecurityContext, AuthIdentity, BufferType, ClientRequestFlags,
    CredentialUse, DataRepresentation, EncryptionFlags, Ntlm, SecurityBuffer, SecurityBufferRef,
    SecurityStatus, Sspi, SspiImpl, Username,
};

use super::{SecurityProvider, SecurityProviderError, StepResult};
pub(crate) struct NtlmAuthProvier {
    ntlm: Ntlm,
    credentials_handle: <Ntlm as SspiImpl>::CredentialsHandle,
    server_computer_name: String,
    sign: Option<bool>,
    seal: Option<bool>,
    sequence_number: u32,
    recv_sequence_number: u32,
    status: Option<SecurityStatus>,
}

impl NtlmAuthProvier {
    pub(crate) fn new(
        ldap_username: &str,
        ldap_password: &str,
        server_computer_name: &str,
        sign: Option<bool>,
        seal: Option<bool>,
    ) -> anyhow::Result<Self> {
        let identity = AuthIdentity {
            username: Username::parse(ldap_username).unwrap(),
            password: ldap_password.to_string().into(),
        };

        let mut ntlm = Ntlm::new();

        let acq_cred_result = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute(&mut ntlm)?;

        Ok(Self {
            ntlm,
            credentials_handle: acq_cred_result.credentials_handle,
            server_computer_name: server_computer_name.to_string(),
            sign,
            seal,
            sequence_number: 0,
            recv_sequence_number: 0,
            status: None,
        })
    }

    fn next_sequence_number(&mut self) -> u32 {
        let res = self.sequence_number;
        self.sequence_number += 1;
        res
    }

    fn next_recv_sequence_number(&mut self) -> u32 {
        let res = self.recv_sequence_number;
        self.recv_sequence_number += 1;
        res
    }
}
impl SecurityProvider for NtlmAuthProvier {
    fn step<'a>(&'a mut self, input: &'a [u8]) -> LocalBoxFuture<'a, StepResult> {
        Box::pin(async move {
            let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];

            let mut input_buffer = vec![SecurityBuffer::new(
                input.to_vec().clone(),
                BufferType::Token,
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
                EmptyInitializeSecurityContext::<<Ntlm as SspiImpl>::CredentialsHandle>::default()
                    .with_credentials_handle(&mut self.credentials_handle)
                    .with_context_requirements(flag)
                    .with_target_data_representation(DataRepresentation::Native)
                    .with_target_name(&target_name)
                    .with_input(&mut input_buffer)
                    .with_output(&mut output_buffer);

            let result = self
                .ntlm
                .initialize_security_context_impl(&mut builder)?
                .resolve_to_result()?;
            self.status = Some(result.status);

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

    fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecurityProviderError> {
        let mut input = input.to_vec();

        let security_trailer_len = self.ntlm.query_context_sizes()?.security_trailer as usize;
        let mut token = vec![0; security_trailer_len];

        let mut msg_buffer = vec![
            SecurityBufferRef::token_buf(&mut token),
            SecurityBufferRef::data_buf(&mut input),
            SecurityBufferRef::padding_buf(&mut []),
        ];
        let seq = self.next_sequence_number();
        self.ntlm
            .encrypt_message(EncryptionFlags::empty(), &mut msg_buffer, seq)?;

        let mut output = Vec::new();
        let length = msg_buffer[0].buf_len() as u32
            + msg_buffer[1].buf_len() as u32
            + msg_buffer[2].buf_len() as u32;
        let length_bytes = length.to_be_bytes();
        output.extend_from_slice(&length_bytes);
        output.extend_from_slice(msg_buffer[0].data());
        output.extend_from_slice(msg_buffer[1].data());
        output.extend_from_slice(msg_buffer[2].data());
        Ok(output)
    }

    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, SecurityProviderError> {
        let length = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
        tracing::debug!(
            "Decrypting message with length: {} vs the len expected is {}",
            input.len() as u32 - 4,
            length
        );

        if length != input.len() as u32 - 4 {
            return Err(SecurityProviderError::BufferNotLargeEnough(length + 4));
        }
        let mut first_16_bytes = input[4..20].to_vec();
        let mut data_buf = input[20..].to_vec();

        let mut msg_buffer = vec![
            SecurityBufferRef::token_buf(&mut first_16_bytes),
            SecurityBufferRef::data_buf(&mut data_buf),
        ];
        let seq = self.next_recv_sequence_number();
        self.ntlm.decrypt_message(&mut msg_buffer, seq)?;

        Ok(data_buf)
    }

    fn status(&self) -> Option<SecurityStatus> {
        self.status
    }
}
