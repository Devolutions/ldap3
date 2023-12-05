use sspi::{
    builders::EmptyInitializeSecurityContext, AuthIdentity, ClientRequestFlags, CredentialUse,
    DataRepresentation, Ntlm, SecurityBuffer, SecurityBufferType, SecurityStatus, Sspi, SspiImpl,
    Username,
};

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
