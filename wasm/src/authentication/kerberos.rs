use anyhow::Context;
use futures_util::future::LocalBoxFuture;
use sspi::{
    builders::EmptyInitializeSecurityContext, detect_kdc_url, AuthIdentity, ClientRequestFlags,
    CredentialUse, DataRepresentation, EncryptionFlags, Kerberos, KerberosConfig, SecurityBuffer,
    SecurityBufferType, SecurityStatus, Sspi, SspiImpl, Username,
};
use tracing::debug;

use super::{AsyncNetworkClient, SecurityProvider, SecurityProviderError, StepResult};

pub struct KerberoAuthProvier {
    kerbero: Kerberos,
    credentials_handle: <Kerberos as SspiImpl>::CredentialsHandle,
    server_computer_name: String,
    sign: Option<bool>,
    seal: Option<bool>,
    client: Box<dyn AsyncNetworkClient>,
    sequence_number: u32,
    recv_sequence_number: u32,
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
            Ok(username) => username,
            Err(_) => Username::new(ldap_username, domain)
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

        let mut kerbero = Kerberos::new_client_from_config(kerb_config).unwrap();

        let acq_cred_result = kerbero
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity.into())
            .execute()
            .unwrap();

        let client = client.unwrap();

        let res = Self {
            kerbero,
            credentials_handle: acq_cred_result.credentials_handle,
            server_computer_name: server_computer_name.to_string(),
            sign,
            seal,
            client,
            sequence_number: 0,
            recv_sequence_number: 0,
            context_status: None,
        };

        Ok(res)
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
                let mut generator = self.kerbero.initialize_security_context_impl(&mut builder);
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

            Ok(output_buffer[0].buffer.clone())
        })
    }

    fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, super::SecurityProviderError> {
        let mut msg_buffer = vec![
            SecurityBuffer::new(Vec::new(), SecurityBufferType::Token),
            SecurityBuffer::new(input.to_vec(), SecurityBufferType::Data),
            SecurityBuffer::new(Vec::new(), SecurityBufferType::Padding),
        ];
        let seq = self.next_sequence_number();
        self.kerbero
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

    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, super::SecurityProviderError> {
        if (input.len() as u32) < 4 {
            return Err(SecurityProviderError::BufferNotLargeEnough(4));
        }
        let length = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);

        if length != input.len() as u32 - 4 {
            return Err(SecurityProviderError::BufferNotLargeEnough(length + 4));
        }

        let rest = input[4..].to_vec();
        let mut msg_buffer = vec![
            SecurityBuffer::new(rest[..60].to_vec(), SecurityBufferType::Token),
            SecurityBuffer::new(rest[60..].to_vec(), SecurityBufferType::Data),
        ];

        let seq = self.next_recv_sequence_number();

        self.kerbero.decrypt_message(&mut msg_buffer, seq)?;

        let SecurityBuffer { buffer: data, .. } = msg_buffer.pop().ok_or(
            SecurityProviderError::Unreachable("missing data buffer".to_string()),
        )?;

        Ok(data)
    }

    fn status(&self) -> Option<sspi::SecurityStatus> {
        self.context_status
    }
}
