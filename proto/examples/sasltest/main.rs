use futures_util::AsyncRead;
use futures_util::AsyncReadExt;
use ldap3_proto::parse_ldap_filter_str;
use openssl::ssl::Ssl;
use openssl::ssl::SslConnector;
use openssl::ssl::SslMethod;
use openssl::ssl::SslVerifyMode;
use sspi::builders::EmptyInitializeSecurityContext;
use sspi::generator;
use sspi::generator::GeneratorInitSecurityContext;
use sspi::generator::NetworkRequest;
use sspi::negotiate;
use sspi::AuthIdentity;
use sspi::ClientRequestFlags;
use sspi::CredentialUse;
use sspi::DataRepresentation;
use sspi::InitializeSecurityContextResult;
use sspi::Kerberos;
use sspi::KerberosConfig;
use sspi::Negotiate;
use sspi::NegotiateConfig;
use sspi::Ntlm;
use sspi::SecurityBuffer;
use sspi::SecurityBufferType;
use sspi::SecurityStatus;
use sspi::Sspi;
use sspi::SspiImpl;
use sspi::Username;
use std::env;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;
use tokio_util::codec::Framed;
use tracing::Level;

use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;

use ldap3_proto::proto::*;
use ldap3_proto::LdapCodec;

mod codec;

async fn get_tcp_frame() -> Framed<TcpStream, LdapCodec> where
{
    // let ldap_server_addr = env::var("LDAP_SERVER_ADDR").unwrap(); // domain.com:port
    let ldap_server_addr = "10.10.0.3:389";
    let addr = SocketAddr::from_str(&ldap_server_addr).expect(&format!(
        "Unable to parse address, addr is {:?}",
        &ldap_server_addr
    ));

    let tcpstream = TcpStream::connect(addr).await.expect("failed to connect");

    let framed = Framed::new(tcpstream, LdapCodec::default());
    // let mut framed = Framed::new(tcpstream, LdapCodec);
    return framed;
}

async fn get_tls_frame() -> Framed<SslStream<TcpStream>, LdapCodec> where
{
    let ldap_server_addr = "10.10.0.3:636";
    let addr = SocketAddr::from_str(&ldap_server_addr).expect(&format!(
        "Unable to parse address, addr is {:?}",
        &ldap_server_addr
    ));

    let tcpstream = TcpStream::connect(addr).await.unwrap();

    let mut tls_parms = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| {
            eprintln!("openssl -> {:?}", e);
        })
        .unwrap();
    tls_parms.set_verify(SslVerifyMode::NONE);
    let tls_parms = tls_parms.build();

    let mut tlsstream = Ssl::new(tls_parms.context())
        .and_then(|tls_obj| SslStream::new(tls_obj, tcpstream))
        .map_err(|e| {
            eprintln!("Failed to initialise TLS -> {:?}", e);
        })
        .unwrap();

    let _ = SslStream::connect(Pin::new(&mut tlsstream))
        .await
        .map_err(|e| {
            eprintln!("Failed to initialise TLS -> {:?}", e);
        })
        .unwrap();

    let framed = Framed::new(tlsstream, LdapCodec::default());

    return framed;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subs = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();

    tracing::subscriber::set_global_default(subs).expect("setting default subscriber failed");

    // let mut framed = get_tcp_frame().await;
    let mut framed = get_tls_frame().await;

    let mut auth = NegotiateAuthProvier::new(
        "Administrator@ad.it-help.ninja",
        "DevoLabs123!",
        "ad.it-help.ninja",
        "tcp://IT-HELP-DC.ad.it-help.ninja:88",
        "IT-HELP-DC.ad.it-help.ninja",
    );
    // let mut auth = KerberoAuthProvier::new(
    //     "Administrator@ad.it-help.ninja",
    //     "DevoLabs123!",
    //     "ad.it-help.ninja",
    //     "tcp://IT-HELP-DC.ad.it-help.ninja:88",
    //     "IT-HELP-DC.ad.it-help.ninja",
    // );
        

    /*
       NOTE:TLS with NTLM NO-INTEGRITY is working
            TLS with NTLM Confidentiality is not working with this example so far, it needs sasl encoding
            TCP with NTLM NO-INTEGRITY is working
    */
    // let mut auth = AuthProvier::new("Administrator@ad.it-help.ninja", "DevoLabs123!");
    let token = auth.step(&[]).await.expect("failed to get token");

    let msg = LdapMsg {
        msgid: 1,
        op: LdapOp::BindRequest(LdapBindRequest {
            dn: "".to_string(),
            cred: LdapBindCred::SASL(SaslCredentials {
                mechanism: "GSS-SPNEGO".to_string(),
                credentials: token,
            }),
        }),
        ctrl: vec![],
    };

    framed.send(msg).await.expect("failed to send bind request");
    loop {
        if let Some(Ok(msg)) = framed.next().await {
            if let LdapOp::BindResponse(res) = msg.op {
                match res.res.code {
                    LdapResultCode::Success => {
                        println!("Bind successful");
                        break;
                    }
                    LdapResultCode::SaslBindInProgress => {
                        if let Some(ref cred) = res.saslcreds {
                            let ntlm_token = auth.step(cred).await.unwrap();
                            let msg = LdapMsg {
                                msgid: 2,
                                op: LdapOp::BindRequest(LdapBindRequest {
                                    dn: "".to_string(),
                                    cred: LdapBindCred::SASL(SaslCredentials {
                                        mechanism: "GSS-SPNEGO".to_string(),
                                        credentials: ntlm_token,
                                    }),
                                }),
                                ctrl: vec![],
                            };

                            let _ = framed.send(msg).await?;
                        }
                    }
                    _ => {
                        panic!("Bind failed: {:?}", res)
                    }
                }
            }
        } else {
            panic!("Unable to get bind response, or server actively closed connection")
        }
    }

    // search for all users
    let msg = LdapMsg {
        msgid: 3,
        op: LdapOp::SearchRequest(LdapSearchRequest {
            base: "dc=ad,dc=it-help,dc=ninja".to_string(),
            scope: LdapSearchScope::Subtree,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter: parse_ldap_filter_str("(objectClass=*)").unwrap(),
            attrs: vec![],
            aliases: LdapDerefAliases::Never,
        }),
        ctrl: vec![],
    };

    framed.send(msg).await?;

    loop {
        if let Some(Ok(msg)) = framed.next().await {
            if let LdapOp::SearchResultEntry(res) = msg.op {
                println!("Entry: {:?}", res);
            }
        } else {
            break;
        }
    }

    Ok(())
}

struct AuthProvier {
    ntlm: Ntlm,
    credentials_handle: <Ntlm as SspiImpl>::CredentialsHandle,
}

impl AuthProvier {
    fn new(ldap_username: &str, ldap_password: &str) -> Self {
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

    async fn step(&mut self, input: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];

        let mut input_buffer = vec![SecurityBuffer::new(
            input.to_vec().clone(),
            SecurityBufferType::Token,
        )];
        let mut builder =
            EmptyInitializeSecurityContext::<<Ntlm as SspiImpl>::CredentialsHandle>::new()
                .with_credentials_handle(&mut self.credentials_handle)
                .with_context_requirements(
                    ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::ALLOCATE_MEMORY,
                )
                .with_target_data_representation(DataRepresentation::Native)
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

pub(crate) struct NegotiateAuthProvier {
    negotiate: Negotiate,
    credentials_handle: <Negotiate as SspiImpl>::CredentialsHandle,
}

impl NegotiateAuthProvier {
    pub(crate) fn new(
        ldap_username: &str,
        ldap_password: &str,
        domain: &str,
        kdc_proxy_url: &str,
        client_computer_name: &str,
    ) -> Self {
        let identity = AuthIdentity {
            username: Username::parse(ldap_username).unwrap(),
            password: ldap_password.to_string().into(),
        };

        let krb_config = KerberosConfig::new(kdc_proxy_url, client_computer_name.to_string());
        let negotiate_config = NegotiateConfig::from_protocol_config(
            Box::new(krb_config),
            client_computer_name.to_string(),
        );

        let mut negotiate = Negotiate::new(negotiate_config).expect("failed to create negotiate");

        let acq_cred_result = negotiate
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity.into())
            .execute()
            .unwrap();

        Self {
            negotiate,
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
            EmptyInitializeSecurityContext::<<Negotiate as SspiImpl>::CredentialsHandle>::new()
                .with_credentials_handle(&mut self.credentials_handle)
                .with_context_requirements(
                    ClientRequestFlags::ALLOCATE_MEMORY
                        | ClientRequestFlags::MUTUAL_AUTH
                        | ClientRequestFlags::REPLAY_DETECT,
                )
                .with_target_data_representation(DataRepresentation::Native)
                .with_target_name("LDAP/IT-HELP-DC.ad.it-help.ninja")
                .with_input(&mut input_buffer)
                .with_output(&mut output_buffer);

        let generator = self.negotiate.initialize_security_context_impl(&mut builder);

        let result = resolve_generator(generator)
            .await
            .expect("failed to get token");

        if [
            SecurityStatus::CompleteAndContinue,
            SecurityStatus::CompleteNeeded,
        ]
        .contains(&result.status)
        {
            println!("Completing the token...");
            self.negotiate.complete_auth_token(&mut output_buffer)?;
        }

        Ok(output_buffer[0].buffer.clone())
    }

}

pub(crate) struct KerberoAuthProvier {
    kerbero: Kerberos,
    credentials_handle: <Kerberos as SspiImpl>::CredentialsHandle,
}

impl KerberoAuthProvier {
    // new func, takes username and password, domian ,kdc_proxy_url and returns Self
    pub(crate) fn new(
        ldap_username: &str,
        ldap_password: &str,
        _domain: &str,
        kdc_proxy_url: &str,
        client_computer_name: &str,
    ) -> Self {
        let identity = AuthIdentity {
            username: Username::parse(ldap_username).unwrap(), // username@domain
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
                .with_context_requirements(
                    ClientRequestFlags::ALLOCATE_MEMORY
                        | ClientRequestFlags::MUTUAL_AUTH
                        | ClientRequestFlags::REPLAY_DETECT,
                )
                .with_target_data_representation(DataRepresentation::Native)
                .with_target_name("LDAP/IT-HELP-DC.ad.it-help.ninja")
                .with_input(&mut input_buffer)
                .with_output(&mut output_buffer);

        let generator = self.kerbero.initialize_security_context_impl(&mut builder);

        let result = resolve_generator(generator)
            .await
            .expect("failed to get token");

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

async fn resolve_generator<'a>(
    mut generator: GeneratorInitSecurityContext<'a>,
) -> Result<InitializeSecurityContextResult, Box<dyn std::error::Error>> {
    let mut state = generator.start();
    loop {
        match state {
            generator::GeneratorState::Suspended(req) => {
                let res = send(&req).await.expect("failed to send request");
                state = generator.resume(Ok(res));
            }
            generator::GeneratorState::Completed(v) => break v.map_err(|e| e.into()),
        }
    }
}

async fn send(req: &NetworkRequest) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match req.protocol {
        sspi::network_client::NetworkProtocol::Https
        | sspi::network_client::NetworkProtocol::Http => {
            let url = req.url.as_str();
            let data = req.data.clone();

            let client = reqwest::Client::new();
            let res = client.post(url).body(data).send().await?;
            let bytes_res = res.bytes().await?;
            Ok(bytes_res.to_vec())
        }
        sspi::network_client::NetworkProtocol::Tcp => {
            println!("tcp : {:?}", &req.url);
            let addr = format!(
                "{}:{}",
                &req.url.host_str().unwrap_or_default(),
                &req.url.port().unwrap_or(88)
            );
            let tcpstream = TcpStream::connect(addr).await?;
            tcpstream.writable().await?;
            tcpstream
                .try_write(&req.data)
                .expect("failed to write to tcp stream");

            tcpstream.readable().await?;
            let mut buf = vec![0; 8064];
            let len = tcpstream.try_read(&mut buf)?;
            buf.truncate(len);
            Ok(buf)
        }
        sspi::network_client::NetworkProtocol::Udp => {
            //same as tcp
            let addr = SocketAddr::from_str(req.url.as_str()).expect("failed to parse url");
            let udpsocket = tokio::net::UdpSocket::bind(addr).await?;
            udpsocket.writable().await?;
            udpsocket
                .try_send(&req.data)
                .expect("failed to write to udp socket");

            udpsocket.readable().await?;
            let mut buf = vec![0; 8064];
            let len = udpsocket.try_recv(&mut buf)?;
            buf.truncate(len);
            Ok(buf)
        }
    }
}
