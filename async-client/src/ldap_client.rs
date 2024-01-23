use std::sync::Arc;

use anyhow::Context;
use futures_util::{SinkExt, StreamExt};
use ldap3_proto::{
    control::LdapControl,
    parse_ldap_filter_str,
    proto::{
        LdapAddRequest, LdapAttribute, LdapBindCred, LdapBindRequest, LdapBindResponse, LdapModify,
        LdapModifyRequest, LdapOp, SaslCredentials,
    },
    LdapCodec, LdapMsg, LdapResultCode, LdapSearchScope,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
};
use tokio_util::codec::Framed;
use tracing::instrument;

use crate::{
    authentication::{
        kerberos::{KerberoAuthProvier, KerberoInitParams},
        negotiate::NegotiateAuthProvier,
        ntlm::NtlmAuthProvier,
        SecurityProvider,
    },
    encryption_stream::EncryptionStream,
    search::LdapSearchResultStream,
};

macro_rules! return_if_match {
    ($res:expr, $variant:path) => {
        match $res.op {
            $variant(_) => Ok($res),
            _ => Err(anyhow::anyhow!("Invalid response")),
        }
    };
}

pub(crate) type LdapFrame<T> = Framed<EncryptionStream<T>, LdapCodec>;
pub struct LdapAsyncClient<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    frame: Arc<Mutex<LdapFrame<T>>>,
    message_id: i32,
}

impl<T> LdapAsyncClient<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn next_message_id(&mut self) -> i32 {
        self.message_id += 1;
        self.message_id
    }

    pub fn frame(&self) -> Arc<Mutex<LdapFrame<T>>> {
        self.frame.clone()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchParameters {
    pub search_base: String,
    pub filter: String,
    pub scope: LdapSearchScope,
    pub attributes: Vec<String>,
    pub size_limit: Option<i32>,
    pub time_limit: Option<i32>,
    pub controls: Option<Vec<LdapControl>>,
}

impl<T> LdapAsyncClient<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn connect(stream: T) -> anyhow::Result<LdapAsyncClient<T>> {
        let encryption_stream = EncryptionStream::new(stream);
        let framed = Framed::new(encryption_stream, LdapCodec::default());
        let session = LdapAsyncClient {
            frame: Arc::new(Mutex::new(framed)),
            message_id: 0,
        };
        Ok(session)
    }

    #[instrument(skip(self))]
    pub async fn search(
        &mut self,
        search_parameters: SearchParameters,
    ) -> anyhow::Result<LdapSearchResultStream<T>> {
        let SearchParameters {
            search_base,
            filter,
            scope,
            attributes,
            size_limit,
            time_limit,
            controls,
        } = search_parameters;
        let filter = parse_ldap_filter_str(&filter)
            .with_context(|| format!("Unable to parse filter : {}", filter))?;
        tracing::trace!(?filter, ?attributes, ?controls);
        let next_msg_id = self.next_message_id();

        let mut framed = self.frame.lock().await;
        tracing::info!("Sending search request");
        framed
            .send(LdapMsg {
                msgid: next_msg_id,
                op: LdapOp::SearchRequest(ldap3_proto::proto::LdapSearchRequest {
                    scope,
                    sizelimit: size_limit.unwrap_or(10),
                    timelimit: time_limit.unwrap_or(10),
                    typesonly: false,
                    filter,
                    base: search_base,
                    aliases: ldap3_proto::proto::LdapDerefAliases::Always,
                    attrs: attributes,
                }),
                ctrl: controls.unwrap_or_default(),
            })
            .await
            .with_context(|| "Unable to send search request")?;
        tracing::info!("Search request sent");

        let stream = LdapSearchResultStream::new(self.frame.clone());
        Ok(stream)
    }

    pub async fn add(
        &mut self,
        dn: String,
        attributes: Vec<LdapAttribute>,
        controls: Option<Vec<LdapControl>>,
    ) -> anyhow::Result<LdapMsg> {
        let request = LdapAddRequest { dn, attributes };

        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::AddRequest(request),
            ctrl: controls.unwrap_or_default(),
        };

        let res = self.send_msg(msg).await?;
        return_if_match!(res, LdapOp::AddResponse)
    }

    pub async fn delete(
        &mut self,
        dn: String,
        controls: Option<Vec<LdapControl>>,
    ) -> anyhow::Result<LdapMsg> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::DelRequest(dn),
            ctrl: controls.unwrap_or_default(),
        };

        let res = self.send_msg(msg).await?;
        return_if_match!(res, LdapOp::DelResponse)
    }

    pub async fn modify_dn(
        &mut self,
        dn: String,
        newrdn: String,
        delete_old_rdn: bool,
        new_superior: Option<String>,
        controls: Option<Vec<LdapControl>>,
    ) -> anyhow::Result<LdapMsg> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::ModifyDNRequest(ldap3_proto::proto::LdapModifyDNRequest {
                dn,
                newrdn,
                deleteoldrdn: delete_old_rdn,
                new_superior,
            }),
            ctrl: controls.unwrap_or_default(),
        };

        let result = self.send_msg(msg).await?;
        return_if_match!(result, LdapOp::ModifyDNResponse)
    }

    pub async fn modify(
        &mut self,
        dn: String,
        changes: Vec<LdapModify>,
        controls: Option<Vec<LdapControl>>,
    ) -> anyhow::Result<LdapMsg> {
        let op = LdapOp::ModifyRequest(LdapModifyRequest { changes, dn });

        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op,
            ctrl: controls.unwrap_or_default(),
        };

        let res = self.send_msg(msg).await?;
        return_if_match!(res, LdapOp::ModifyResponse)
    }

    pub async fn compare(
        &mut self,
        dn: String,
        attribute: String,
        value: String,
        controls: Option<Vec<LdapControl>>,
    ) -> anyhow::Result<LdapMsg> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::CompareRequest(ldap3_proto::proto::LdapCompareRequest {
                dn,
                atype: attribute,
                val: value.as_bytes().to_vec(),
            }),
            ctrl: controls.unwrap_or_default(),
        };

        let res = self.send_msg(msg).await?;
        return_if_match!(res, LdapOp::CompareResult)
    }

    async fn send_msg(&mut self, msg: LdapMsg) -> anyhow::Result<LdapMsg> {
        let mut frame = self.frame.lock().await;
        frame
            .send(msg)
            .await
            .with_context(|| "Unable to send message")?;

        let res = frame
            .next()
            .await
            .with_context(|| "Unable to receive response")??;

        Ok(res)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaslBindConfig {
    pub username: String,
    pub password: String,
    pub auth_method: SspiAuthMethod,
    pub controls: Option<Vec<LdapControl>>,
    pub sign: Option<bool>,
    pub seal: Option<bool>,
}

impl<T> LdapAsyncClient<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[instrument(skip(self))]
    pub async fn bind(
        &mut self,
        distinguished_name: String,
        password: String,
        controls: Option<Vec<LdapControl>>,
    ) -> anyhow::Result<LdapMsg> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::BindRequest(LdapBindRequest {
                dn: distinguished_name,
                cred: LdapBindCred::Simple(password),
            }),
            ctrl: controls.unwrap_or_default(),
        };

        let res = self.send_msg(msg).await?;

        match &res.op {
            LdapOp::BindResponse(bind_response) => match &bind_response.res.code {
                ldap3_proto::proto::LdapResultCode::Success => Ok(res),
                _ => Err(anyhow::anyhow!("Bind failed : {:?}", bind_response)),
            },
            _ => Err(anyhow::anyhow!("Invalid response")),
        }
    }

    #[instrument(skip(self))]
    pub async fn unbind(&mut self, control: Option<Vec<LdapControl>>) -> anyhow::Result<()> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::UnbindRequest,
            ctrl: control.unwrap_or_default(),
        };

        self.frame
            .lock()
            .await
            .send(msg)
            .await
            .map_err(|e| anyhow::anyhow!("Unable to send unbind request -> {:?}", e))?;
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn sasl_bind(&mut self, config: SaslBindConfig) -> anyhow::Result<LdapBindResponse> {
        let SaslBindConfig {
            username,
            password,
            auth_method,
            controls,
            sign,
            seal,
        } = config;

        let mut auth_provider: Box<dyn SecurityProvider> = match auth_method {
            SspiAuthMethod::Ntlm {
                server_computer_name,
            } => Box::new(NtlmAuthProvier::new(
                &username,
                &password,
                &server_computer_name,
                sign,
                seal,
            )?),
            SspiAuthMethod::Kerberos {
                domain,
                kdc_url: kdc_proxy_url,
                server_computer_name,
                client_computer_name,
            } => {
                let kerberos_param = KerberoInitParams::builder()
                    .ldap_username(&username)
                    .ldap_password(&password)
                    .domain(domain.as_deref())
                    .kdc_proxy_url(kdc_proxy_url.as_deref())
                    .client_computer_name(&client_computer_name)
                    .server_computer_name(&server_computer_name)
                    .sign(sign)
                    .seal(seal)
                    .client(None)
                    .build();

                let kerberos = KerberoAuthProvier::try_from(kerberos_param)?;
                Box::new(kerberos)
            }
            SspiAuthMethod::Negotiate {
                domain,
                kdc_url,
                server_computer_name,
                client_computer_name,
            } => {
                let kerberos_param = KerberoInitParams::builder()
                    .ldap_username(&username)
                    .ldap_password(&password)
                    .domain(domain.as_deref())
                    .kdc_proxy_url(kdc_url.as_deref())
                    .client_computer_name(&client_computer_name)
                    .server_computer_name(&server_computer_name)
                    .sign(sign)
                    .seal(seal)
                    .client(None)
                    .build();

                let negotiate = NegotiateAuthProvier::try_from(kerberos_param)?;
                Box::new(negotiate)
            }
        };

        let token = auth_provider.step(&[]).await.unwrap();

        let msg = LdapMsg {
            msgid: 1,
            op: LdapOp::BindRequest(LdapBindRequest {
                dn: "".to_string(),
                cred: LdapBindCred::SASL(SaslCredentials {
                    mechanism: "GSS-SPNEGO".to_string(),
                    credentials: token,
                }),
            }),
            ctrl: controls.unwrap_or_default(),
        };

        let frame_arc = self.frame.clone();
        let mut frame = frame_arc.lock().await;

        frame
            .send(msg)
            .await
            .with_context(|| "Unable to send bind request")?;

        loop {
            let msg = frame
                .next()
                .await
                .with_context(|| "Unable to receive bind response")??;

            let bind_response = if let LdapOp::BindResponse(bind_response) = msg.op {
                bind_response
            } else {
                anyhow::bail!("Invalid response");
            };

            match bind_response.res.code {
                LdapResultCode::Success => {
                    tracing::trace!("bind success");
                    if sign.unwrap_or(false) && !seal.unwrap_or(false) {
                        anyhow::bail!("sign without seal is not currently supported");
                    }

                    if seal.unwrap_or(false) {
                        tracing::debug!("seal is required, setting encryption");
                        frame.get_mut().set_encryption(auth_provider);
                    }

                    break Ok(bind_response);
                }
                LdapResultCode::SaslBindInProgress => {
                    if let Some(ref cred) = bind_response.saslcreds {
                        let token = auth_provider.step(cred).await.map_err(|e| {
                            anyhow::anyhow!("Unable to step auth provider : {:?}", e)
                        })?;
                        let msg = LdapMsg {
                            msgid: self.next_message_id(),
                            op: LdapOp::BindRequest(LdapBindRequest {
                                dn: String::default(),
                                cred: LdapBindCred::SASL(SaslCredentials {
                                    mechanism: "GSS-SPNEGO".to_string(),
                                    credentials: token,
                                }),
                            }),
                            ctrl: vec![],
                        };

                        frame
                            .send(msg)
                            .await
                            .with_context(|| "Unable to send bind request")?;
                    }
                }
                _ => {
                    anyhow::bail!("Bind failed : {:?}", bind_response);
                }
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SspiAuthMethod {
    Ntlm {
        server_computer_name: String,
    },
    Kerberos {
        domain: Option<String>,
        kdc_url: Option<String>,
        server_computer_name: String,
        client_computer_name: String,
    },
    Negotiate {
        domain: Option<String>,
        kdc_url: Option<String>,
        server_computer_name: String,
        client_computer_name: String,
    },
}
