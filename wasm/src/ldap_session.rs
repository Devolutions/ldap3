#![allow(non_snake_case)]
// this is because Tsify and wasm-bindgen generates name in PascalCase, will look for solution later
use crate::{
    authentication::{
        kerberos::{KerberoAuthProvier, KerberoInitParams},
        negotiate::NegotiateAuthProvier,
        ntlm::NtlmAuthProvier,
        SecurityProvider, WasmNetworkClient,
    },
    dto::{
        control::LdapControlArray,
        operation::LdapBindResponse,
        result::LdapResult,
        search::{SearchMessages, SearchParameters},
    },
    encryption_stream::EncryptionStream,
    error::JsErrorValue,
};
use anyhow::Context as _;
use async_io_stream::IoStream;
use futures_util::sink::SinkExt;
use futures_util::StreamExt;

use std::sync::{atomic::AtomicI32, Arc};

use ldap3_proto::{
    parse_ldap_filter_str,
    proto::{
        LdapAddRequest, LdapBindCred, LdapBindRequest, LdapModify, LdapModifyRequest, LdapOp,
        SaslCredentials,
    },
    LdapCodec, LdapMsg, LdapResultCode, LdapSearchScope,
};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio_util::codec::Framed;

use tracing::trace;
use tsify::Tsify;
use wasm_bindgen::prelude::*;
use ws_stream_wasm::WsStreamIo;

use crate::JsResult;
use crate::{dto::modify::ModifyRequest, send_message};

pub(crate) type LdapFrame = Framed<EncryptionStream<IoStream<WsStreamIo, Vec<u8>>>, LdapCodec>;
#[wasm_bindgen]
pub struct LdapSession {
    frame: Arc<Mutex<LdapFrame>>,
    message_id: AtomicI32,
}

#[wasm_bindgen]
pub struct LdapSessionParameters {
    server_address_ws_proxy: String,
    max_bytes_for_decoder: Option<u32>,
}

#[wasm_bindgen]
impl LdapSessionParameters {
    #[wasm_bindgen(constructor)]
    /// max_bytes_for_decoder: the maximum number of bytes that the decoder can decode, if not specified, the default is 8KB
    pub fn new(server_address_ws_proxy: String, max_bytes_for_decoder: Option<u32>) -> Self {
        Self {
            server_address_ws_proxy,
            max_bytes_for_decoder,
        }
    }
}
impl LdapSession {
    fn next_message_id(&self) -> i32 {
        self.message_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.message_id.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/*
!Important: currently, in order to remain the sequence of messages to be received in the same order as they were sent,
            we lock the frame while sending a message and receiving the response. This is not ideal, but it works for now.
            in the future, we should have some mechanism to ensure that the messages are received in the same order as they were sent
            as well as to avoid locking the frame while waiting for a response.

Note: for those who wonder why I write code this way, Is because until today, 2023,Dec, it is still very hard to have a typed value and struct to pass
    from and into Typescript.
    1. I want to preserve the type information of the struct, so I can use it in Typescript, in a type safe manner
    2. I want to automatically serialize and deserialize the struct

*/
#[wasm_bindgen]
impl LdapSession {
    pub async fn connect(params: LdapSessionParameters) -> JsResult<LdapSession> {
        let (_ws_meta, ws_stream_wasm) =
            ws_stream_wasm::WsMeta::connect(&params.server_address_ws_proxy, None)
                .await
                .map_err(|e| JsErrorValue::new_with_context("failed to connect to server", e))?;
        let io_stream = ws_stream_wasm.into_io();
        let io_stream = EncryptionStream::new(io_stream);

        let framed = Framed::new(
            io_stream,
            params
                .max_bytes_for_decoder
                .map(|m| LdapCodec::new(Some(m as usize)))
                .unwrap_or_default(),
        );
        let session = LdapSession {
            #[allow(clippy::arc_with_non_send_sync)]
            frame: Arc::new(Mutex::new(framed)),
            message_id: AtomicI32::new(0),
        };
        Ok(session)
    }

    // Counterintuitively, the search method that returns result in bulk is faster and more performant than return result one by one through a callback
    // Invoking Javascript function from Rust is slow, and if there's always message in the queue, it will be a blocking call until the queue is empty
    pub async fn search(
        &self,
        SearchParameters {
            search_base,
            filter,
            scope,
            attributes,
            size_limit,
            time_limit,
            controls,
        }: SearchParameters,
    ) -> JsResult<SearchMessages> {
        let filter = parse_ldap_filter_str(&filter)
            .map_err(|e| JsErrorValue::new_with_context("invalid filter", e))?;

        trace!(?filter, ?attributes, ?controls);

        let request = ldap3_proto::proto::LdapSearchRequest {
            base: search_base,
            filter,
            scope: scope.into(),
            attrs: attributes,
            aliases: ldap3_proto::proto::LdapDerefAliases::Never,
            sizelimit: size_limit.unwrap_or(1000),
            timelimit: time_limit.unwrap_or(10),
            typesonly: false,
        };

        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::SearchRequest(request),
            ctrl: controls.unwrap_or_default().into(),
        };

        let mut frame = self.frame.lock().await;

        frame.send(msg).await?;

        let mut messages = Vec::new();

        loop {
            let msg = frame
                .next()
                .await
                .ok_or_else(|| JsErrorValue::msg("unable to get search response"))??;

            let should_stop = matches!(msg.op, LdapOp::SearchResultDone(_));

            let message = msg.try_into().map_err(JsErrorValue::from_anyhow)?;

            messages.push(message);

            if should_stop {
                break;
            };
        }

        Ok(SearchMessages { messages })
    }

    pub async fn add(
        &self,
        dn: String,
        attributes: crate::dto::search::AttributesArray,
        controls: Option<LdapControlArray>,
    ) -> JsResult<LdapResult> {
        let request = LdapAddRequest {
            dn,
            attributes: attributes.into(),
        };

        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::AddRequest(request),
            ctrl: controls.unwrap_or_default().into(),
        };

        let res = send_message!(self, msg);

        match res.op {
            LdapOp::AddResponse(res) => Ok(res.into()),
            _ => Err(JsErrorValue::msg("invalid response")),
        }
    }

    pub async fn delete(
        &self,
        dn: String,
        controls: Option<LdapControlArray>,
    ) -> JsResult<LdapResult> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::DelRequest(dn),
            ctrl: controls.unwrap_or_default().into(),
        };

        let res = send_message!(self, msg);

        match res.op {
            LdapOp::DelResponse(res) => Ok(res.into()),
            _ => Err(JsErrorValue::msg("invalid response")),
        }
    }

    pub async fn modify_dn(
        &self,
        dn: String,
        newrdn: String,
        delete_old_rdn: bool,
        new_superior: Option<String>,
        controls: Option<LdapControlArray>,
    ) -> JsResult<LdapResult> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::ModifyDNRequest(ldap3_proto::proto::LdapModifyDNRequest {
                dn,
                newrdn,
                deleteoldrdn: delete_old_rdn,
                new_superior,
            }),
            ctrl: controls.unwrap_or_default().into(),
        };

        let result = send_message!(self, msg);

        match result.op {
            LdapOp::ModifyDNResponse(res) => Ok(res.into()),
            _ => Err(JsErrorValue::msg("invalid response")),
        }
    }

    /// modify is of type LdapModify[]
    pub async fn modify(
        &self,
        dn: String,
        modifies: crate::dto::modify::BinaryLdapModifies,
        controls: Option<LdapControlArray>,
    ) -> JsResult<LdapResult> {
        let deserialized_modify: Vec<ModifyRequest> = modifies.into();

        let op = LdapOp::ModifyRequest(LdapModifyRequest {
            changes: deserialized_modify
                .into_iter()
                .map(|m| {
                    m.try_into()
                        .context("invalid modify")
                        .map_err(JsErrorValue::from_anyhow)
                })
                .collect::<Result<Vec<LdapModify>, _>>()?,
            dn,
        });

        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op,
            ctrl: controls.unwrap_or_default().into(),
        };

        let result = send_message!(self, msg);
        match result.op {
            LdapOp::ModifyResponse(res) => Ok(res.into()),
            _ => Err(JsErrorValue::msg("invalid response")),
        }
    }

    pub async fn compare(
        &self,
        dn: String,
        attribute: String,
        value: String,
        controls: Option<LdapControlArray>,
    ) -> JsResult<LdapResult> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::CompareRequest(ldap3_proto::proto::LdapCompareRequest {
                dn,
                atype: attribute,
                val: value.as_bytes().to_vec(),
            }),
            ctrl: controls.unwrap_or_default().into(),
        };

        let result = send_message!(self, msg);

        match result.op {
            LdapOp::CompareResult(res) => Ok(res.into()),
            _ => Err(JsErrorValue::msg("invalid response")),
        }
    }
}

#[derive(Debug, Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct SaslBindConfig {
    pub username: String,
    pub password: String,
    pub auth_method: SspiAuthMethod,
    pub controls: Option<LdapControlArray>,
    pub sign: Option<bool>,
    pub seal: Option<bool>,
}

#[wasm_bindgen]
impl LdapSession {
    pub async fn bind(
        &mut self,
        distinguished_name: String,
        password: String,
        controls: Option<LdapControlArray>,
    ) -> JsResult<LdapBindResponse> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::BindRequest(LdapBindRequest {
                dn: distinguished_name,
                cred: LdapBindCred::Simple(password),
            }),
            ctrl: controls.unwrap_or_default().into(),
        };

        let res = send_message!(self, msg);
        match &res.op {
            LdapOp::BindResponse(bind_response) => match &bind_response.res.code {
                ldap3_proto::proto::LdapResultCode::Success => Ok(bind_response.clone().into()),
                _ => Err(JsErrorValue::msg(format!("bind failed: {bind_response:?}"))),
            },
            _ => Err(JsErrorValue::msg("invalid response")),
        }
    }

    pub async fn unbind(&mut self, control: Option<LdapControlArray>) -> JsResult<()> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::UnbindRequest,
            ctrl: control.unwrap_or_default().into(),
        };

        self.frame
            .lock()
            .await
            .send(msg)
            .await
            .map_err(|e| JsErrorValue::new_with_context("unable to send unbind request", e))?;
        Ok(())
    }

    pub async fn sasl_bind(&mut self, config: SaslBindConfig) -> JsResult<LdapBindResponse> {
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
            } => {
                let res =
                    NtlmAuthProvier::new(&username, &password, &server_computer_name, sign, seal)
                        .map_err(JsErrorValue::from_anyhow)?;
                Box::new(res)
            }
            SspiAuthMethod::Kerberos {
                domain,
                kdc_proxy_url,
                server_computer_name,
            } => {
                let builder = KerberoInitParams::builder()
                    .ldap_username(&username)
                    .ldap_password(&password)
                    .domain(Some(&domain))
                    .kdc_proxy_url(Some(&kdc_proxy_url))
                    .client_computer_name("client_computer_name")
                    .server_computer_name(&server_computer_name)
                    .sign(sign)
                    .seal(seal)
                    .client(Some(Box::new(WasmNetworkClient)))
                    .build();
                let kerberos =
                    KerberoAuthProvier::try_from(builder).map_err(JsErrorValue::from_anyhow)?;
                Box::new(kerberos)
            }
            SspiAuthMethod::Negotiate {
                domain,
                kdc_proxy_url,
                server_computer_name,
            } => {
                let builder = KerberoInitParams::builder()
                    .ldap_username(&username)
                    .ldap_password(&password)
                    .domain(domain.as_deref())
                    .kdc_proxy_url(kdc_proxy_url.as_deref())
                    .client_computer_name("client_computer_name")
                    .server_computer_name(&server_computer_name)
                    .sign(sign)
                    .seal(seal)
                    .client(Some(Box::new(WasmNetworkClient)))
                    .build();
                let negotiate =
                    NegotiateAuthProvier::try_from(builder).map_err(JsErrorValue::from_anyhow)?;
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
            ctrl: controls.unwrap_or_default().into(),
        };

        let frame_arc = self.frame.clone();
        let mut frame = frame_arc.lock().await;

        frame
            .send(msg)
            .await
            .map_err(|e| JsErrorValue::new_with_context("unable to send bind request", e))?;

        loop {
            let msg = frame
                .next()
                .await
                .ok_or_else(|| JsErrorValue::msg("unable to get bind response"))?
                .map_err(|e| JsErrorValue::new_with_context("unable to get bind response", e))?;

            let bind_response = if let LdapOp::BindResponse(bind_response) = msg.op {
                bind_response
            } else {
                break Err(JsErrorValue::msg(
                    "invalid response type,expected BindResponse",
                ));
            };

            match bind_response.res.code {
                LdapResultCode::Success => {
                    tracing::trace!("bind success");

                    if !sign.unwrap_or(false) && seal.is_some_and(|s| s) {
                        // break error saying that sign without seal is not supported
                        break Err(JsErrorValue::msg(
                            "sign without seal is not supported, please set seal to true",
                        ));
                    }

                    if seal.unwrap_or(false) {
                        tracing::trace!("setting encryption");
                        frame.get_mut().set_encryption(auth_provider);
                    }

                    break Ok(bind_response.into());
                }
                LdapResultCode::SaslBindInProgress => {
                    if let Some(ref cred) = bind_response.saslcreds {
                        tracing::info!("sasl bind in progress");
                        let token = auth_provider.step(cred).await.map_err(|e| {
                            JsErrorValue::from_anyhow(
                                anyhow::Error::from_boxed(e)
                                    .context("error in accepting incoming sasl token"),
                            )
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
                            .context("unable to send bind request")
                            .map_err(JsErrorValue::from_anyhow)?;
                    }
                }
                _ => {
                    break Err(JsErrorValue::msg(format!("bind failed: {bind_response:?}")));
                }
            }
        }
    }
}

//================================================================================================

#[derive(Debug, Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum JsLdapSearchScope {
    Base = 0,
    OneLevel = 1,
    Subtree = 2,
    Children = 3,
}

impl From<JsLdapSearchScope> for LdapSearchScope {
    fn from(val: JsLdapSearchScope) -> Self {
        match val {
            JsLdapSearchScope::Base => LdapSearchScope::Base,
            JsLdapSearchScope::OneLevel => LdapSearchScope::OneLevel,
            JsLdapSearchScope::Subtree => LdapSearchScope::Subtree,
            JsLdapSearchScope::Children => LdapSearchScope::Children,
        }
    }
}

#[derive(Debug, Tsify, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[tsify(from_wasm_abi)]
pub enum SspiAuthMethod {
    Ntlm {
        server_computer_name: String,
    },
    Kerberos {
        domain: String,
        kdc_proxy_url: String,
        server_computer_name: String,
    },
    Negotiate {
        domain: Option<String>,
        kdc_proxy_url: Option<String>,
        server_computer_name: String,
    },
}
