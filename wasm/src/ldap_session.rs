#![allow(non_snake_case)]
// this is because Tsify and wasm-bindgen generates name in PascalCase, will look for solution later
use crate::{
    authentication::{
        kerberos::KerberoAuthProvier, negotiate::NegotiateAuthProvier, ntlm::NtlmAuthProvier,
        SecurityProvider,
    },
    error::JsErrorValue,
};
use async_io_stream::IoStream;
use futures_util::sink::SinkExt;
use futures_util::StreamExt;
use std::sync::Arc;

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

use crate::{
    control::LdapControlArray,
    modify::ModifyRequest,
    return_msg_if_type_matches,
    schema::search_objects::AttributesArray,
    search::{LdapSearchResultStream, LdapSearchStreamBuilder},
    send_message,
};
use crate::{to_js_error, JsResult};

pub(crate) type LdapFrame = Framed<IoStream<WsStreamIo, Vec<u8>>, LdapCodec>;
#[wasm_bindgen]
pub struct LdapSession {
    frame: Arc<Mutex<LdapFrame>>,
    message_id: i32,
}

#[wasm_bindgen]
pub struct LdapSessionParameters {
    server_address_ws_proxy: String,
}

#[wasm_bindgen]
impl LdapSessionParameters {
    #[wasm_bindgen(constructor)]
    pub fn new(server_address_ws_proxy: String) -> Self {
        Self {
            server_address_ws_proxy
        }
    }
}
impl LdapSession {
    fn next_message_id(&mut self) -> i32 {
        self.message_id += 1;
        self.message_id
    }
}

/*
!Important: currently, in order to remain the sequence of messages to be recevied in the same order as they were sent,
            we lock the frame while sending a message and receiving the response. This is not ideal, but it works for now.
            in the future, we should have some machanism to ensure that the messages are received in the same order as they were sent
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
                .map_err(|e| to_js_error!("Failed to connect to server : {:?}", e))?;
        let io_stream = ws_stream_wasm.into_io();

        let framed = Framed::new(io_stream, LdapCodec::default());
        let session = LdapSession {
            frame: Arc::new(Mutex::new(framed)),
            message_id: 0,
        };
        Ok(session)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn search(
        &mut self,
        search_base: String,
        filter: String,
        scope: JsLdapSearchScope,
        attributes: Vec<String>,
        size_limit: Option<i32>,
        time_limit: Option<i32>,
        controls: Option<LdapControlArray>,
    ) -> JsResult<LdapSearchResultStream> {
        let filter =
            parse_ldap_filter_str(&filter).map_err(|e| to_js_error!("Invalid filter : {:?}", e))?;
        trace!(?filter, ?attributes, ?controls);
        let builder = LdapSearchStreamBuilder::default()
            .frame(self.frame.clone())
            .search_base(search_base)
            .filter(filter)
            .scope(scope)
            .size_limit(size_limit)
            .time_limit(time_limit)
            .message_id(self.next_message_id())
            .attributes(attributes)
            .controls(controls.unwrap_or_default().into());

        builder.build()
    }

    pub async fn add(
        &mut self,
        dn: String,
        attributes: AttributesArray,
        controls: Option<LdapControlArray>,
    ) -> JsResult<JsValue> {
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

        return_msg_if_type_matches!(LdapOp::AddResponse, res)
    }

    pub async fn delete(
        &mut self,
        dn: String,
        controls: Option<LdapControlArray>,
    ) -> JsResult<JsValue> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::DelRequest(dn),
            ctrl: controls.unwrap_or_default().into(),
        };

        let res = send_message!(self, msg);

        return_msg_if_type_matches!(LdapOp::DelResponse, res)
    }

    pub async fn modify_dn(
        &mut self,
        dn: String,
        newrdn: String,
        delete_old_rdn: bool,
        new_superior: Option<String>,
        controls: Option<LdapControlArray>,
    ) -> JsResult<JsValue> {
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

        return_msg_if_type_matches!(LdapOp::ModifyDNResponse, result)
    }

    /// modify is of type LdapModify[]
    pub async fn modify(
        &mut self,
        dn: String,
        modifies: crate::modify::BinaryLdapModifies,
        controls: Option<LdapControlArray>,
    ) -> JsResult<JsValue> {
        let deserialized_modify: Vec<ModifyRequest> = modifies.into();

        let op = LdapOp::ModifyRequest(LdapModifyRequest {
            changes: deserialized_modify
                .into_iter()
                .map(|m| {
                    m.try_into()
                        .map_err(|e| to_js_error!("Invalid modify : {:?}", e))
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
        return_msg_if_type_matches!(LdapOp::ModifyResponse, result)
    }

    pub async fn compare(
        &mut self,
        dn: String,
        attribute: String,
        value: String,
        controls: Option<LdapControlArray>,
    ) -> JsResult<JsValue> {
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
        return_msg_if_type_matches!(LdapOp::CompareResult, result)
    }
}

#[derive(Debug, Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct SaslBindConfig {
    pub username: String,
    pub password: String,
    pub auth_method: SspiAuthMethod,
    pub controls: Option<LdapControlArray>,
}

#[wasm_bindgen]
impl LdapSession {
    pub async fn bind(
        &mut self,
        distinguished_name: String,
        password: String,
        controls: Option<LdapControlArray>,
    ) -> JsResult<JsValue> {
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
                ldap3_proto::proto::LdapResultCode::Success => {
                    Ok(serde_wasm_bindgen::to_value(&res)?)
                }
                _ => Err(serde_wasm_bindgen::to_value(&res)?),
            },
            _ => Err(to_js_error!("Invalid response")),
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
            .map_err(|e| to_js_error!("Unable to send unbind request -> {:?}", e))?;
        Ok(())
    }

    pub async fn sasl_bind(&mut self, config: SaslBindConfig) -> JsResult<JsValue> {
        let SaslBindConfig {
            username,
            password,
            auth_method,
            controls,
        } = config;

        let mut auth_provider: Box<dyn SecurityProvider> = match auth_method {
            SspiAuthMethod::Ntlm {
                server_computer_name,
            } => Box::new(NtlmAuthProvier::new(
                &username,
                &password,
                &server_computer_name,
            )),
            SspiAuthMethod::Kerberos {
                domain,
                kdc_proxy_url,
                server_computer_name,
            } => Box::new(KerberoAuthProvier::new(
                &username,
                &password,
                &domain,
                &kdc_proxy_url,
                &server_computer_name,
                &server_computer_name,
            )),
            SspiAuthMethod::Negotiate {
                domain,
                kdc_proxy_url,
                server_computer_name,
            } => Box::new(NegotiateAuthProvier::new(
                &username,
                &password,
                &domain,
                &kdc_proxy_url,
                &server_computer_name,
                &server_computer_name,
            )),
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
            .map_err(|e| to_js_error!("unable to send bind request: {:?}", e))?;

        loop {
            let msg = frame
                .next()
                .await
                .ok_or(to_js_error!("Unable to get bind response"))?
                .map_err(|e| to_js_error!("Unable to get bind response: {:?}", e))?;

            let bind_response = if let LdapOp::BindResponse(bind_response) = msg.op {
                bind_response
            }else{
                break Err(to_js_error!("Invalid response type,expected BindResponse"));
            };

            match bind_response.res.code {
                LdapResultCode::Success => {
                    println!("Bind successful");
                    break Ok(serde_wasm_bindgen::to_value(&bind_response)?);
                }
                LdapResultCode::SaslBindInProgress => {
                    if let Some(ref cred) = bind_response.saslcreds {
                        let ntlm_token = auth_provider.step(cred).await.map_err(|e| to_js_error!("Unable to get ntlm token: {:?}", e))?;
                        let msg = LdapMsg {
                            msgid: self.next_message_id(),
                            op: LdapOp::BindRequest(LdapBindRequest {
                                dn: String::default(),
                                cred: LdapBindCred::SASL(SaslCredentials {
                                    mechanism: "GSS-SPNEGO".to_string(),
                                    credentials: ntlm_token,
                                }),
                            }),
                            ctrl: vec![],
                        };

                        frame.send(msg).await.map_err(|e| to_js_error!("Unable to send bind request -> {:?}",e))?;
                    }
                }
                _ => {
                    break Err(to_js_error!("Bind failed: {:?}", bind_response));
                }
            }
        }
    }
}

//================================================================================================

#[wasm_bindgen]
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
        domain: String,
        kdc_proxy_url: String,
        server_computer_name: String,
    },
}
