use core::panic;
use std::sync::Arc;

use async_io_stream::IoStream;
use futures_util::sink::SinkExt;
use futures_util::StreamExt;

use ldap3_proto::{
    parse_ldap_filter_str,
    proto::{LdapAddRequest, LdapBindCred, LdapBindRequest, LdapModify, LdapModifyRequest, LdapOp},
    LdapCodec, LdapMsg, LdapSearchScope,
};

use tokio::sync::Mutex;
use tokio_util::codec::Framed;

use wasm_bindgen::prelude::*;
use ws_stream_wasm::WsStreamIo;

use crate::modify::DisplayableModify;
use crate::{
    error::JsErrorValue, modify::LdapModifies, replace_with_new_vec, return_msg_if_type_matches,
    schema::displayables::DisplayableAttributes, search::LdapSearchStreamBuilder, send_message,
};
use crate::{to_js_error, JsResult};

pub(crate) type LdapFrame = Framed<IoStream<WsStreamIo, Vec<u8>>, LdapCodec>;
#[wasm_bindgen]
pub struct LdapSession {
    frame: Arc<Mutex<LdapFrame>>,
    message_id: i32,
    control: Vec<ldap3_proto::proto::LdapControl>,
    _parameters: LdapSessionParameters,
}

#[wasm_bindgen]
pub struct LdapSessionParameters {
    server_address_ws_proxy: String,
    _kdc_address: Option<String>,             // to be used in the future
    _kdc_address_ws_endpoint: Option<String>, // to be used in the future
}

#[wasm_bindgen]
impl LdapSessionParameters {
    #[wasm_bindgen(constructor)]
    pub fn new(server_address_ws_proxy: String) -> Self {
        Self {
            server_address_ws_proxy,
            _kdc_address: None,
            _kdc_address_ws_endpoint: None,
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
            control: vec![],
            _parameters: params,
        };
        Ok(session)
    }

    pub fn add_control_for_next_request(&mut self, control: JsValue) -> JsResult<()> {
        let control: Vec<ldap3_proto::proto::LdapControl> =
            serde_wasm_bindgen::from_value(control)?;
        self.control.extend(control);
        Ok(())
    }

    pub fn search(
        &mut self,
        search_base: String,
        filter: String,
        scope: JsLdapSearchScope,
        size_limit: Option<i32>,
        time_limit: Option<i32>,
    ) -> JsResult<LdapSearchStreamBuilder> {
        let filter =
            parse_ldap_filter_str(&filter).map_err(|e| to_js_error!("Invalid filter : {:?}", e))?;

        let builder = LdapSearchStreamBuilder::default()
            .frame(self.frame.clone())
            .search_base(search_base)
            .filter(filter)
            .scope(scope)
            .size_limit(size_limit)
            .time_limit(time_limit)
            .message_id(self.next_message_id());

        Ok(builder)
    }

    pub async fn add(
        &mut self,
        dn: String,
        attributes: DisplayableAttributes,
    ) -> JsResult<JsValue> {
        let request = LdapAddRequest {
            dn,
            attributes: attributes.into(),
        };

        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::AddRequest(request),
            ctrl: replace_with_new_vec!(&mut self.control),
        };

        let res = send_message!(self, msg);

        return_msg_if_type_matches!(LdapOp::AddResponse, res)
    }

    pub async fn delete(&mut self, dn: String) -> JsResult<JsValue> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::DelRequest(dn),
            ctrl: replace_with_new_vec!(&mut self.control),
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
    ) -> JsResult<JsValue> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::ModifyDNRequest(ldap3_proto::proto::LdapModifyDNRequest {
                dn,
                newrdn,
                deleteoldrdn: delete_old_rdn,
                new_superior,
            }),
            ctrl: replace_with_new_vec!(&mut self.control),
        };

        let result = send_message!(self, msg);

        return_msg_if_type_matches!(LdapOp::ModifyDNResponse, result)
    }

    /// modify is of type LdapModify[]
    pub async fn modify(&mut self, dn: String, modifies: LdapModifies) -> JsResult<JsValue> {
        // let deserialized_modify: Vec<DisplayableModify> = serde_wasm_bindgen::from_value(modifies)?;
        let deserialized_modify: Vec<DisplayableModify> = modifies.into();

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
            ctrl: replace_with_new_vec!(&mut self.control),
        };

        let result = send_message!(self, msg);
        return_msg_if_type_matches!(LdapOp::ModifyResponse, result)
    }

    pub async fn compare(
        &mut self,
        dn: String,
        attribute: String,
        value: String,
    ) -> JsResult<JsValue> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::CompareRequest(ldap3_proto::proto::LdapCompareRequest {
                dn,
                atype: attribute,
                val: value.as_bytes().to_vec(),
            }),
            ctrl: replace_with_new_vec!(&mut self.control),
        };

        let result = send_message!(self, msg);
        return_msg_if_type_matches!(LdapOp::CompareResult, result)
    }
}

#[wasm_bindgen]
impl LdapSession {
    pub async fn bind(
        &mut self,
        distinguished_name: String,
        password: String,
    ) -> JsResult<JsValue> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::BindRequest(LdapBindRequest {
                dn: distinguished_name,
                cred: LdapBindCred::Simple(password),
            }),
            ctrl: replace_with_new_vec!(&mut self.control),
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

    pub async fn unbind(&mut self) -> JsResult<()> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::UnbindRequest,
            ctrl: replace_with_new_vec!(&mut self.control),
        };

        let res = send_message!(self, msg);
        Ok(())
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
