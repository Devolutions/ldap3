use core::panic;

use std::cell::RefCell;
use std::fmt::Debug;

use std::rc::Rc;

use async_io_stream::IoStream;
use futures_util::sink::SinkExt;
use futures_util::StreamExt;

use ldap3_proto::{
    parse_ldap_filter_str,
    proto::{LdapAddRequest, LdapBindCred, LdapBindRequest, LdapModify, LdapModifyRequest, LdapOp},
    LdapCodec, LdapMsg, LdapSearchScope,
};

use serde::{Deserialize, Serialize};
use tokio_util::codec::Framed;

use tracing::debug;
use wasm_bindgen::prelude::*;
use ws_stream_wasm::WsStreamIo;

use crate::{error::JsErrorValue, receive_message, search::LdapSearchStreamBuilder, send_message};
use crate::{
    modify::DeserializableModify,
    schema::{DefaultAttributeSyntaxSchema, DisplayableAttribute},
};
use crate::{to_js_error, JsResult};

pub(crate) type LdapFrame = Framed<IoStream<WsStreamIo, Vec<u8>>, LdapCodec>;
#[wasm_bindgen]
pub struct LdapSession {
    frame: Rc<RefCell<LdapFrame>>,
    message_id: i32,
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

#[wasm_bindgen]
#[allow(clippy::await_holding_refcell_ref)]
impl LdapSession {
    pub async fn connect(params: LdapSessionParameters) -> JsResult<LdapSession> {
        let (_ws_meta, ws_stream_wasm) =
            ws_stream_wasm::WsMeta::connect(&params.server_address_ws_proxy, None)
                .await
                .unwrap();
        let io_stream = ws_stream_wasm.into_io();
        let framed = Framed::new(io_stream, LdapCodec::default());
        let session = LdapSession {
            frame: Rc::new(RefCell::new(framed)),
            message_id: 0,
            _parameters: params,
        };
        Ok(session)
    }

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
            ctrl: vec![],
        };

        send_message!(self, msg);

        if let Some(Ok(msg)) = self.frame.as_ref().borrow_mut().next().await {
            return Ok(serde_wasm_bindgen::to_value(&msg)?);
        }
        Err(to_js_error!("Failed to bind"))
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
            .schema(DefaultAttributeSyntaxSchema::default())
            .frame(self.frame.clone())
            .search_base(search_base)
            .filter(filter)
            .scope(scope)
            .size_limit(size_limit)
            .time_limit(time_limit)
            .message_id(self.next_message_id());

        Ok(builder)
    }

    pub async fn add(&mut self, dn: String, attributes: JsValue) -> JsResult<JsValue> {
        let displayable_attributes: Vec<DisplayableAttribute> =
            serde_wasm_bindgen::from_value(attributes)?;

        let request = LdapAddRequest {
            dn,
            attributes: displayable_attributes
                .into_iter()
                .map(|a| a.into())
                .collect(),
        };

        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::AddRequest(request),
            ctrl: vec![],
        };

        send_message!(self, msg);
        let result = receive_message!(self);

        Ok(serde_wasm_bindgen::to_value(&result)?)
    }

    pub async fn delete(&mut self, dn: String) -> JsResult<JsValue> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::DelRequest(dn),
            ctrl: vec![],
        };

        send_message!(self, msg);

        let result = if let Some(msg) = self.frame.as_ref().borrow_mut().next().await {
            match msg {
                Ok(res) => {
                    debug!(" DELETE RESULT =  {:?}", &res);
                    match res.op {
                        LdapOp::DelResponse(..) => res,
                        _ => panic!("Error: {:?}", res),
                    }
                }
                Err(e) => panic!("Error: {:?}", e),
            }
        } else {
            panic!("No result")
        };

        Ok(serde_wasm_bindgen::to_value(&result)?)
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
            ctrl: vec![],
        };

        self.frame
            .as_ref()
            .borrow_mut()
            .send(msg)
            .await
            .map_err(|e| to_js_error!("failed to modify {:?}", e))?;

        let result = self
            .frame
            .as_ref()
            .borrow_mut()
            .next()
            .await
            .ok_or(to_js_error!("No result"))?
            .map_err(|e| to_js_error!("{:?}", e))?;

        Ok(serde_wasm_bindgen::to_value(&result)?)
    }

    pub async fn modify(&mut self, dn: String, modifies: JsValue) -> JsResult<JsValue> {
        let deserialized_modify: Vec<DeserializableModify> =
            serde_wasm_bindgen::from_value(modifies)?;

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
            ctrl: vec![],
        };

        send_message!(self, msg);
        let res = receive_message!(self);

        Ok(serde_wasm_bindgen::to_value(&res)?)
    }
}

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

/*
{
    "attribute_name": "cn",
    "attribute_value": {
        "type": 0,
        "value": [
            "string",
            "string2"
        ]
    }
}
*/

#[derive(Clone, Copy, Serialize, Deserialize)]
#[wasm_bindgen]
#[repr(u8)]
pub enum DisplayableAttributesValueType {
    String = 0,
    Integer = 1,
    Boolean = 2,
    Date = 3,
    Bytes = 4,
    Enum = 5,
}

impl Debug for DisplayableAttributesValueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String => write!(f, "String"),
            Self::Integer => write!(f, "Integer"),
            Self::Boolean => write!(f, "Boolean"),
            Self::Date => write!(f, "Date"),
            Self::Bytes => write!(f, "Bytes"),
            Self::Enum => write!(f, "Enum"),
        }
    }
}

impl TryFrom<i32> for DisplayableAttributesValueType {
    type Error = anyhow::Error;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DisplayableAttributesValueType::String),
            1 => Ok(DisplayableAttributesValueType::Integer),
            2 => Ok(DisplayableAttributesValueType::Boolean),
            3 => Ok(DisplayableAttributesValueType::Date),
            4 => Ok(DisplayableAttributesValueType::Bytes),
            5 => Ok(DisplayableAttributesValueType::Enum),
            _ => Err(anyhow::anyhow!("Invalid value")),
        }
    }
}

impl DisplayableAttributesValueType {
    pub fn into_i32(self) -> i32 {
        match self {
            // match to it's number
            DisplayableAttributesValueType::String => 0,
            DisplayableAttributesValueType::Integer => 1,
            DisplayableAttributesValueType::Boolean => 2,
            DisplayableAttributesValueType::Date => 3,
            DisplayableAttributesValueType::Bytes => 4,
            DisplayableAttributesValueType::Enum => 5,
        }
    }
}
