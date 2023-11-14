use core::panic;
use std::cell::RefCell;
use std::collections::HashMap;

use std::rc::Rc;

use async_io_stream::IoStream;
use futures_util::sink::SinkExt;
use futures_util::StreamExt;
use js_sys::Function;
use ldap3_proto::{
    parse_ldap_filter_str,
    proto::{LdapAddRequest, LdapBindCred, LdapBindRequest, LdapOp, LdapSearchRequest},
    LdapCodec, LdapFilter, LdapMsg, LdapSearchScope,
};

use tokio_util::codec::Framed;
use tracing::debug;
use wasm_bindgen::prelude::*;
use ws_stream_wasm::WsStreamIo;

use crate::error::JsErrorValue;
use crate::schema::{AttributeSyntaxSchema, DefaultAttributeSyntaxSchema, DisplayableEntry};
use crate::{call_js_function, to_js_error, JsResult};

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
pub struct LdapSearchResultStream {
    schema: Rc<RefCell<DefaultAttributeSyntaxSchema>>,
    frame: Rc<RefCell<LdapFrame>>,
    request_message: LdapMsg,
}

#[wasm_bindgen]
#[allow(clippy::await_holding_refcell_ref)] // browser is single threaded
impl LdapSearchResultStream {
    /// if error, will call callback with {error: string}
    pub fn on_message(&mut self, callback: &Function) -> JsResult<()> {
        if !callback.is_function() {
            return Err(to_js_error!("callback is not a function"));
        }
        let frame_clone = self.frame.clone();
        let schema = self.schema.clone();
        let callback_clone = callback.clone();
        let msg = self.request_message.clone();

        let future = Box::pin(async move {
            let res = frame_clone
                .as_ref()
                .borrow_mut()
                .send(msg)
                .await
                .map_err(|e| to_js_error!("Unable to send search -> {:?}", e));

            if let Err(e) = res {
                let error = JsErrorValue::new(e).to_js_value();
                call_js_function!(callback_clone, error);
                return;
            }

            let error = loop {
                let response = frame_clone.as_ref().borrow_mut().next().await;

                if response.is_none() {
                    break Err(JsErrorValue::new("no result present").to_js_value());
                }
                let response = response.unwrap();
                if response.is_err() {
                    break Err(JsErrorValue::new("error in response").to_js_value());
                }
                let response = response.unwrap();

                match &response.op {
                    LdapOp::SearchResultEntry(entry) => {
                        let schema_ref = schema.as_ref().borrow();
                        let parsed_attrubutes = entry
                            .attributes
                            .iter()
                            .map(|attr| {
                                schema_ref
                                    .to_displayable_attribute(attr)
                                    .map_err(|e| to_js_error!("{:?}", e))
                            })
                            .collect::<Result<Vec<_>, _>>();

                        if let Err(e) = parsed_attrubutes {
                            break Err(e);
                        }

                        let parsed_attrubutes = parsed_attrubutes.unwrap();
                        let displayable_entry = DisplayableEntry {
                            dn: entry.dn.clone(),
                            attributes: parsed_attrubutes,
                        };
                        match serde_wasm_bindgen::to_value(&displayable_entry) {
                            Ok(js_mes) => {
                                call_js_function!(callback_clone, js_mes)
                            }
                            Err(e) => break Err(to_js_error!("failed to serialize {:?}", e)),
                        }
                    }
                    LdapOp::SearchResultReference(..) => continue,
                    LdapOp::SearchResultDone(..) => break Ok(()),
                    _ => {
                        break Err(
                            JsErrorValue::new_with_message("unexpected response", response)
                                .to_js_value(),
                        );
                    }
                };
            };
            if let Err(e) = error {
                call_js_function!(callback_clone, e);
            }
        });
        wasm_bindgen_futures::spawn_local(future);
        Ok(())
    }
}

impl LdapSearchResultStream {
    pub fn new(
        schema: Rc<RefCell<DefaultAttributeSyntaxSchema>>,
        frame: Rc<RefCell<LdapFrame>>,
        msg: LdapMsg,
    ) -> Self {
        Self {
            schema,
            frame,
            request_message: msg,
        }
    }
}

#[wasm_bindgen]
impl LdapSearchStreamBuilder {
    /// schema is of type  { [key: string]: DisplayableAttributesValueTypes }
    pub fn with_attribute_schema(self, js_shcema: JsValue) -> JsResult<LdapSearchResultStream> {
        let LdapSearchStreamBuilder {
            schema,
            frame,
            search_base,
            scope,
            size_limit,
            filter,
            time_limit,
            message_id,
        } = self;

        let new_map: HashMap<String, i32> = serde_wasm_bindgen::from_value(js_shcema)?;
        let keys_used = schema
            .as_deref()
            .ok_or(to_js_error!("Rust Schema Struct not set"))?
            .borrow_mut()
            .add_attribute_display_type(new_map)
            .map_err(|e| to_js_error!("{:?}", e))?;

        let request = LdapSearchRequest {
            base: search_base.ok_or(to_js_error!("Search base not set"))?,
            filter: filter.ok_or(to_js_error!("Filter not set"))?,
            scope: scope.ok_or(to_js_error!("Scope not set"))?.into(),
            attrs: keys_used,
            aliases: ldap3_proto::proto::LdapDerefAliases::Never,
            sizelimit: size_limit.unwrap_or(1000),
            timelimit: time_limit.unwrap_or(10),
            typesonly: false,
        };

        let msg = LdapMsg {
            msgid: message_id.ok_or_else(|| to_js_error!("Message id not set"))?,
            op: LdapOp::SearchRequest(request),
            ctrl: vec![],
        };

        Ok(LdapSearchResultStream::new(
            schema.unwrap(),
            frame.ok_or(to_js_error!("missing stream"))?,
            msg,
        ))
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

        self.frame
            .as_ref()
            .borrow_mut()
            .send(msg)
            .await
            .map_err(|e| to_js_error!("failed to bind {:?}", e))?;

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
            .schema(Rc::new(RefCell::new(DefaultAttributeSyntaxSchema::new())))
            .frame(self.frame.clone())
            .search_base(search_base)
            .filter(filter)
            .scope(scope)
            .size_limit(size_limit)
            .time_limit(time_limit)
            .message_id(self.next_message_id());

        Ok(builder)
    }

    /// TODO:Attributes cannot be added at this moment, work in progress
    pub async fn add(&mut self, dn: String, attributes: JsValue) -> JsResult<JsValue> {
        let _map: HashMap<String, Vec<u8>> = serde_wasm_bindgen::from_value(attributes)?;
        let request = LdapAddRequest {
            dn,
            attributes: vec![],
        };

        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::AddRequest(request),
            ctrl: vec![],
        };

        self.frame
            .as_ref()
            .borrow_mut()
            .send(msg)
            .await
            .map_err(|e| to_js_error!("failed to add {:?}", e))?;

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

    pub async fn delete(&mut self, dn: String) -> JsResult<JsValue> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::DelRequest(dn),
            ctrl: vec![],
        };

        self.frame
            .as_ref()
            .borrow_mut()
            .send(msg)
            .await
            .map_err(|e| to_js_error!("failed to delete {:?}", e))?;

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

#[wasm_bindgen]
#[derive(Default)]
pub struct LdapSearchStreamBuilder {
    schema: Option<Rc<RefCell<DefaultAttributeSyntaxSchema>>>,
    frame: Option<Rc<RefCell<LdapFrame>>>,
    search_base: Option<String>,
    filter: Option<LdapFilter>,
    scope: Option<JsLdapSearchScope>,
    size_limit: Option<i32>,
    time_limit: Option<i32>,
    message_id: Option<i32>,
}

impl LdapSearchStreamBuilder {
    pub fn schema(mut self, schema: Rc<RefCell<DefaultAttributeSyntaxSchema>>) -> Self {
        self.schema = Some(schema);
        self
    }

    pub fn frame(mut self, frame: Rc<RefCell<LdapFrame>>) -> Self {
        self.frame = Some(frame);
        self
    }

    pub fn search_base(mut self, base: String) -> Self {
        self.search_base = Some(base);
        self
    }

    pub fn filter(mut self, filter: LdapFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    pub fn scope(mut self, scope: JsLdapSearchScope) -> Self {
        self.scope = Some(scope);
        self
    }

    pub fn size_limit(mut self, limit: Option<i32>) -> Self {
        self.size_limit = limit;
        self
    }

    pub fn time_limit(mut self, limit: Option<i32>) -> Self {
        self.time_limit = limit;
        self
    }

    pub fn message_id(mut self, id: i32) -> Self {
        self.message_id = Some(id);
        self
    }
}
