use std::cell::RefCell;
use std::collections::HashMap;

use std::rc::Rc;

use futures_util::sink::SinkExt;
use futures_util::StreamExt;
use js_sys::Function;
use ldap3_proto::{
    proto::{LdapOp, LdapSearchRequest},
    LdapFilter, LdapMsg,
};

use wasm_bindgen::prelude::*;

use crate::{
    call_js_function, call_js_function_serde, schema::schema::to_displayable_entry, to_js_error,
    JsResult,
};
use crate::{error::JsErrorValue, ldap_session::LdapFrame};
use crate::{ldap_session::JsLdapSearchScope, schema::schema::DefaultAttributeSyntaxSchema};

#[wasm_bindgen]
pub struct LdapSearchResultStream {
    schema: DefaultAttributeSyntaxSchema,
    frame: Rc<RefCell<LdapFrame>>,
    request_message: LdapMsg,
}

#[wasm_bindgen]
#[allow(clippy::await_holding_refcell_ref)] // browser is single threaded
impl LdapSearchResultStream {
    /// if error, will call callback with {error: string}
    /// NOTE:: DO NOT USE LdapSearchResultStream after calling this function
    pub fn on_message(self, callback: &Function) -> JsResult<()> {
        if !callback.is_function() {
            return Err(to_js_error!("callback is not a function"));
        }

        let LdapSearchResultStream {
            schema,
            frame,
            request_message,
        } = self;

        let callback_clone = callback.clone();

        let future = Box::pin(async move {
            let res = frame
                .as_ref()
                .borrow_mut()
                .send(request_message)
                .await
                .map_err(|e| to_js_error!("Unable to send search -> {:?}", e));

            if let Err(e) = res {
                call_js_function!(callback_clone, JsErrorValue::new(e).to_js_value());
                return;
            }

            let error = loop {
                let response = frame.as_ref().borrow_mut().next().await;

                if response.is_none() {
                    break Err(JsErrorValue::new("no result present").to_js_value());
                }
                let response = response.unwrap();
                if response.is_err() {
                    break Err(JsErrorValue::new("error in response").to_js_value());
                }
                let response = response.unwrap();

                match response.op {
                    LdapOp::SearchResultEntry(entry) => {
                        let displayable_entry = to_displayable_entry(&schema, entry);
                        match displayable_entry {
                            Ok(js_message) => {
                                call_js_function_serde!(callback_clone, js_message)
                            }
                            Err(e) => {
                                call_js_function!(
                                    callback_clone,
                                    to_js_error!("failed to convert entry {:?}", e)
                                )
                            }
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
        schema: DefaultAttributeSyntaxSchema,
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
        let mut schema = schema.ok_or(to_js_error!("Rust Schema Struct not set"))?;
        let keys_used = schema
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
            schema,
            frame.ok_or(to_js_error!("missing stream"))?,
            msg,
        ))
    }
}

#[wasm_bindgen]
#[derive(Default)]
pub struct LdapSearchStreamBuilder {
    schema: Option<DefaultAttributeSyntaxSchema>,
    frame: Option<Rc<RefCell<LdapFrame>>>,
    search_base: Option<String>,
    filter: Option<LdapFilter>,
    scope: Option<JsLdapSearchScope>,
    size_limit: Option<i32>,
    time_limit: Option<i32>,
    message_id: Option<i32>,
}

impl LdapSearchStreamBuilder {
    pub fn schema(mut self, schema: DefaultAttributeSyntaxSchema) -> Self {
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
