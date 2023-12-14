use std::sync::Arc;

use futures_util::sink::SinkExt;
use futures_util::StreamExt;
use js_sys::Function;
use ldap3_proto::{
    control::LdapControl,
    proto::{LdapOp, LdapSearchRequest},
    LdapFilter, LdapMsg,
};

use tokio::sync::Mutex;
use tracing::info;
use wasm_bindgen::prelude::*;

use crate::ldap_session::JsLdapSearchScope;
use crate::{
    call_js_function, call_js_function_serde,
    schema::search_objects::{SearchMessage, SearchOperation},
    to_js_error, JsResult,
};
use crate::{error::JsErrorValue, ldap_session::LdapFrame};

#[wasm_bindgen]
pub struct LdapSearchResultStream {
    frame: Arc<Mutex<LdapFrame>>,
    request_message: LdapMsg,
}

#[wasm_bindgen]
impl LdapSearchResultStream {
    /// if error, will call callback with {error: string}
    /// NOTE:: DO NOT USE LdapSearchResultStream after calling this function
    pub fn on_message(self, callback: &Function) -> JsResult<()> {
        if !callback.is_function() {
            return Err(to_js_error!("callback is not a function"));
        }

        let LdapSearchResultStream {
            frame,
            request_message,
        } = self;

        let callback_clone = callback.clone();

        let future = Box::pin(async move {
            let mut locked_frame = frame.lock().await;
            let res = locked_frame
                .send(request_message)
                .await
                .map_err(|e| to_js_error!("Unable to send search -> {:?}", e));

            if let Err(e) = res {
                call_js_function!(callback_clone, JsErrorValue::new(e).to_js_value());
                return;
            }

            let error = loop {
                let response = locked_frame.next().await;

                if response.is_none() {
                    break Err(JsErrorValue::new("no result present").to_js_value());
                }
                let response = response.unwrap();
                if response.is_err() {
                    break Err(JsErrorValue::new("error in response").to_js_value());
                }
                let response = response.unwrap();
                let LdapMsg { op, ctrl, msgid } = response;
                match op {
                    LdapOp::SearchResultEntry(entry) => {
                        let message = SearchMessage {
                            msgid,
                            op: SearchOperation::SearchEntry(entry.into()),
                            ctrl: Some(ctrl.into()),
                        };
                        call_js_function_serde!(callback_clone, message);
                    }
                    LdapOp::SearchResultReference(..) => continue,
                    LdapOp::SearchResultDone(msg) => {
                        let message = SearchMessage {
                            msgid,
                            op: SearchOperation::SearchDone(msg),
                            ctrl: Some(ctrl.into()),
                        };
                        info!("search is done, message = {:?}", message);
                        break Ok(call_js_function_serde!(callback_clone, message));
                    }
                    _ => {
                        break Err(to_js_error!(
                            "Invalid response type, either search is rejected or the lock on websocket has failed"
                        ));
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
    pub fn new(frame: Arc<Mutex<LdapFrame>>, msg: LdapMsg) -> Self {
        Self {
            frame,
            request_message: msg,
        }
    }
}

impl LdapSearchStreamBuilder {
    pub fn build(self) -> JsResult<LdapSearchResultStream> {
        let LdapSearchStreamBuilder {
            controls,
            frame,
            search_base,
            scope,
            size_limit,
            filter,
            time_limit,
            message_id,
            attributes,
        } = self;

        let request = LdapSearchRequest {
            base: search_base.ok_or(to_js_error!("Search base not set"))?,
            filter: filter.ok_or(to_js_error!("Filter not set"))?,
            scope: scope.ok_or(to_js_error!("Scope not set"))?.into(),
            attrs: attributes.unwrap_or_default(),
            aliases: ldap3_proto::proto::LdapDerefAliases::Never,
            sizelimit: size_limit.unwrap_or(1000),
            timelimit: time_limit.unwrap_or(10),
            typesonly: false,
        };

        let msg = LdapMsg {
            msgid: message_id.ok_or_else(|| to_js_error!("Message id not set"))?,
            op: LdapOp::SearchRequest(request),
            ctrl: controls.unwrap_or_default(),
        };

        Ok(LdapSearchResultStream::new(
            frame.ok_or(to_js_error!("missing stream"))?,
            msg,
        ))
    }
}

#[derive(Default)]
pub struct LdapSearchStreamBuilder {
    controls: Option<Vec<LdapControl>>,
    frame: Option<Arc<Mutex<LdapFrame>>>,
    search_base: Option<String>,
    filter: Option<LdapFilter>,
    scope: Option<JsLdapSearchScope>,
    size_limit: Option<i32>,
    time_limit: Option<i32>,
    message_id: Option<i32>,
    attributes: Option<Vec<String>>,
}

impl LdapSearchStreamBuilder {
    pub fn frame(mut self, frame: Arc<Mutex<LdapFrame>>) -> Self {
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

    pub fn attributes(mut self, attributes: Vec<String>) -> Self {
        self.attributes = Some(attributes);
        self
    }

    pub fn controls(mut self, controls: Vec<LdapControl>) -> Self {
        self.controls = Some(controls);
        self
    }
}
