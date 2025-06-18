use core::fmt;

use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct JsErrorValue {
    pub error: String,
}

impl From<JsErrorValue> for JsValue {
    fn from(val: JsErrorValue) -> Self {
        val.to_js_value()
    }
}

impl<E> From<E> for JsErrorValue
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn from(error: E) -> Self {
        JsErrorValue::new(error)
    }
}

impl JsErrorValue {
    pub fn new<E: std::error::Error + Send + Sync + 'static>(error: E) -> Self {
        Self {
            error: format!("{:#}", anyhow::Error::new(error)),
        }
    }

    pub fn new_with_context<E: std::error::Error + Send + Sync + 'static>(
        message: &str,
        error: E,
    ) -> Self {
        Self {
            error: format!("{message}: {:#}", anyhow::Error::new(error)),
        }
    }

    pub fn msg<M: fmt::Display>(message: M) -> Self {
        Self {
            error: message.to_string(),
        }
    }

    pub fn from_anyhow(error: anyhow::Error) -> Self {
        Self {
            error: format!("{error:#}"),
        }
    }

    pub fn to_js_value(&self) -> JsValue {
        serde_wasm_bindgen::to_value(self).expect("should never happen")
    }
}
