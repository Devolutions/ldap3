use core::fmt;

use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct JsErrorValue {
    pub error: String,
}

#[macro_export]
macro_rules! to_js_error {
    ($($arg:tt)*) => {
        JsErrorValue::new(format!($($arg)*).as_str())
    };
}

impl From<JsErrorValue> for JsValue {
    fn from(val: JsErrorValue) -> Self {
        val.to_js_value()
    }
}

impl<T> From<T> for JsErrorValue
where
    T: std::fmt::Display,
{
    fn from(error: T) -> Self {
        JsErrorValue::new(error.to_string())
    }
}

// impl From<JsValue> for JsErrorValue {
//     fn from(error: JsValue) -> Self {
//         JsErrorValue::new(error)
//     }
// }

impl JsErrorValue {
    pub fn new<T: fmt::Debug>(error: T) -> Self {
        Self {
            error: format!("{:?}", error),
        }
    }

    pub fn new_with_message<T: fmt::Debug>(message: &str, error: T) -> Self {
        Self {
            error: format!("{}: {:?}", message, error),
        }
    }

    pub fn to_js_value(&self) -> JsValue {
        let res = serde_wasm_bindgen::to_value(self);
        match res {
            Ok(js_value) => js_value,
            Err(_error) => JsValue::from_str("error serializing errors, this should never happen"),
        }
    }
}
