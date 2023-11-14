use core::fmt;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[macro_export]
macro_rules! to_js_error {
    ($($arg:tt)*) => {
        JsErrorValue::new(format!($($arg)*).as_str()).to_js_value()
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct JsErrorValue {
    error: String,
}

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
            Err(error) => to_js_error!(
                "failed to serialize {:?}, the original error message is {:?}",
                error,
                self.error
            ),
        }
    }
}
