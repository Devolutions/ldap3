use error::JsErrorValue;
use tracing::Level;
use wasm_bindgen::prelude::wasm_bindgen;

pub mod authentication;
pub mod dto;
pub mod encryption_codec;
pub mod error;
pub mod ldap_session;
pub mod schema;
pub mod search;
#[cfg(test)]
mod test;
pub mod types;
pub mod utils;

pub type JsResult<T> = Result<T, JsErrorValue>;

#[macro_export]
macro_rules! call_js_function {
    ($callback:ident, $value:expr) => {
        $callback
            .call1(&JsValue::NULL, &$value)
            .expect("Callback invocation failed")
    };
}

#[macro_export]
macro_rules! call_js_function_serde {
    ($callback:ident, $value:expr) => {
        match serde_wasm_bindgen::to_value(&$value) {
            Ok(js_value) => call_js_function!($callback, js_value),
            Err(error) => call_js_function!($callback, JsErrorValue::new(error).to_js_value()),
        }
    };
}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn set_logging_level(level: LoggingLevel) {
    let mut builder = tracing_wasm::WASMLayerConfigBuilder::new();
    builder.set_max_level(level.into());
    tracing_wasm::set_as_global_default_with_config(builder.build());
}

#[wasm_bindgen]
pub enum LoggingLevel {
    Panic,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LoggingLevel> for Level {
    fn from(val: LoggingLevel) -> Self {
        match val {
            LoggingLevel::Panic => Level::ERROR,
            LoggingLevel::Warn => Level::WARN,
            LoggingLevel::Info => Level::INFO,
            LoggingLevel::Debug => Level::DEBUG,
            LoggingLevel::Trace => Level::TRACE,
        }
    }
}

pub struct JsFunction {
    pub callback: js_sys::Function,
}
