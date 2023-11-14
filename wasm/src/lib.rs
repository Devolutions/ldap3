use tracing::Level;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

pub mod error;
pub mod ldap_session;
pub mod schema;
#[cfg(test)]
mod test;

pub type JsResult<T> = Result<T, JsValue>;

#[macro_export]
macro_rules! call_js_function {
    ($callback:ident, $error:ident) => {
        $callback
            .call1(&JsValue::NULL, &$error)
            .expect("Callback invocation failed")
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
