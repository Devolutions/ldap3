use error::JsErrorValue;
use std::sync::OnceLock;
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::reload;
use tracing_subscriber::Registry;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_tracing::{ConsoleConfig, WasmLayer, WasmLayerConfig};

pub mod authentication;
pub mod dto;
pub mod encryption_stream;
pub mod error;
pub mod ldap_session;
pub mod schema;
// pub mod search;
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
    init_or_update_logger(Level::WARN);
}

#[wasm_bindgen]
pub fn set_logging_level(level: LoggingLevel) {
    init_or_update_logger(Level::from(level));
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

fn init_or_update_logger(level: Level) {
    static LOG_FILTER_HANDLE: OnceLock<reload::Handle<WasmLayer, Registry>> = OnceLock::new();

    let reload_handle = LOG_FILTER_HANDLE.get_or_init(move || {
        let wasm_layer = build_wasm_layer(level);
        let (reload_layer, reload_handle) = reload::Layer::new(wasm_layer);

        let _ = tracing::subscriber::set_global_default(Registry::default().with(reload_layer));

        reload_handle
    });

    let _ = reload_handle.reload(build_wasm_layer(level));

    fn build_wasm_layer(level: Level) -> WasmLayer {
        let mut config = WasmLayerConfig::new();
        config
            .set_console_config(ConsoleConfig::ReportWithConsoleColor)
            .set_max_level(level);
        WasmLayer::new(config)
    }
}
