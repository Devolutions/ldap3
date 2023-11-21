#[macro_export]
macro_rules! send_message {
    ($self:ident, $msg:expr) => {{
        let mut frame = $self.frame.lock().await;
        frame
            .send($msg)
            .await
            .map_err(|e| to_js_error!("Unable to send search -> {:?}", e))?;
        frame.next().await
    }
    .ok_or(to_js_error!("No response"))
    .map_err(|e| to_js_error!("Error receiving response : {:?}", e))?
    .map_err(|e| to_js_error!("Error receiving response : {:?}", e))?};
}

#[macro_export]
macro_rules! return_msg_if_type_matches {
    ($enum:path,$res:expr) => {
        match $res.op {
            $enum(_) => Ok(serde_wasm_bindgen::to_value(&$res)?),
            _ => Err(to_js_error!("Invalid response")),
        }
    };
}
