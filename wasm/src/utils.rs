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
