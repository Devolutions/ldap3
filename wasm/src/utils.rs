#[macro_export]
macro_rules! send_message {
    ($self:ident, $msg:expr) => {{
        let mut frame = $self.frame.lock().await;

        frame.send($msg).await.map_err(|e| {
            crate::error::JsErrorValue::new_with_context("unable to send search", e)
        })?;

        frame
            .next()
            .await
            .ok_or_else(|| crate::error::JsErrorValue::msg("no response"))?
            .map_err(|e| {
                crate::error::JsErrorValue::new_with_context("error receiving response", e)
            })?
    }};
}
