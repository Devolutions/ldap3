pub mod authentication;
pub mod ldap_client;
pub mod search;
pub mod encryption_stream;




#[macro_export]
macro_rules! debug_u8_hex {
    ($byte_array:expr, $message:expr) => {
        let hex = $byte_array.iter()
            .map(|x| format!("{:02X}", x))
            .collect::<Vec<_>>()
            .join(" ");
        tracing::debug!("{}: {}", $message, hex);
    };
}


#[derive(Debug, thiserror::Error)]
pub enum LdapClientError {
    #[error("Operation does not match the expected one")]
    NotTheMessageExpected,
}
