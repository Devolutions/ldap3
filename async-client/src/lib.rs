pub mod authentication;
pub mod ldap_client;
pub mod search;
pub mod encryption_stream;



pub fn dbg_u8_itr<'a>(u8_itr: impl Iterator<Item = &'a u8>) {
    let hex = u8_itr
        .map(|x| format!("{:02X}", x))
        .collect::<Vec<_>>()
        .join(" ");
    tracing::info!("Debugging bytes values: {:?}", hex);
}

#[derive(Debug, thiserror::Error)]
pub enum LdapClientError {
    #[error("Operation does not match the expected one")]
    NotTheMessageExpected,
}
