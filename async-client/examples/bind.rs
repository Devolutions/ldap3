use async_client::ldap_session::{LdapSession, SaslBindConfig};
use tokio::net::TcpStream;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let server_computer_name = "IT-HELP-DC.ad.it-help.ninja".to_string();
    let username = "Administrator@ad.it-help.ninja".to_string();
    let password = "DevoLabs123!".to_string();
    let sign = Some(true);
    let seal = Some(true);

    let stream = TcpStream::connect("10.10.0.3:389").await.unwrap();
    let mut session = LdapSession::connect(stream).await?;

    session
        .sasl_bind(SaslBindConfig {
            auth_method: async_client::ldap_session::SspiAuthMethod::Ntlm {
                server_computer_name,
            },
            username,
            password,
            sign,
            seal,
            controls: None,
        })
        .await?;

    Ok(())
}
