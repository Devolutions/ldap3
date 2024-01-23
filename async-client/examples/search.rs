use async_client::ldap_client::{LdapAsyncClient, SaslBindConfig, SearchParameters};
use futures_util::StreamExt;

use tokio::net::TcpStream;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .pretty()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let server_computer_name = "IT-HELP-DC.ad.it-help.ninja".to_string();
    // let username = "Administrator@ad.it-help.ninja".to_string();
    let username = "Administrator".to_string();
    let password = "DevoLabs123!".to_string();
    let search_base = "dc=ad,dc=it-help,dc=ninja".to_string();
    let filter = "(objectClass=*)".to_string();
    let scope = ldap3_proto::LdapSearchScope::Subtree;
    let attributes = vec!["*".to_string()];
    let sign = Some(true);
    let seal = Some(true);

    let stream = TcpStream::connect("10.10.0.3:389").await?;
    let mut session = LdapAsyncClient::connect(stream).await?;

    session
        .sasl_bind(SaslBindConfig {
            auth_method: async_client::ldap_client::SspiAuthMethod::Negotiate {
                domain: None,
                kdc_url: None,
                server_computer_name,
                client_computer_name: "DESKTOP-1".to_string(),
            },
            username,
            password,
            sign,
            seal,
            controls: None,
        })
        .await?;

    let mut search_stream = session
        .search(SearchParameters {
            search_base,
            filter,
            scope,
            attributes,
            controls: None,
            size_limit: Some(10000), // stress test
            time_limit: None,
        })
        .await?;

    while let Some(msg) = search_stream.next().await {
        tracing::info!("msg is: {:?}", msg);
    }

    Ok(())
}
