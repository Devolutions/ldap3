use async_client::ldap_client::{LdapAsyncClient, SaslBindConfig, SearchParameters};
use futures_util::StreamExt;

use ldap3_proto::{
    proto::{LdapModify, LdapModifyRequest, LdapModifyType},
    LdapPartialAttribute,
};
use tokio::net::TcpStream;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .pretty()
        .with_max_level(tracing::Level::INFO)
        .init();

    let server_computer_name = "IT-HELP-DC.ad.it-help.ninja".to_string();
    let username = "Administrator@ad.it-help.ninja".to_string();
    // let username = "Administrator@ad.".to_string();
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
            size_limit: Some(5), // stress test
            time_limit: None,
        })
        .await?;

    while let Some(msg) = search_stream.next().await {
        let msg = msg?;
        tracing::info!("msg is: {:?}", msg);
        if let ldap3_proto::proto::LdapOp::SearchResultDone(_) = msg.op {
            break;
        }       
    }

    // add a new user called testuser
    let res = session
        .add(
            "CN=Testuser,CN=Users,DC=ad,DC=it-help,DC=ninja".to_string(),
            vec![],
            None,
        )
        .await?;

    tracing::info!("add result: {:?}", res);

    // modify the user's password
    let res = session
        .modify(
            "CN=testuser,CN=Users,DC=ad,DC=it-help,DC=ninja".to_string(),
            vec![LdapModify {
                operation: LdapModifyType::Replace,
                modification: LdapPartialAttribute {
                    atype: "password".to_string(),
                    vals: vec![b"DevoLabs123!".to_vec()],
                },
            }],
            None,
        )
        .await?;

    tracing::info!("modify result: {:?}", res);

    // delete the user
    let res = session
        .delete("CN=testuser,CN=Users,DC=ad,DC=it-help,DC=ninja".to_string(), None)
        .await?;

    tracing::info!("delete result: {:?}", res);

    Ok(())
}
