use wasm_bindgen_test::*;

use crate::ldap_session::{LdapSession, LdapSessionParameters};

wasm_bindgen_test_configure!(run_in_browser);

async fn connect_to_ldap_server(params: LdapSessionParameters) -> LdapSession {
    match LdapSession::connect(params).await {
        Ok(mut session) => {
            let result = session
                .bind(
                    "CN=Administrator,CN=Users,DC=ad,DC=it-help,DC=ninja".to_string(),
                    "DevoLabs123!".to_string(),
                )
                .await
                .unwrap();

            console_log!("result: {:?}", result);
            session
        }
        Err(e) => {
            // Handle the error, such as logging or asserting
            panic!("Failed to connect to LDAP server: {:?}", e);
        }
    }
}

#[wasm_bindgen_test]
async fn test_as_whole() {
    let server_address_ws_proxy = "ws://localhost:7171/jet/fwd/tcp/30f0e8f6-23cf-4c24-b0f1-376e8dd80fca?token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkFTU09DSUFUSU9OIn0NCg.eyJpYXQiOjE2OTkzNzk0NDYsIm5iZiI6MTY5OTM3OTQ0NiwiZXhwIjoxNjk5OTg0MjQ2LCJqdGkiOiJmOGEzNzFmNS00NzA5LTRkNWQtOTg0OC1mMWQ1NGNmNWIxZTQiLCJqZXRfYXAiOiJsZGFwIiwiamV0X2NtIjoiZndkIiwiamV0X2FpZCI6IjMwZjBlOGY2LTIzY2YtNGMyNC1iMGYxLTM3NmU4ZGQ4MGZjYSIsImRzdF9oc3QiOiJ0Y3A6Ly9JVC1IRUxQLURDLmFkLml0LWhlbHAubmluamE6Mzg5In0NCg.pM3DnFPY4F__OUnjZzduJp2fAcs3wdyCjz8MVRbtQIVOX99ttApujku2oiwTDxtb36fvclIMv4TmYHvDtzQQLe7bNZDltKhXzjT2U9KmkDxo7th0JRJ5f8NpI9g_LLMqCwDYa62LVeQ49vLByceU7zp0q6Jbs6FxU17p9V5yIj3AbXM3v2zY941xDOoMtCXmCa77sM8Pc1-nGVZnyYg0UggHPKjngxnqb4-TlZ8Itw9OSiq1mX3qBcDoVnSHB6CfeH1UWQCa2aSyiDlUP7fcdxrIU3AikgbQLzqwc2aXg0MS6jlxNbhrp_xfKQPmwMlpa4qFrMtXWQnZtFg_FHgZeA";
    let params = LdapSessionParameters::new(server_address_ws_proxy.to_string());
    let mut session = connect_to_ldap_server(params).await;
    let _result = session
        .search(
            "DC=ad,DC=it-help,DC=ninja".to_string(),
            "(objectclass=Person)".to_string(),
            crate::ldap_session::JsLdapSearchScope::Subtree,
            None,
            None,
        )
        .unwrap();
}
