use wasm_bindgen_test::wasm_bindgen_test;

use crate::{ldap_session::{LdapSession, LdapSessionParameters}};

#[wasm_bindgen_test]
async fn test_kerbero_bind() {
    console_error_panic_hook::set_once();
    let gatewat_addr  = "ws://localhost:7171/jet/fwd/tcp/fb328630-66b3-4b16-ac66-ed9e16fa5469?token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkFTU09DSUFUSU9OIn0NCg.eyJpYXQiOjE2OTk2NDQ3MDIsIm5iZiI6MTY5OTY0NDcwMiwiZXhwIjoxNzAwMjQ5NTAxLCJqdGkiOiIzZjlkNGM0NS1mMzE3LTQxZDUtOTE0Yy0wMzNlMDJmM2Q2NGYiLCJqZXRfYXAiOiJsZGFwIiwiamV0X2NtIjoiZndkIiwiamV0X2FpZCI6ImZiMzI4NjMwLTY2YjMtNGIxNi1hYzY2LWVkOWUxNmZhNTQ2OSIsImRzdF9oc3QiOiJ0Y3A6Ly9JVC1IRUxQLURDLmFkLml0LWhlbHAubmluamE6Mzg5In0NCg.pXYJsX2PtJV9-zkPEuU5lgdxWvx2cncakiO4yNyEf5ts6QSuhgh_lmAewrZHc86zI-5xJdDiBmB_aou7JycNBPtyD26WiWjCf43RJR25vO165dZ5fNCjy-2eBv-AZPu8SG8xFTuvWmjNmR2AhVazBtV9bnqxHtZEJCRKwbQ1Qgn0vB9uz-lKrlhp55ykdBzaiLThdc7gU5w-B1iFZuqxfFXolenzUEEPFOwfAmsH7bpjlpFp1Uid0nJTWW7bQWYrW40a7UkcXdpmgKQhsLKyJZgdZnCQz9bRQcMN1NQfA5CA-6hDja3BDEm1LKsklTHrNqzPXeGKEGBGRmhzHG-KPw";
    let mut session = LdapSession::connect(LdapSessionParameters::new(gatewat_addr.to_string()))
        .await
        .expect("failed to connect to ldap server");

    let ldap_username = "ProtectedUser";
    let ldap_password = "Protected123!";
    let kdc_proxy_url = "http://localhost:7171/jet/KdcProxy/eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IktEQyJ9.eyJleHAiOjE3MDIzMTM0NzIsImp0aSI6IjFlZDRjOGJiLTJlYWQtNDUzMi1hZGE5LTY3N2IyMTE2MTNiMiIsImtyYl9rZGMiOiJ0Y3A6Ly9JVC1IRUxQLURDLmFkLml0LWhlbHAubmluamE6ODgiLCJrcmJfcmVhbG0iOiJhZC5pdC1oZWxwLm5pbmphIiwibmJmIjoxNzAyMzEyNTcyfQ.jIsblT9hm9DfhA0YKSHMOps28OCkbQo5pNv8hPLqQB-1xGdT4jk95H_KZ08uFiGa3H0TibOhiZ0bbDwPDrYD5wG6k4vKjM2WVwTXuT5T1Uj_12cz3eqNnjCLhWo8U4yRCROM2pQzgLkKoAHYLcfx4F6XyFnIQWYsjXfS8cbqjBzUY-sQqEm_usjD9bXnWUXbLz2hcwJenIj5QxMK6-H04jxw_8BFlXg73IfXPqsZG9YU9NMl6kGEUOhuUN5YDZJIZepx1D0SzykrgvB0bZYbUFtAPYzQ-vUBiU-vWLfHHoPa_aEdGC740w_zPRfPvTUoXzQ5zySqt0_Gut5Z1csk7g";

    session
        .kerbero_bind(
            ldap_username.to_string(),
            ldap_password.to_string(),
            "ad.it-help.ninja".to_string(),
            kdc_proxy_url.to_string(),
            "IT-HELP-DC.ad.it-help.ninja".to_string(),
        )
        .await
        .expect("failed to bind to ldap server");

    session
        .search(
            "dc=ad,dc=it-help,dc=ninja".to_string(),
            "(objectClass=*)".to_string(),
            crate::ldap_session::JsLdapSearchScope::Subtree,
            vec![],
            Some(10),
            Some(10),
        ).unwrap()
        .on_message(&js_sys::Function::new_with_args("arg", "console.log(arg)")).unwrap();
}
