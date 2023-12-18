use derive_more::{From, Into};
use serde::{Deserialize, Serialize};
use tsify::Tsify;

use super::ldap_ops::LdapResult;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, From, Into)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi)]
pub struct LdapBindRequest {
    pub dn: String,
    pub cred: LdapBindCred,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, From)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi)]
pub enum LdapBindCred {
    Simple(String),
    SASL(SaslCredentials),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, From, Into)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi)]
pub struct SaslCredentials {
    pub mechanism: String,
    pub credentials: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, From, Into)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct LdapBindResponse {
    pub res: LdapResult,
    pub saslcreds: Option<Vec<u8>>,
}

impl From<LdapBindResponse> for ldap3_proto::proto::LdapBindResponse {
    fn from(item: LdapBindResponse) -> Self {
        ldap3_proto::proto::LdapBindResponse {
            res: item.res.into(),
            saslcreds: item.saslcreds,
        }
    }
}

impl From<ldap3_proto::proto::LdapBindResponse> for LdapBindResponse {
    fn from(item: ldap3_proto::proto::LdapBindResponse) -> Self {
        LdapBindResponse {
            res: item.res.into(),
            saslcreds: item.saslcreds,
        }
    }
}
